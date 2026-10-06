"""`unified-mcphub fleet join | status` — enrolling a hub, by command.

Joining used to be four manual steps — generate nothing, `secrets set` a
credential obtained somehow, hand-write a `control_plane:` block with a root
key copied out of an HTTP response, restart — and the step it never had was the
one that matters most now: registering the key the hub signs its evidence
with. A credential enrolled without an `evidence_key` can never acquire one
(the control plane makes it one-way, at enrolment, so a stolen token cannot be
used to register an attacker's key later). So `join` does all of it, in the
order that wastes nothing if a step fails:

1. Refuse to replace an existing enabled `control_plane:` block without
   `--force` — before anything else, because the join token is single-use.
2. Load or generate the hub signing key and store it in the secrets store.
   Also before enrolling: a secrets backend that cannot persist anything (the
   `env` backend with no key) must fail here, not after the token is spent.
3. Enrol: `POST {url}/api/v1/enrol` with the join token, `kind: sidecar` and
   the signing key's public half as `evidence_key`.
4. Render the `control_plane:` block with ruamel round-trip, so the
   operator's comments and layout in `config.yaml` survive (as servers.py does
   for workspaces), pinning the `root_key` from the enrolment response — and
   validate it with the hub's own config model.
5. Store the returned credential under `control_plane.credential_secret_ref`,
   then write the block that refers to it.

**Never prints a secret.** Not the join token, not the credential, not the
seed. What it prints is what an operator needs to check the result against
the control plane: the fleet, the credential id, the signing key id.

`status` is offline by design: it reads `config.yaml` and `signing.json` and
nothing else — not the network, and not the secrets store (whose key may sit
behind a keychain prompt that a status command has no business raising).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
import yaml
from ruamel.yaml.comments import CommentedMap

from .config import ControlPlaneConfig, HubConfig, config_path, load_hub_config
from .secrets import SecretsKeyError, SecretsStore
from .servers import _dump, _load_doc, _yaml
from .signing import (
    generate_seed,
    load_record,
    public_key_b64u,
    signer_from_secret,
    signing_record_path,
)
from .util import secure_write

#: The enrolment request's own timeout. Generous because it is one request,
#: run by a person, and a failed one may have spent the token anyway.
ENROL_TIMEOUT_SECONDS = 30.0


class JoinError(RuntimeError):
    """A join that stopped before (or instead of) changing anything it should not."""


@dataclass(frozen=True)
class JoinResult:
    fleet_id: str
    credential_id: str | None
    credential_secret_ref: str
    signing_key_id: str
    signing_key_created: bool
    approvals: str


def _current_block(doc: CommentedMap) -> Any:
    block = doc.get("control_plane")
    return block if isinstance(block, dict) else None


def _enrol(url: str, join_token: str, evidence_key: str) -> dict[str, Any]:
    endpoint = url.rstrip("/") + "/api/v1/enrol"
    try:
        with httpx.Client(timeout=ENROL_TIMEOUT_SECONDS) as client:
            response = client.post(
                endpoint,
                json={"join_token": join_token, "kind": "sidecar", "evidence_key": evidence_key},
            )
    except httpx.HTTPError as exc:
        raise JoinError(f"cannot reach the control plane at {endpoint}: {exc}") from None
    if response.status_code != 201 and response.status_code != 200:
        detail = ""
        try:
            detail = str(response.json().get("detail", ""))
        except ValueError:
            pass
        raise JoinError(
            f"enrolment refused (HTTP {response.status_code}){': ' + detail if detail else ''}. "
            "A join token is single-use: if this one reached the control plane it may now be "
            "spent, and a new one is needed (`unified-control issue-join-token --fleet ...`)."
        )
    try:
        payload = response.json()
    except ValueError:
        raise JoinError("the control plane's enrolment response was not JSON") from None
    for field in ("token", "fleet_id", "root_key"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise JoinError(f"the control plane's enrolment response has no {field!r}")
    return payload


def join(
    *,
    url: str,
    fleet: str,
    join_token: str,
    approvals: str = "console",
    force: bool = False,
    store: SecretsStore | None = None,
) -> JoinResult:
    if approvals not in ("console", "terminal"):
        raise JoinError("--approvals must be console or terminal")
    if not url.startswith(("https://", "http://")):
        raise JoinError(f"--url must be an http(s) URL, got {url!r}")

    # 1. The config check, before anything is spent.
    rt = _yaml()
    path = config_path()
    doc = _load_doc(rt, path)
    if not isinstance(doc, CommentedMap):
        raise JoinError(f"{path}: expected a mapping at the top level")
    hub_cfg = load_hub_config()
    existing = _current_block(doc)
    if hub_cfg.control_plane.enabled and not force:
        raise JoinError(
            f"this hub is already joined to fleet {hub_cfg.control_plane.fleet_id!r} at "
            f"{hub_cfg.control_plane.url}; pass --force to re-enrol and replace that block "
            "(the old credential stays valid at the control plane until revoked there)"
        )
    credential_ref = hub_cfg.control_plane.credential_secret_ref
    signing_ref = hub_cfg.audit.signing_key_secret_ref

    # 2. The signing key, before the token is spent.
    store = store or SecretsStore.from_config(hub_cfg.secrets)
    try:
        seed = store.get(signing_ref)
        created = seed is None
        if seed is None:
            seed = generate_seed()
            store.set(signing_ref, seed)
    except SecretsKeyError as exc:
        raise JoinError(f"secrets: {exc}") from None
    try:
        signer = signer_from_secret(seed)
    except ValueError as exc:
        raise JoinError(f"the existing signing key under {signing_ref!r} is unusable: {exc}")

    # 3. Enrol.
    payload = _enrol(url, join_token, public_key_b64u(signer))
    if payload["fleet_id"] != fleet:
        # The token decides the fleet, not the flag; a mismatch means the
        # operator holds a token for a fleet they did not mean. Nothing is
        # stored, so this hub cannot end up reporting somewhere unintended.
        raise JoinError(
            f"the join token enrolled this hub into fleet {payload['fleet_id']!r}, not {fleet!r}; "
            "nothing was stored. Revoke the credential just issued "
            f"({payload.get('credential_id', 'see list-credentials')}) and use a token for "
            f"{fleet!r}."
        )

    # 4. The config block, comments preserved — rendered and validated
    # before the credential is stored, so a refusal leaves no half-join.
    block = existing if isinstance(existing, CommentedMap) else CommentedMap()
    block["url"] = url
    block["fleet_id"] = payload["fleet_id"]
    block["root_public_key"] = payload["root_key"]
    block["on_stale"] = "keep"
    block["approvals"] = approvals
    if (
        "credential_secret_ref" in block
        or credential_ref != ControlPlaneConfig().credential_secret_ref
    ):
        block["credential_secret_ref"] = credential_ref
    doc["control_plane"] = block
    rendered = _dump(rt, doc)
    # Validate what is about to be written with the hub's own model: a block
    # the hub would refuse at start is better refused here, by the command
    # that wrote it.
    HubConfig.model_validate(yaml.safe_load(rendered) or {})

    # 5. The credential, then the block that refers to it.
    store.set(credential_ref, payload["token"])
    secure_write(path, rendered.encode())

    return JoinResult(
        fleet_id=payload["fleet_id"],
        credential_id=payload.get("credential_id"),
        credential_secret_ref=credential_ref,
        signing_key_id=signer.key_id,
        signing_key_created=created,
        approvals=approvals,
    )


def status() -> dict[str, Any]:
    """What this hub is configured to do, from files alone."""
    cfg = load_hub_config()
    cp = cfg.control_plane
    record = load_record()
    return {
        "joined": cp.enabled,
        "url": cp.url,
        "fleet_id": cp.fleet_id,
        "approvals": cp.approvals if cp.enabled else None,
        "approval_timeout_seconds": cp.approval_timeout_seconds if cp.console_approvals else None,
        "on_stale": cp.on_stale if cp.enabled else None,
        "evidence": cp.evidence if cp.enabled else None,
        "credential_secret_ref": cp.credential_secret_ref,
        "signing_key_secret_ref": cfg.audit.signing_key_secret_ref,
        "signing": (
            None
            if record is None
            else {
                "key_id": record.key_id,
                "public_key": record.public_key,
                "since_seq": record.since_seq,
                "record": str(signing_record_path()),
            }
        ),
    }


def print_join(result: JoinResult, url: str) -> None:
    print(f"joined fleet {result.fleet_id!r} at {url}")
    if result.credential_id:
        print(
            f"  credential:   {result.credential_id} (stored as {result.credential_secret_ref!r})"
        )
    else:
        print(f"  credential:   stored as {result.credential_secret_ref!r}")
    print(
        f"  signing key:  {result.signing_key_id} "
        f"({'generated' if result.signing_key_created else 'existing'}; registered as this "
        "credential's evidence key — unsigned evidence from it is now refused)"
    )
    print(f"  approvals:    {result.approvals}")
    print("restart the hub to apply (`unified-mcphub start`)")


def print_status(data: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
        return
    if not data["joined"]:
        print("standalone (no control_plane.url)")
    else:
        print(f"joined:       fleet {data['fleet_id']!r} at {data['url']}")
        approvals = data["approvals"]
        if approvals == "console":
            approvals += f" (timeout {data['approval_timeout_seconds']:g}s)"
        print(f"approvals:    {approvals}")
        print(f"on_stale:     {data['on_stale']}")
        print(f"evidence:     {'on' if data['evidence'] else 'off'}")
        print(f"credential:   secret ref {data['credential_secret_ref']!r}")
    signing = data["signing"]
    if signing is None:
        print(
            f"signing:      no signed entry recorded yet (key ref "
            f"{data['signing_key_secret_ref']!r}; the record appears at the first signed write)",
        )
    else:
        print(
            f"signing:      key {signing['key_id']} since seq {signing['since_seq']} "
            f"({signing['record']})",
        )
