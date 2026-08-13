"""Where a checkpoint goes, and what each destination is actually worth. UAI-134.

`checkpoint.py` is cryptography and has one right answer. This file is a trust
question and does not — an anchor is only as good as the *independence* of
whoever holds it, and that is a property of the deployment rather than of the
code. So each implementation states what it proves and against whom, because an
anchor whose independence is assumed rather than reasoned about is a compliance
artifact rather than evidence.

| anchor | independent of | does **not** protect against |
|---|---|---|
| `DirectoryAnchor` | nothing by itself | anyone who can write the directory |
| `ControlPlaneAnchor` | the sidecar and its host | a compromised control plane, i.e. us |
| a counterparty or transparency log | both | — (not built; see below) |

**`ControlPlaneAnchor` is the honest middle**, and worth being precise about
because it is the one that will actually run. It defends against exactly the
attacker the audit chain cannot: somebody who owns a sidecar, rewrites its log,
and re-signs every entry with the key that machine holds. The control plane is
already holding last week's root, and no rewrite reconciles the two. It does not
defend against the control plane itself, which is why the interface is a
protocol — a customer who needs that plugs in a destination we do not control,
and the code does not change.

**What is deliberately not built here** is an RFC 3161 timestamp authority or a
transparency-log client. Both are real answers to "independent of the vendor
too", and both are a network dependency plus a trust decision that belongs to
the customer rather than to a default. The protocol below is the extension
point, and `DirectoryAnchor` is what a customer pointing a nightly job at their
own storage uses today.

**Anchoring never blocks a decision, and never blocks a write.** It is
after-the-fact by construction: a checkpoint describes entries that are already
durable. An anchor that could not be reached is a gap in coverage — visible,
and reported — never a reason to stop enforcing or stop recording.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Protocol

from .checkpoint import SignedCheckpoint

log = logging.getLogger("unified_enforce.anchors")


class AnchorError(Exception):
    """The checkpoint was not accepted. Never fatal to the caller."""


class Anchor(Protocol):
    """Somewhere a checkpoint is put beyond the writer's reach.

    A protocol rather than a base class, for the same reason `Source` is one in
    `distribution.py`: the artifact is signed and self-describing, so how it
    travels is not this package's concern.
    """

    def submit(self, signed: SignedCheckpoint) -> dict[str, Any]:
        """Publish it. Returns whatever the destination said, for the record."""
        ...

    def latest(self, *, fleet_id: str, reporter_id: str) -> dict[str, Any] | None:
        """The most recent checkpoint this anchor holds, so the next one can
        chain to it and so a restart does not re-checkpoint a covered range."""
        ...


class DirectoryAnchor:
    """A directory. Air-gapped transfer, or a customer-held copy.

    **Independent of nothing on its own.** Anyone who can write the sidecar's
    filesystem can write here too, so this only becomes an anchor once the
    directory is somewhere the writer cannot reach — a read-only mount, an
    object store the sidecar can PUT to and not DELETE, a courier. That is a
    deployment decision this class cannot make or verify, and pretending
    otherwise would be the most comfortable possible lie about what a customer
    has.
    """

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)

    def submit(self, signed: SignedCheckpoint) -> dict[str, Any]:
        self._root.mkdir(parents=True, exist_ok=True)
        checkpoint = signed.checkpoint
        name = f"{checkpoint.reporter_id}-{checkpoint.to_seq:012d}.json"
        path = self._root / name

        # Never overwritten. A second checkpoint for a range that already has
        # one is the signal this whole feature exists to produce, and silently
        # replacing the file would destroy the evidence at the moment it was
        # created.
        if path.exists():
            raise AnchorError(
                f"{name} already exists. A checkpoint for this range was already "
                "anchored; if its root differs, that is a rewritten log and the "
                "existing file is the evidence."
            )

        path.write_text(json.dumps(signed.as_dict(), indent=2, sort_keys=True))
        return {"path": str(path)}

    def latest(self, *, fleet_id: str, reporter_id: str) -> dict[str, Any] | None:
        files = sorted(self._root.glob(f"{reporter_id}-*.json"))
        if not files:
            return None
        try:
            return json.loads(files[-1].read_text())
        except (OSError, ValueError):
            return None


class ControlPlaneAnchor:
    """The control plane, which countersigns and keeps its own copy.

    Defends against the attacker the chain and the signature both cannot: one
    who owns a sidecar. It does not defend against the control plane, and the
    docs say so — a customer who needs that anchors somewhere else, which is
    what the protocol is for.

    The countersignature matters more than the storage. A root the control plane
    has merely stored is a root the control plane could later claim it never
    saw; one it signed is one it cannot disown, which is what makes this
    evidence in a dispute rather than a shared spreadsheet.
    """

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        channel: Any = None,
        http_timeout: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._credential = credential
        self._channel = channel
        self._timeout = http_timeout

    def submit(self, signed: SignedCheckpoint) -> dict[str, Any]:
        body = signed.as_dict()
        answer = self._request("POST", "/api/v1/checkpoints", body)

        counter = answer.get("countersignature")
        if counter:
            signed.countersignatures.append(counter)
        else:
            # Stored but not countersigned is weaker than it looks, and silence
            # would let a deployment believe it had evidence it does not.
            log.warning(
                "checkpoint %s..%s was stored without a countersignature; the "
                "control plane can later decline to confirm it saw this root",
                signed.checkpoint.from_seq,
                signed.checkpoint.to_seq,
            )
        return answer

    def latest(self, *, fleet_id: str, reporter_id: str) -> dict[str, Any] | None:
        """Asks about *this* credential, deliberately ignoring `reporter_id`.

        The control plane keys checkpoints on the authenticated credential id,
        never on a name in the body — that is what stops one sidecar filing
        checkpoints against another and manufacturing evidence of tampering.
        Which means asking it about our own local reporter name finds nothing,
        and the caller then re-checkpoints a range that is already covered.

        That is not a harmless duplicate. An overlapping checkpoint is reported
        as a possible rewrite, so a sidecar doing this would raise a fresh
        alarm about itself on every single run, forever — the exact failure a
        unit test warned about and could not catch, because a `DirectoryAnchor`
        keys on the name it was given and the two happened to agree.
        """
        try:
            answer = self._request("GET", "/api/v1/checkpoints/latest", None)
        except AnchorError:
            return None
        return answer.get("checkpoint")

    def _request(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        import urllib.error
        import urllib.request

        raw = json.dumps(body).encode() if body is not None else None
        headers = {"authorization": f"Bearer {self._credential}"}
        if raw is not None:
            headers["content-type"] = "application/json"
        if self._channel is not None:
            headers.update(self._channel.headers(method, path.split("?")[0], raw))

        request = urllib.request.Request(
            self._base + path, data=raw, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise AnchorError(f"HTTP {exc.code}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise AnchorError(f"cannot reach {self._base}: {exc.reason}") from exc
        except (ValueError, OSError) as exc:
            raise AnchorError(f"{path}: {exc}") from exc


class Anchoring:
    """Checkpoints a chain and publishes the result. The thing a sidecar runs.

    Deliberately not automatic on every write. A checkpoint per entry would be
    one signature and one network call per decision, on a path whose entire
    design is about not having either — and it would produce a stream of
    single-entry roots that prove nothing a per-entry signature does not already
    prove. Batching is what makes the anchor cheap enough to be real.

    The window is the exposure: entries written after the last checkpoint are
    covered by the chain and the signature but not yet pinned externally, so an
    attacker who compromises a sidecar can rewrite the tail. That is a stated,
    bounded gap — the same shape as the containment bound — and shortening it is
    a matter of how often this is called.
    """

    def __init__(
        self,
        chain: Any,
        anchor: Anchor,
        *,
        fleet_id: str,
        #: What this sidecar calls itself in the checkpoint it signs. The
        #: control plane stores checkpoints under the *credential* id
        #: regardless, so this is a label for whoever reads the artifact later
        #: — set it to the credential id from enrolment and the two agree.
        reporter_id: str,
        signer: Any,
    ) -> None:
        self._chain = chain
        self._anchor = anchor
        self._fleet = fleet_id
        self._reporter = reporter_id
        self._signer = signer

    def checkpoint(self, *, days: int = 2) -> SignedCheckpoint | None:
        """Cover everything since the last anchored checkpoint. `None` if nothing new.

        Never raises on an unreachable anchor: this runs on a timer beside a
        sidecar that is enforcing policy, and an anchor being down must not take
        that down with it. The failure is a gap in coverage, which the next
        successful run closes by covering the wider range.
        """
        from .checkpoint import build

        previous = self._anchor.latest(fleet_id=self._fleet, reporter_id=self._reporter)
        after = 0
        prev_root = None
        if previous:
            payload = previous.get("payload", previous)
            after = int(payload["to_seq"])
            prev_root = payload["root"]

        entries = [
            e
            for e in self._chain.entries(days=days)
            if isinstance(e.get("seq"), int) and e["seq"] > after
        ]
        if not entries:
            return None

        entries.sort(key=lambda e: e["seq"])
        signed = build(
            entries,
            fleet_id=self._fleet,
            reporter_id=self._reporter,
            signer=self._signer,
            prev_root=prev_root,
        )
        self._anchor.submit(signed)
        return signed
