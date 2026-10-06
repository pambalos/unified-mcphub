"""Detachable payloads: record content raw, export it optionally, verify either way.

**The problem this solves.** An audit chain has two jobs that pull against each
other. It must record *exactly* what an agent sent and what came back — an
investigator reconstructing an incident needs the arguments, not a scrubbed
paraphrase, and ISO/IEC 42001 A.6.2.8 asks for the data the system acted on.
And it must be exportable to people who should not see that content — an
auditor sampling a window, a regulator, a customer's own compliance team —
while still proving that nothing was altered. When the entry hash covers the
content directly, those are incompatible: remove the content from an exported
line and its hash no longer recomputes, so every link after it breaks. The old
answer was to shape the content *at write time* (`audit_level`), which meant
the record itself was lossy — `minimal` kept nothing, `standard` scrubbed
strings — and no export could ever recover what the chain chose not to keep.

**The rule.** Content-bearing fields are *detached*: the entry hash covers a
digest of the value instead of the value itself, and the value stays inline
beside it. An entry may carry

    "detached": {<dotted path>: <hex sha256>, ...}   part of the hashed body
    "salts":    {<dotted path>: <base64 salt>, ...}  NOT hashed
    "unrecorded": [<dotted path>, ...]               hashed; see `record=False`

and its chain hash is computed over `hashable_body(entry)`: the entry minus
`sig`/`key_id`/`hash`, minus `salts`, minus the value at every detached path.
The digest of a detached value is

    sha256(salt_bytes + canonical(value))

with `canonical` the chain's own lenient canonical JSON (sorted keys, no
whitespace, UTF-8, unknown types stringified). So:

- *With the content present*, `check` recomputes each digest; a value edited
  after the fact no longer matches the digest the signed hash committed to.
- *With the content withheld* (`redact`), the line still hashes to the same
  value, the chain still links, every signature still verifies — and the
  digest in the hashed body still commits to exactly one value. The customer
  can later hand over any single withheld value (with its salt), and the
  auditor can check it against the signed entry without seeing the rest.

**Why salted.** Many inputs are guessable: a ticket id like "UAI-203", a yes/no
flag, a customer number from a short range, a well-known file path. An
unsalted digest in a digests-only export would let anybody holding the export
confirm a guess by hashing it — the export would leak exactly what it was meant
to withhold, one guess at a time. A fresh 16-byte salt per value makes the
digest useless without the salt, and the salt travels *with* the content: it is
withheld whenever the content is, which is why `check` treats a salt present
without its content as a defect rather than a harmless leftover. (A salt alone
reveals nothing, but it is the only thing standing between a guess and a
confirmation, so an export that kept it would be quietly weaker than it says.)

**Why the salt is not hashed.** It does not need to be: the digest commits to
`salt + value`, so a substituted salt fails `check` exactly as substituted
content does. Leaving it out of the hash is what lets `redact` remove it.

**`record=False` (the explicit escape hatch).** Some deployments must not keep
the content at all. They still get a digest and a salt per value — the salt
kept locally so that a copy held elsewhere (the upstream system's own records)
can be proved against the chain later — and the entry lists those paths under
`unrecorded`. That list is *hashed*, so the signed record itself says "this
content was never stored", which an auditor must be able to tell apart from
"this content was withheld from your copy". `redact` still strips the salts on
export, as for any withheld value.

**Backward compatibility.** An entry with no `detached` key hashes exactly as
before this module existed — `hashable_body` then reduces to "the entry minus
`sig`, `key_id` and `hash`" — so every chain written before it keeps verifying
unchanged.

**Standalone on purpose.** This file is copied verbatim into evidence packs next
to `attest.py` and `pack_verify.py`, where the auditor runs it with nothing
installed. So: standard library only, and no imports from this package. Paths
are dotted keys into nested objects (`payload.action.params`); a key containing
a dot cannot be detached, which no current entry shape needs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Callable, Iterable
from typing import Any, NamedTuple

DETACHED = "detached"
SALTS = "salts"
UNRECORDED = "unrecorded"
#: Fields that are never part of the hashed body: the hash itself and the
#: signature over it (plus the signer's key id, which the signature binds).
UNHASHED = ("sig", "key_id", "hash", SALTS)
SALT_BYTES = 16


def canonical(value: Any) -> bytes:
    """The chain's lenient canonical JSON, applied to any JSON value.

    Byte-for-byte the rule `unified_enforce.canonical.canonical_bytes(...,
    strict=False)` and `pack_verify._entry_hash` use — restated here rather
    than imported because this module has to run on its own inside a pack.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def digest(salt: bytes, value: Any) -> str:
    return hashlib.sha256(salt + canonical(value)).hexdigest()


# --- paths -------------------------------------------------------------------------


def _parts(path: str) -> list[str]:
    return path.split(".")


def get(entry: dict[str, Any], path: str) -> tuple[bool, Any]:
    """(found, value) at a dotted path. A key holding `null` is found."""
    node: Any = entry
    for part in _parts(path):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _without(entry: dict[str, Any], paths: Iterable[str]) -> dict[str, Any]:
    """A copy of `entry` with the value at each path removed.

    Copies only the containers along each path (the rest is shared with the
    input), which is all removal needs and keeps this cheap on the hot path:
    the writer calls it once per append.
    """
    out = dict(entry)
    for path in paths:
        if not get(out, path)[0]:
            continue  # nothing at this path, so nothing to remove (and every parent is a dict)
        *parents, leaf = _parts(path)
        node = out
        for part in parents:
            child = dict(node[part])
            node[part] = child
            node = child
        node.pop(leaf, None)
    return out


# --- the rule --------------------------------------------------------------------------


def _detached_paths(entry: dict[str, Any]) -> list[str]:
    detached = entry.get(DETACHED)
    if not isinstance(detached, dict):
        return []
    return [p for p in detached if isinstance(p, str)]


def hashable_body(entry: dict[str, Any]) -> dict[str, Any]:
    """What the chain hash covers (see module docstring).

    Total on purpose: a malformed `detached` is hashed as it stands rather than
    raising, so a damaged entry reports as a hash mismatch or a `check` problem
    in the verifier instead of crashing it.
    """
    body = {k: v for k, v in entry.items() if k not in UNHASHED}
    paths = _detached_paths(body)
    return _without(body, paths) if paths else body


def detach(
    entry: dict[str, Any],
    paths: Iterable[str],
    *,
    record: bool = True,
    salt: Callable[[int], bytes] = os.urandom,
) -> dict[str, Any]:
    """Commit to the value at each path by a salted digest. Returns a new entry.

    Paths absent from the entry are skipped (a decision with no `extra` has
    nothing to commit to). `record=False` removes the value after digesting it
    and lists the path under `unrecorded` — the salt is kept, so that a copy of
    the content held elsewhere can still be proved against this entry.
    The input is not mutated.
    """
    paths = list(paths)
    detached: dict[str, str] = dict(entry.get(DETACHED) or {})
    salts: dict[str, str] = dict(entry.get(SALTS) or {})
    unrecorded: list[str] = list(entry.get(UNRECORDED) or [])
    dropped: list[str] = []
    for path in paths:
        found, value = get(entry, path)
        if not found:
            continue
        raw = salt(SALT_BYTES)
        detached[path] = digest(raw, value)
        salts[path] = base64.b64encode(raw).decode("ascii")
        if not record:
            dropped.append(path)
            if path not in unrecorded:
                unrecorded.append(path)
    out = _without(entry, dropped) if dropped else dict(entry)
    if detached:
        out[DETACHED] = detached
        out[SALTS] = salts
    if unrecorded:
        out[UNRECORDED] = sorted(unrecorded)
    return out


def redact(entry: dict[str, Any]) -> dict[str, Any]:
    """Withhold every detached value and its salt. Returns a new entry.

    The hashed body is unchanged — `detached` (and `unrecorded`) stay — so the
    result hashes to the same `hash`, links to the same neighbours and carries
    a signature that still verifies. Entries without detached fields come back
    unchanged: there is nothing in them that can be removed without breaking
    the chain, which is why the exporter reports them.
    """
    paths = _detached_paths(entry)
    if not paths:
        return dict(entry)
    out = _without(entry, paths)
    out.pop(SALTS, None)
    return out


class Checked(NamedTuple):
    ok: bool
    present: int  # detached values present and matching their digest
    withheld: int  # detached values absent (redacted for export)
    unrecorded: int  # detached values the writer was configured not to store
    problem: str | None = None


def check(entry: dict[str, Any]) -> Checked:
    """Check every detached value present against its digest.

    The chain hash covers the digests, not the values, so this is the check
    that catches edited content: a present value must have its salt and hash
    to the committed digest. An absent value is fine (withheld or never
    recorded) — but then its salt must be absent too, unless the signed entry
    itself says the value was never recorded (see module docstring).
    """
    detached = entry.get(DETACHED)
    salts = entry.get(SALTS)
    unrecorded = entry.get(UNRECORDED)
    if detached is None:
        if salts is not None:
            return Checked(False, 0, 0, 0, "salts on an entry with no detached fields")
        if unrecorded is not None:
            return Checked(False, 0, 0, 0, "'unrecorded' on an entry with no detached fields")
        return Checked(True, 0, 0, 0)
    if not isinstance(detached, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in detached.items()
    ):
        return Checked(False, 0, 0, 0, "'detached' is not a map of path to digest")
    salts = {} if salts is None else salts
    if not isinstance(salts, dict) or not all(isinstance(v, str) for v in salts.values()):
        return Checked(False, 0, 0, 0, "'salts' is not a map of path to base64 salt")
    unrecorded = [] if unrecorded is None else unrecorded
    if not isinstance(unrecorded, list) or not all(p in detached for p in unrecorded):
        return Checked(False, 0, 0, 0, "'unrecorded' names a path that is not detached")
    stray = sorted(set(salts) - set(detached))
    if stray:
        return Checked(False, 0, 0, 0, f"salt for a path that is not detached: {stray}")

    present = withheld = never = 0
    for path, committed in sorted(detached.items()):
        found, value = get(entry, path)
        salt_b64 = salts.get(path)
        if found:
            if salt_b64 is None:
                return Checked(False, present, withheld, never, f"{path}: content without its salt")
            try:
                raw = base64.b64decode(salt_b64, validate=True)
            except (binascii.Error, ValueError):
                return Checked(False, present, withheld, never, f"{path}: salt is not base64")
            if digest(raw, value) != committed:
                return Checked(
                    False,
                    present,
                    withheld,
                    never,
                    f"{path}: content does not match its digest (tampered)",
                )
            present += 1
        elif path in unrecorded:
            never += 1
        else:
            if salt_b64 is not None:
                return Checked(
                    False,
                    present,
                    withheld,
                    never,
                    f"{path}: salt present without its content (a withheld value's salt "
                    "only helps somebody confirm a guess)",
                )
            withheld += 1
    return Checked(True, present, withheld, never)
