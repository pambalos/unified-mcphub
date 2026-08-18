"""One answer to "which file does this string mean".

A path check is only worth something when the component that *decides* and the
component that *acts* agree on what a path string refers to. They did not: the
policy engine canonicalised with `realpath` (symlinks resolved) while the
filesystem server used `abspath` (symlinks not resolved), so a symlink was
invisible to exactly one of them. That gap is enough to walk a write past an
authorisation that examined a different file than the one eventually opened.

So there is one implementation, here, and both ends import it. This package has
no third-party dependencies on purpose: the guarantee is that the two ends
cannot drift, and a shared dependency they could pin differently would give the
drift somewhere to hide.

What canonicalisation means here:

- `~` expands, `.` and `..` collapse, and symlinks resolve — including symlinks
  in parent directories, which is the case a lexical check misses.
- The target need not exist. The thing being authorised is usually a file about
  to be created, and a check that only worked on existing files would be
  useless for exactly the operation that creates one.
- A relative path has no meaning without a base. `canonical` says so by
  returning None rather than quietly adopting the current process's directory —
  which is what the caller almost never means, and is a silent bypass when the
  process that decides and the process that acts sit in different directories.

What it deliberately does NOT do: promise the answer stays true. Between this
call and an `open()`, a symlink can be repointed. Only the operating system can
close that window (see `docs/deployment-security.md`); this module makes the
policy layer coherent, not authoritative.
"""

from __future__ import annotations

import os

__all__ = ["canonical", "is_under", "is_indeterminate"]


def canonical(path: str, *, base: str | None = None) -> str | None:
    """The one location `path` names, or None when it does not name one.

    `base` supplies the directory a relative path is relative to — the working
    directory of whatever will actually open the file. Without it a relative
    path is indeterminate and returns None; callers decide what that means for
    them (a deny rule should treat it as a match, an allow rule as a miss).
    """
    if not path:
        return None
    try:
        expanded = os.path.expanduser(path)
        if not os.path.isabs(expanded):
            if base is None:
                return None
            expanded = os.path.join(base, expanded)
        # realpath resolves `..` and symlinks, including symlinks in parents
        # that do exist, and tolerates a leaf that does not.
        return os.path.realpath(expanded)
    except (OSError, ValueError):
        # Embedded NUL, over-long path, and similar. No definite location, and
        # importantly not an exception escaping into a policy decision.
        return None


def is_indeterminate(path: str, *, base: str | None = None) -> bool:
    """True when `path` cannot be reduced to one location."""
    return canonical(path, base=base) is None


def is_under(child: str, parent: str) -> bool:
    """True when canonical `child` is `parent` itself or lies inside it.

    Both arguments must already be canonical. The separator is what makes this
    a directory test rather than a string test: without it `/srv/app-backup`
    reads as living under `/srv/app`, which over-denies a deny rule and
    over-grants an allow rule.
    """
    if child == parent:
        return True
    return child.startswith(parent.rstrip(os.sep) + os.sep)
