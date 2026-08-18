"""The shared canonicalisation. Its whole job is that two components cannot
disagree about which file a string names, so the cases below are the ones where
a naive implementation gives two different answers."""

from __future__ import annotations

import os

from unified_paths import canonical, is_indeterminate, is_under


def test_traversal_collapses():
    assert canonical("/srv/app/../data/f.txt") == "/srv/data/f.txt"


def test_symlinks_resolve_including_in_parents(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "f.txt").write_text("x")
    link = tmp_path / "link"
    link.symlink_to(real)
    # The case a lexical check misses: the string never mentions `real`.
    assert canonical(str(link / "f.txt")) == str(real / "f.txt")


def test_a_target_that_does_not_exist_still_canonicalises(tmp_path):
    """The thing being authorised is usually a file about to be created."""
    target = tmp_path / "sub" / "new.txt"
    assert canonical(str(target)) == str(target)


def test_relative_without_a_base_is_indeterminate():
    """It names no single location, and saying so beats quietly adopting the
    current process's directory — which is a silent bypass when the process
    deciding and the process acting sit in different places."""
    assert canonical("notes.txt") is None
    assert is_indeterminate("notes.txt")


def test_relative_with_a_base_resolves_against_it():
    assert canonical("notes.txt", base="/srv/app") == "/srv/app/notes.txt"
    assert canonical("../notes.txt", base="/srv/app") == "/srv/notes.txt"


def test_empty_and_unparseable_are_indeterminate():
    assert canonical("") is None
    assert canonical("\0") is None


def test_user_expansion():
    assert canonical("~") == os.path.realpath(os.path.expanduser("~"))


def test_is_under_requires_a_directory_boundary():
    assert is_under("/srv/app", "/srv/app")
    assert is_under("/srv/app/x.txt", "/srv/app")
    # The sibling that a bare string prefix wrongly swept up.
    assert not is_under("/srv/app-backup/x.txt", "/srv/app")
    assert not is_under("/srv/other", "/srv/app")


def test_is_under_tolerates_a_trailing_separator_on_the_parent():
    assert is_under("/srv/app/x.txt", "/srv/app/")
