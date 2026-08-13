import pytest

from unified_enforce import SCHEMA_VERSION, Action, CanonicalizationError, Principal, Signer


def make_action(**overrides) -> Action:
    kwargs = dict(
        principal=Principal(id="agent:claude-code"),
        tool="mcp://github/create_pr",
        verb="call",
        resource="repo:acme/api",
        params={"title": "fix", "draft": True},
    )
    kwargs.update(overrides)
    return Action.build(**kwargs)


def test_digest_is_stable_across_serialization_roundtrip():
    action = make_action()
    clone = Action.model_validate_json(action.model_dump_json())
    assert clone.digest() == action.digest()


def test_identical_payloads_get_distinct_ids_but_param_changes_change_digest():
    a = make_action()
    b = make_action()
    assert a.id != b.id  # ULID per observed action
    c = a.model_copy(update={"params": {"title": "fix", "draft": False}})
    assert c.digest() != a.digest()


def test_float_params_fail_canonicalization():
    action = make_action(params={"amount": 12.5})
    with pytest.raises(CanonicalizationError):
        action.digest()


def test_sign_and_verify():
    signer = Signer.generate("key-1")
    signed = signer.sign(make_action())
    assert signed.key_id == "key-1"
    assert signed.verify(signer.public_bytes())


def test_tampered_action_fails_verification():
    signer = Signer.generate("key-1")
    signed = signer.sign(make_action())
    tampered = signed.model_copy(
        update={"action": signed.action.model_copy(update={"verb": "delete"})}
    )
    assert not tampered.verify(signer.public_bytes())


def test_wrong_key_fails_verification():
    signed = Signer.generate("key-1").sign(make_action())
    other = Signer.generate("key-2")
    assert not signed.verify(other.public_bytes())


def test_signer_roundtrips_private_bytes():
    signer = Signer.generate("key-1")
    restored = Signer.from_private_bytes(signer.private_bytes(), "key-1")
    signed = restored.sign(make_action())
    assert signed.verify(signer.public_bytes())


# --- how an identity was established ------------------------------------------------
#
# Every rule the plane enforces keys on `principal.id`, so the strength of a
# floor, a budget or a kill switch is the strength of that identifier. Until
# this field existed, nothing recorded which kind it was — and "we enforce per
# agent" meant three different things depending on the deployment.


def test_an_identity_is_assumed_unproven_unless_something_says_otherwise():
    """The default is the weakest answer, deliberately.

    A caller that has not thought about how it knows who is acting must not be
    recorded as having proven anything — the whole point of the field is that
    somebody reads it later and decides how much to believe.
    """
    assert Principal(id="agent:x").attestation == "assigned"


def test_lineage_is_recorded_rather_than_collapsed():
    """An agent that spawns agents is the common case in the frameworks this
    supports, and a child inheriting its parent's id makes the audit wrong in a
    way that only surfaces during an incident: every action looks like the
    parent's, so "what did the researcher do" has no answer, and revoking the
    child revokes the parent."""
    child = Principal(id="agent:researcher", parent_id="agent:crew-1")

    assert child.lineage() == ["agent:researcher", "agent:crew-1"]
    assert child.id != child.parent_id


def test_an_orphan_needs_no_special_case():
    """`lineage()` returns a list either way, so no caller needs a branch and
    none will forget one."""
    assert Principal(id="agent:crew-1").lineage() == ["agent:crew-1"]


def test_lineage_does_not_imply_attestation():
    """A child of an assigned parent is not better attested than its parent.

    Worth pinning because the opposite is a tempting shortcut: a derived child
    of a proven parent *sounds* proven. The two fields are independent because
    they answer different questions, and conflating them would let lineage
    launder an unproven identity into a trusted-looking one.
    """
    child = Principal(id="agent:researcher", parent_id="agent:crew-1")

    assert child.attestation == "assigned"


def test_the_attestation_is_part_of_the_action_digest():
    """So it cannot be rewritten without changing the identity of the action.

    The digest is the join key into the customer's chain and into the approval
    queue. An action whose principal was merely assigned and one whose
    principal was attested are not the same action and should not share a
    digest.

    **Everything but the attestation is held fixed**, including `id` and `ts`.
    The first version of this test used `Action.build` twice, which mints a
    fresh ULID and timestamp each call — so the digests differed no matter what
    the principal said, and the test passed whether or not the field was
    covered at all. Same shape as the vacuous checks this suite exists to
    catch, written while writing them.
    """
    fixed = {
        "schema_version": SCHEMA_VERSION,
        "id": "01KZSPD9BJWDYY6GTG49RXGRY3",
        "ts": "2026-08-12T00:00:00.000000+00:00",
        "tool": "mcp://s/t",
        "verb": "call",
        "resource": "*",
        "params": {},
    }
    assigned = Action(principal=Principal(id="agent:x", attestation="assigned"), **fixed)
    attested = Action(principal=Principal(id="agent:x", attestation="attested"), **fixed)

    assert assigned.digest() != attested.digest()

    # And the control: identical principals really do agree, so the difference
    # above is the attestation rather than anything else about construction.
    same = Action(principal=Principal(id="agent:x", attestation="assigned"), **fixed)
    assert assigned.digest() == same.digest()


def test_lineage_is_part_of_the_action_digest():
    """For the same reason: a child's action is not its parent's action."""
    fixed = {
        "schema_version": SCHEMA_VERSION,
        "id": "01KZSPD9BJWDYY6GTG49RXGRY3",
        "ts": "2026-08-12T00:00:00.000000+00:00",
        "tool": "mcp://s/t",
        "verb": "call",
        "resource": "*",
        "params": {},
    }
    orphan = Action(principal=Principal(id="agent:researcher"), **fixed)
    child = Action(principal=Principal(id="agent:researcher", parent_id="agent:crew-1"), **fixed)

    assert orphan.digest() != child.digest()
