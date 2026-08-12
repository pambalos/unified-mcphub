import pytest

from unified_enforce import Action, CanonicalizationError, Principal, Signer


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
