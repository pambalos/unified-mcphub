import pytest

from unified_enforce import CanonicalizationError, canonical_bytes, digest


def test_key_order_is_irrelevant():
    assert digest({"a": 1, "b": "x"}) == digest({"b": "x", "a": 1})


def test_bytes_are_compact_and_sorted():
    assert canonical_bytes({"b": 1, "a": [True, None]}) == b'{"a":[true,null],"b":1}'


def test_unicode_is_utf8_not_escaped():
    assert canonical_bytes({"k": "café"}) == '{"k":"café"}'.encode("utf-8")


def test_floats_are_rejected():
    with pytest.raises(CanonicalizationError, match=r"float at \$\.amount"):
        canonical_bytes({"amount": 1.5})


def test_nested_float_path_is_reported():
    with pytest.raises(CanonicalizationError, match=r"\$\.a\[0\]\.b"):
        canonical_bytes({"a": [{"b": 0.1}]})


def test_non_json_values_are_rejected_not_coerced():
    with pytest.raises(CanonicalizationError, match="non-JSON value"):
        canonical_bytes({"k": object()})


def test_non_string_keys_are_rejected():
    with pytest.raises(CanonicalizationError, match="non-string key"):
        canonical_bytes({"k": {1: "x"}})
