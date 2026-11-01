import string

import pytest

from passwordmanager.core.generator import (
    SYMBOLS,
    estimate_entropy_bits,
    generate_password,
    strength_label,
)


def test_length_and_classes():
    for _ in range(200):
        pw = generate_password(16)
        assert len(pw) == 16
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_no_symbols_option():
    for _ in range(100):
        assert all(c.isalnum() for c in generate_password(20, symbols=False))


def test_too_short_rejected():
    with pytest.raises(ValueError):
        generate_password(4)


def test_outputs_are_unique():
    assert len({generate_password(20) for _ in range(500)}) == 500


def test_entropy_grows_with_length_and_label():
    assert estimate_entropy_bits("abc") < estimate_entropy_bits("abcdefghijkl")
    assert strength_label(estimate_entropy_bits(generate_password(24))) == "strong"
    assert strength_label(10) == "weak"
