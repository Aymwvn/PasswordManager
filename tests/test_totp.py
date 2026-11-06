import base64
import string

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from passwordmanager.core.totp import TotpConfig, generate, parse, seconds_remaining

SHA1_KEY = b"12345678901234567890"
SHA256_KEY = b"12345678901234567890123456789012"
SHA512_KEY = b"1234567890123456789012345678901234567890123456789012345678901234"

# RFC 6238, Appendix B: (time, SHA1, SHA256, SHA512), 8 digits
RFC_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
FUZZ = settings(max_examples=int(__import__("os").environ.get("PM_FUZZ_EXAMPLES", "200")), deadline=None, suppress_health_check=list(HealthCheck))


@pytest.mark.parametrize("when,sha1,sha256,sha512", RFC_VECTORS)
def test_rfc_6238_vectors(when, sha1, sha256, sha512):
    assert generate(TotpConfig(SHA1_KEY, digits=8), when) == sha1
    assert generate(TotpConfig(SHA256_KEY, digits=8, algorithm="SHA256"), when) == sha256
    assert generate(TotpConfig(SHA512_KEY, digits=8, algorithm="SHA512"), when) == sha512


def test_six_digit_code_is_the_tail_of_the_eight_digit_one():
    assert generate(TotpConfig(SHA1_KEY), 59) == "287082"


def test_code_is_stable_within_a_period_and_changes_after():
    config = TotpConfig(SHA1_KEY)
    assert generate(config, 60) == generate(config, 89.9)
    assert generate(config, 60) != generate(config, 90)


def test_secret_formats_are_equivalent():
    secret = base64.b32encode(SHA1_KEY).decode()
    spaced = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
    forms = [secret, secret.lower(), spaced, spaced.replace(" ", "-"), secret.rstrip("=")]
    assert len({generate(parse(form), 59) for form in forms}) == 1


def test_otpauth_uri_is_parsed():
    uri = (
        "otpauth://totp/GitHub:aymen?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        "&digits=8&period=60&algorithm=sha256"
    )
    config = parse(uri)
    assert (config.digits, config.period, config.algorithm) == (8, 60, "SHA256")
    assert (config.issuer, config.label) == ("GitHub", "GitHub:aymen")


def test_otpauth_defaults_and_issuer_from_label():
    config = parse("otpauth://totp/Acme%20Co:bob%40example.com?secret=JBSWY3DPEHPK3PXP")
    assert (config.digits, config.period, config.algorithm) == (6, 30, "SHA1")
    assert config.issuer == "Acme Co"


@pytest.mark.parametrize(
    "bad",
    [
        "", "   ", "not base32!!", "JBSW", "\u00fcn\u00efc\u00f6d\u00e9",
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
        "otpauth://totp/x",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=1",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        "otpauth://totp/x?secret=",
    ],
)
def test_invalid_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        parse(bad)


def test_seconds_remaining_counts_down_to_the_boundary():
    config = TotpConfig(SHA1_KEY)
    assert seconds_remaining(config, 60) == 30
    assert seconds_remaining(config, 89) == 1


def test_time_before_epoch_is_rejected():
    with pytest.raises(ValueError):
        generate(TotpConfig(SHA1_KEY), -100)


@FUZZ
@given(st.text(max_size=200))
def test_parse_only_ever_raises_value_error(text):
    try:
        config = parse(text)
    except ValueError:
        return
    assert len(generate(config, 1_700_000_000)) == config.digits


@FUZZ
@given(st.text(alphabet=string.printable, max_size=200))
def test_fuzzed_otpauth_links_fail_cleanly(tail):
    try:
        config = parse("otpauth://totp/" + tail)
    except ValueError:
        return
    assert config.digits in (6, 7, 8)
