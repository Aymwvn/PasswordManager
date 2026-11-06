import hashlib
import urllib.error

import pytest

from passwordmanager.core import breach


def test_sha1_split_matches_the_known_value_for_password():
    # Well-known: SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    assert breach.sha1_parts("password") == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")


def test_only_a_five_character_prefix_ever_leaves_the_machine():
    seen = []
    breach.check_password("hunter2hunter2", lambda prefix: seen.append(prefix) or "")
    assert seen == [hashlib.sha1(b"hunter2hunter2").hexdigest().upper()[:5]]
    assert "hunter2" not in seen[0]


def _body(password, count):
    _, suffix = breach.sha1_parts(password)
    return f"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{suffix}:{count}\r\n011053FD0102:1\r\n"


def test_count_is_read_from_the_range_response():
    assert breach.check_password("password", lambda _p: _body("password", 10437277)) == 10437277


def test_zero_count_padding_lines_are_not_a_match():
    assert breach.check_password("password", lambda _p: _body("password", 0)) == 0


def test_absent_suffix_means_not_breached():
    assert breach.check_password("a-unique-passphrase-x9", lambda _p: "ABC:5\r\nDEF:9") == 0


def test_suffix_match_is_case_insensitive():
    body = _body("password", 7).lower()
    assert breach.check_password("password", lambda _p: body) == 7


def test_malformed_count_is_an_error_not_a_crash():
    with pytest.raises(breach.BreachCheckError):
        breach.check_password("password", lambda _p: _body("password", "abc"))


def test_http_fetch_rejects_bad_prefixes():
    for bad in ("zz", "5BAA61", "5baa6", "5BAA/", ""):
        with pytest.raises(ValueError):
            breach.http_fetch(bad)


class _Response:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit):
        return self.data[:limit]


def test_http_fetch_request_shape(monkeypatch):
    captured = {}

    def fake_open(request, timeout):
        captured.update(request=request, timeout=timeout)
        return _Response(b"ABC:1")

    monkeypatch.setattr(breach._OPENER, "open", fake_open)
    assert breach.http_fetch("5BAA6") == "ABC:1"
    request = captured["request"]
    assert request.full_url == "https://api.pwnedpasswords.com/range/5BAA6"
    assert request.get_header("Add-padding") == "true"
    assert "PasswordManager" in request.get_header("User-agent")
    assert captured["timeout"] <= 10


def test_network_failures_become_breach_check_errors(monkeypatch):
    def boom(request, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(breach._OPENER, "open", boom)
    with pytest.raises(breach.BreachCheckError):
        breach.http_fetch("5BAA6")


def test_oversized_responses_are_rejected(monkeypatch):
    big = b"A" * (breach.MAX_RESPONSE_BYTES + 5)
    monkeypatch.setattr(breach._OPENER, "open", lambda request, timeout: _Response(big))
    with pytest.raises(breach.BreachCheckError):
        breach.http_fetch("5BAA6")


def test_redirects_are_never_followed():
    handler = breach._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://evil.example/") is None
