"""Have I Been Pwned password check using k-anonymity.

Only the first 5 hex characters of the password's SHA-1 are sent (the same for ~800 000 other
passwords); matching happens locally. The request also asks HIBP to pad the response so its
size doesn't reveal the match. The password itself never leaves the machine.

This makes a network call, so it is only ever triggered by an explicit user action.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from collections.abc import Callable

API_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "PasswordManager (+https://github.com/Aymwvn/PasswordManager)"
MAX_RESPONSE_BYTES = 2_000_000
HEX = "0123456789ABCDEF"


class BreachCheckError(Exception):
    """The check could not be completed (offline, blocked, malformed response)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow redirects off the fixed URL
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def sha1_parts(password: str) -> tuple[str, str]:
    # SHA-1 is mandated by the HIBP range protocol; it is not used for any security purpose here.
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:5], digest[5:]


def http_fetch(prefix: str, timeout: float = 8.0) -> str:
    if len(prefix) != 5 or any(c not in HEX for c in prefix):
        raise ValueError("prefix must be exactly 5 uppercase hex characters")
    request = urllib.request.Request(  # noqa: S310 - fixed https URL, validated prefix
        API_URL + prefix, headers={"User-Agent": USER_AGENT, "Add-Padding": "true"}
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BreachCheckError("could not reach the breach-check service") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise BreachCheckError("breach-check response was unexpectedly large")
    return body.decode("utf-8", errors="replace")


def parse_range(body: str, suffix: str) -> int:
    """Count for `suffix` in a range response ('SUFFIX:COUNT' lines). 0 if absent or padding."""
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            try:
                return max(0, int(count))
            except ValueError:
                raise BreachCheckError("malformed breach-check response") from None
    return 0


def check_password(password: str, fetch: Callable[[str], str] = http_fetch) -> int:
    """How many times the password appears in known breaches (0 = not found)."""
    prefix, suffix = sha1_parts(password)
    return parse_range(fetch(prefix), suffix)
