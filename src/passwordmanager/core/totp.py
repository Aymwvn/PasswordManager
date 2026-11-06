"""RFC 6238 TOTP (standard library only) and otpauth:// URI parsing."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
MIN_SECRET_BYTES = 10  # 80 bits: the smallest secret authenticator apps commonly use
VALID_DIGITS = (6, 7, 8)
PERIOD_RANGE = (10, 300)


@dataclass(frozen=True)
class TotpConfig:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    issuer: str = ""
    label: str = ""


def _decode_secret(text: str) -> bytes:
    cleaned = "".join(text.split()).replace("-", "").upper().rstrip("=")
    if not cleaned:
        raise ValueError("TOTP secret is empty")
    if not cleaned.isascii():
        raise ValueError("TOTP secret is not valid base32")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        secret = base64.b32decode(cleaned)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("TOTP secret is not valid base32") from exc
    if len(secret) < MIN_SECRET_BYTES:
        raise ValueError(f"TOTP secret is too short (need at least {MIN_SECRET_BYTES} bytes)")
    return secret


def _int_param(params: dict[str, list[str]], key: str, default: int) -> int:
    if key not in params:
        return default
    try:
        return int(params[key][0])
    except ValueError:
        raise ValueError(f"otpauth '{key}' must be a number") from None


def parse(value: str) -> TotpConfig:
    """Accepts a bare base32 secret or an otpauth://totp/... URI. Raises ValueError."""
    value = value.strip()
    if not value.lower().startswith("otpauth://"):
        return TotpConfig(secret=_decode_secret(value))

    parsed = urlparse(value)
    if parsed.netloc.lower() != "totp":
        raise ValueError("only otpauth://totp/ links are supported")
    params = parse_qs(parsed.query, max_num_fields=20)
    if "secret" not in params:
        raise ValueError("otpauth link has no secret")
    algorithm = params.get("algorithm", ["SHA1"])[0].upper()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported TOTP algorithm '{algorithm}'")
    digits = _int_param(params, "digits", 6)
    if digits not in VALID_DIGITS:
        raise ValueError("TOTP digits must be 6, 7 or 8")
    period = _int_param(params, "period", 30)
    if not PERIOD_RANGE[0] <= period <= PERIOD_RANGE[1]:
        raise ValueError(f"TOTP period must be between {PERIOD_RANGE[0]} and {PERIOD_RANGE[1]}s")
    label = unquote(parsed.path.lstrip("/"))
    issuer = params.get("issuer", [""])[0] or (label.split(":", 1)[0] if ":" in label else "")
    return TotpConfig(_decode_secret(params["secret"][0]), digits, period, algorithm, issuer, label)


def generate(config: TotpConfig, at: float | None = None) -> str:
    now = time.time() if at is None else at
    counter = int(now // config.period)
    if counter < 0:
        raise ValueError("time is before the Unix epoch")
    digest = hmac.new(
        config.secret, struct.pack(">Q", counter), ALGORITHMS[config.algorithm]
    ).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**config.digits).zfill(config.digits)


def seconds_remaining(config: TotpConfig, at: float | None = None) -> int:
    now = time.time() if at is None else at
    return config.period - int(now % config.period)
