"""Password generation (CSPRNG only) and a rough strength estimate."""

from __future__ import annotations

import math
import secrets
import string

SYMBOLS = "!@#$%^&*-_=+?"
MIN_LENGTH = 8


def generate_password(length: int = 20, symbols: bool = True) -> str:
    if length < MIN_LENGTH:
        raise ValueError(f"length must be at least {MIN_LENGTH}")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    # Guarantee one char from every pool, fill the rest from the union, then shuffle.
    chars = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def estimate_entropy_bits(password: str) -> float:
    """Naive pool-size estimate. Over-rates human-chosen passwords; fine for generated ones."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33
    return len(password) * math.log2(pool) if pool else 0.0


def strength_label(bits: float) -> str:
    if bits < 40:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 80:
        return "good"
    return "strong"
