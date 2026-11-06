"""Crypto primitives: Argon2id key derivation + AES-256-GCM with a versioned header.

File layout (format version 1):

    MAGIC(4) | version(1) | time_cost(4) | memory_cost(4) | parallelism(4)
    | salt(16) | nonce(12) | ciphertext + GCM tag

The whole header is passed to AES-GCM as associated data (AAD), so changing any header
byte (KDF params, salt, version) makes decryption fail instead of being silently accepted.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from argon2.exceptions import Argon2Error
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PMGR"  # vault files
EXPORT_MAGIC = b"PMEX"  # encrypted export files (.pmbak); the magic is part of the AAD
FORMAT_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16

_HEADER = struct.Struct(">4sBIII16s12s")
HEADER_SIZE = _HEADER.size

# Sanity bounds: the header is attacker-controlled input (anyone can hand us a vault file), so
# it must not be able to demand unreasonable CPU/RAM. Defaults are t=3, 64 MiB, p=4.
_MAX_TIME = 10
_MAX_MEMORY_KIB = 256 * 1024  # 256 MiB
_MAX_PARALLELISM = 16


class CryptoError(Exception):
    """Base class for crypto failures."""


class InvalidFormat(CryptoError):
    """File is not a (supported) vault."""


class DecryptionError(CryptoError):
    """Wrong password, or the file was modified."""


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_cost: int = 64 * 1024  # KiB -> 64 MiB
    parallelism: int = 4


@dataclass(frozen=True)
class Header:
    version: int
    params: KdfParams
    salt: bytes
    nonce: bytes


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def encrypt(
    key: bytes, plaintext: bytes, salt: bytes, params: KdfParams, magic: bytes = MAGIC
) -> bytes:
    """Encrypt with a fresh random nonce. Returns header + ciphertext."""
    nonce = os.urandom(NONCE_LEN)
    header = _HEADER.pack(
        magic, FORMAT_VERSION, params.time_cost, params.memory_cost, params.parallelism, salt, nonce
    )
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def parse_header(blob: bytes, magic: bytes = MAGIC) -> Header:
    if len(blob) < HEADER_SIZE + TAG_LEN:
        raise InvalidFormat("file too short to be a vault")
    found, version, time_cost, memory_cost, parallelism, salt, nonce = _HEADER.unpack_from(blob)
    if found != magic:
        raise InvalidFormat("not the expected PasswordManager file type")
    if version != FORMAT_VERSION:
        raise InvalidFormat(f"unsupported vault version {version}")
    if not (
        1 <= time_cost <= _MAX_TIME
        and 1 <= parallelism <= _MAX_PARALLELISM
        and 8 * parallelism <= memory_cost <= _MAX_MEMORY_KIB  # Argon2 needs m >= 8*p
    ):
        raise InvalidFormat("vault has out-of-range KDF parameters")
    return Header(version, KdfParams(time_cost, memory_cost, parallelism), salt, nonce)


def decrypt(password: str, blob: bytes, magic: bytes = MAGIC) -> tuple[bytes, bytes, Header]:
    """Returns (plaintext, derived_key, header). Raises DecryptionError on failure."""
    header = parse_header(blob, magic)
    try:
        key = derive_key(password, header.salt, header.params)
    except Argon2Error as exc:  # belt and braces: never let a library error escape as a crash
        raise InvalidFormat("vault has unusable KDF parameters") from exc
    try:
        plaintext = AESGCM(key).decrypt(header.nonce, blob[HEADER_SIZE:], blob[:HEADER_SIZE])
    except InvalidTag as exc:
        raise DecryptionError("wrong master password, or the vault was tampered with") from exc
    return plaintext, key, header
