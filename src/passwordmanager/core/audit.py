"""Local password audit: reuse and weakness. Pure functions, no network."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from .generator import estimate_entropy_bits
from .vault import Entry

WEAK_MIN_LENGTH = 12
WEAK_MIN_BITS = 50.0
MIN_DISTINCT_CHARS = 6


def looks_patterned(password: str) -> bool:
    """Few distinct characters, or one short block repeated ('abcabcabc...').
    The pool-size entropy estimate alone would rate these as strong."""
    if len(set(password)) < MIN_DISTINCT_CHARS:
        return True
    return (password + password).find(password, 1) < len(password)


@dataclass
class AuditReport:
    reused: list[list[str]] = field(default_factory=list)  # groups of entry names
    weak: list[tuple[str, int]] = field(default_factory=list)  # (name, estimated bits)
    no_password: list[str] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.reused or self.weak)


def audit(entries: Iterable[Entry]) -> AuditReport:
    report = AuditReport()
    by_password: dict[str, list[str]] = defaultdict(list)
    for entry in sorted(entries, key=lambda e: e.name.lower()):
        if not entry.password:
            report.no_password.append(entry.name)
            continue
        by_password[entry.password].append(entry.name)
        bits = estimate_entropy_bits(entry.password)
        too_simple = len(entry.password) < WEAK_MIN_LENGTH or bits < WEAK_MIN_BITS
        if too_simple or looks_patterned(entry.password):
            report.weak.append((entry.name, round(bits)))
    report.reused = [names for names in by_password.values() if len(names) > 1]
    return report
