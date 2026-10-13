"""Canonical serialization and time rules shared by every contract in the core.

Digests appear in authorization records, coverage manifests, closure intents and
the audit chain. They are only comparable if every component computes them the
same way, so the one implementation lives here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

#: Bumped whenever the canonical form changes. Stored alongside every digest so
#: a recomputation under a newer rule is a reviewed equivalence decision (U10),
#: never a silent comparison.
CANONICAL_VERSION = 1

_SHA256_HEX_LENGTH = 64


def digest(value: Any) -> str:
    """Return the canonical SHA-256 hex digest of a JSON-serializable value.

    Rejects NaN/Infinity so a digest can never depend on a non-finite float that
    round-trips differently between producers.
    """
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def is_digest(value: Any) -> bool:
    """True when ``value`` has the exact shape of a lowercase SHA-256 hex digest."""
    if not isinstance(value, str) or len(value) != _SHA256_HEX_LENGTH:
        return False
    return all(character in "0123456789abcdef" for character in value)


def is_aware(value: Any) -> bool:
    """True when ``value`` is a timezone-aware datetime.

    The core refuses naive datetimes everywhere. A naive timestamp silently
    adopts the reader's local zone, which would make a testing window, an EPSS
    freshness check or an anchor-overdue decision depend on where it ran.
    """
    return isinstance(value, datetime) and value.utcoffset() is not None


def require_aware(**named: Any) -> list[str]:
    """Return the names of any arguments that are not timezone-aware datetimes."""
    return [name for name, value in named.items() if not is_aware(value)]


def utc(*args: int) -> datetime:
    """Build a UTC datetime. Convenience for fixtures and callers."""
    return datetime(*args, tzinfo=timezone.utc)


def elapsed(start: datetime, end: datetime) -> timedelta:
    """Signed interval between two aware datetimes."""
    if require_aware(start=start, end=end):
        raise ValueError("timezone-aware datetimes required")
    return end - start
