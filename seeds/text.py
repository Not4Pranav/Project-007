from __future__ import annotations

import re

_DIGITS = re.compile(r"\d+")
_REPEAT = re.compile(r"(.)\1{2,}")


def username_template(name: str) -> str:
    """Mask digit runs so `guest00412` and `guest00413` collapse to one shape.

    Batch-registered accounts almost always share a template; this is the
    feature a signup-abuse rule keys on.
    """
    masked = _DIGITS.sub("#", (name or "").lower())
    return _REPEAT.sub(r"\1\1", masked)


def email_local_part(email: str) -> str:
    return (email or "").split("@", 1)[0].split("+", 1)[0]


def ip_prefix24(ip: str) -> str:
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip or ""


def entropy(s: str) -> float:
    import math

    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
