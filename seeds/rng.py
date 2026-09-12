"""Deterministic randomness helpers.

Every draw comes from one seeded `random.Random`, which is what makes
`--seed 42` reproduce a fixture database exactly.
"""

from __future__ import annotations

import random
from collections.abc import Sequence


class Rng:
    """Thin, opinionated wrapper over `random.Random`."""

    def __init__(self, seed: int | str) -> None:
        self._r = random.Random(seed)

    @property
    def raw(self) -> random.Random:
        return self._r

    def int(self, low: int, high: int) -> int:
        """Inclusive on both ends (unlike `random.randint` typo traps)."""
        return self._r.randint(low, high)

    def float(self, low: float = 0.0, high: float = 1.0) -> float:
        return self._r.uniform(low, high)

    def chance(self, p: float) -> bool:
        return self._r.random() < p

    def pick(self, items: Sequence) -> object:
        return self._r.choice(items)

    def weighted(self, pairs: Sequence[tuple[object, float]]) -> object:
        """`pairs` is a sequence of (value, weight)."""
        return self._r.choices([p[0] for p in pairs], weights=[p[1] for p in pairs], k=1)[0]

    def weighted_index(self, weights: Sequence[float], k: int = 1) -> list[int]:
        return self._r.choices(range(len(weights)), cum_weights=_cumsum(weights), k=k)

    def lognormal(self, mu: float, sigma: float, lo: float, hi: float) -> float:
        return min(hi, max(lo, self._r.lognormvariate(mu, sigma)))

    def pareto(self, alpha: float, lo: float = 1.0, hi: float = 1e9) -> float:
        """Heavy tail: use for message counts, session lengths, invite fan-out."""
        return min(hi, lo * ((1.0 - self._r.random()) ** (-1.0 / alpha)))

    def gauss(self, mu: float, sigma: float, lo: float, hi: float) -> float:
        return min(hi, max(lo, self._r.gauss(mu, sigma)))

    def jitter(self, base: float, pct: float) -> float:
        return base * (1.0 + self.float(-pct, pct))

    def hex_id(self, nbytes: int = 8) -> str:
        return "".join(self._r.choice("0123456789abcdef") for _ in range(nbytes * 2))



def _cumsum(weights: Sequence[float]) -> list[float]:
    out: list[float] = []
    total = 0.0
    for w in weights:
        total += w
        out.append(total)
    return out
