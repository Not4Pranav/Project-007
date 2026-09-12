"""Time-of-day / day-of-week signup shapes, cohorts, and injected abuse.

The point of a synthetic signup curve is not cosmetic realism: rate limits,
partitioning, nightly cron jobs, and "new user" indexes all behave differently
when signups are spread the way a real product sees them rather than uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .rng import Rng

# Relative traffic per weekday, Mon..Sun.
WEEKDAY_WEIGHTS: tuple[float, ...] = (1.06, 1.08, 1.05, 1.02, 0.96, 0.82, 0.79)

# Share of active population awake/engaging, indexed by LOCAL hour. Bimodal
# (commute + evening) is close enough to real web traffic for capacity testing.
DIURNAL: tuple[float, ...] = (
    0.22, 0.16, 0.12, 0.10, 0.10, 0.14, 0.28, 0.52, 0.78, 0.92,
    0.98, 1.00, 0.96, 0.94, 0.98, 1.02, 1.06, 1.10, 1.14, 1.16,
    1.12, 0.98, 0.72, 0.44,
)


@dataclass(frozen=True)
class Cohort:
    """A slice of the population that shares acquisition characteristics.

    `username_styles` is where the naming mix lives (see `make_username` for the
    shapes); weighting it per cohort is what makes `--users 30000` look like
    several acquisition channels instead of one generator.
    """

    name: str
    weight: float
    username_styles: dict[str, float] = field(default_factory=dict)
    domain_bias: float = 0.0  # >0 favours disposable domains (abuse fixtures only)
    verify_delay_mu: float = 1.4  # lognormal mu over minutes
    activity_scale: float = 1.0


DEFAULT_COHORTS: tuple[Cohort, ...] = (
    Cohort("organic", 46, {"handle": 24, "first.last.num": 26, "adjective_noun_num": 22},
           verify_delay_mu=1.6, activity_scale=1.15),
    Cohort("referral", 25, {"first.last.num": 30, "nickname_repeat": 16, "name_year": 14},
           verify_delay_mu=1.1, activity_scale=1.45),
    Cohort("paid", 14, {"adjective_noun_num": 30, "initial_last_num": 22},
           verify_delay_mu=2.1, activity_scale=0.75),
    Cohort("campaign", 10, {"name_year": 26, "handle": 22},
           verify_delay_mu=1.8, activity_scale=0.55),
    Cohort("lowint", 5, {"initial_last_num": 28, "adjective_noun_num": 20},
           domain_bias=0.06, verify_delay_mu=2.4, activity_scale=0.25),
)


class SignupCurve:
    """Hourly probability weights over a window, combining growth + seasonality."""

    def __init__(
        self,
        start_epoch: int,
        days: int,
        region_offsets: tuple[tuple[float, float], ...],  # (utc_offset_hours, population weight)
        growth: float = 0.6,
    ) -> None:
        self.start_epoch = start_epoch
        self.days = days
        self.hours = days * 24
        self.weights = self._build(region_offsets, growth)

    def _build(self, region_offsets, growth: float) -> list[float]:
        weights: list[float] = []
        for h in range(self.hours):
            day = h // 24
            # Linear growth from 1.0 -> 1.0+growth across the window.
            trend = 1.0 + growth * (day / max(1, self.days - 1))
            weekday = WEEKDAY_WEIGHTS[((self.start_epoch // 86400) + day) % 7]
            utc_hour = h % 24
            local_share = 0.0
            pop = 0.0
            for offset, w in region_offsets:
                local_hour = int((utc_hour + offset) % 24)
                local_share += DIURNAL[local_hour] * w
                pop += w
            weights.append(trend * weekday * (local_share / pop))
        return weights

    def sample(self, rng: Rng, n: int) -> list[int]:
        """Return `n` sorted epoch seconds drawn from the curve."""
        idx = rng.weighted_index(self.weights, k=n)
        out = [
            self.start_epoch + i * 3600 + rng.int(0, 3599) for i in idx
        ]
        out.sort()
        return out


@dataclass
class Burst:
    """A tight cluster of signups: launch spike, broadcast link, or abuse run."""

    start_epoch: int
    count: int
    spacing_seconds: float
    kind: str


def make_bursts(rng: Rng, window: tuple[int, int], count: int, kind: str = "campaign") -> list[Burst]:
    """Spike-shaped clusters with sub-minute spacing, Pareto-sized."""
    lo, hi = window
    bursts: list[Burst] = []
    for _ in range(count):
        size = int(min(400, max(6, rng.pareto(alpha=1.15, lo=8))))
        spacing = rng.lognormal(mu=1.6, sigma=0.7, lo=1.0, hi=90.0)
        start = rng.int(lo, max(lo, hi - int(size * spacing) - 1))
        bursts.append(Burst(start_epoch=start, count=size, spacing_seconds=spacing, kind=kind))
    return bursts


def allocate(total: int, weights: list[float]) -> list[int]:
    """Largest-remainder allocation so per-cohort counts sum exactly to total."""
    s = sum(weights)
    raw = [total * w / s for w in weights]
    base = [int(x) for x in raw]
    rem = total - sum(base)
    order = sorted(range(len(raw)), key=lambda i: raw[i] - base[i], reverse=True)
    for i in order[: max(0, rem)]:
        base[i] += 1
    return base


def verify_delay_seconds(rng: Rng, mu: float) -> int:
    """Real people verify by email minutes-to-hours later, with a long tail.

    Anything under ~10s is physically odd for a human and is a feature the
    abuse detector keys on.
    """
    return int(min(48 * 3600, max(1, rng.lognormal(mu=mu, sigma=1.15, lo=1.0, hi=1e5)) * 60))
