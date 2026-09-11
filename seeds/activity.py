from __future__ import annotations

import time

from .rng import Rng

EVENT_KINDS: tuple[tuple[str, int], ...] = (
    ("message", 46),
    ("reaction", 24),
    ("login", 12),
    ("comment", 9),
    ("post", 5),
    ("profile_update", 3),
    ("logout", 1),
)


def generate_activity(
    users: list[dict],
    rng: Rng,
    *,
    events_per_user_mu: float = -0.4,
    max_events: int = 900,
    window_days: int = 30,
    now: int | None = None,
) -> list[dict]:
    """Attach a realistic activity tail to each user.

    Volume is Pareto, not Poisson: in real products the top 5% of accounts
    produce a wildly disproportionate share of writes, and that skew is what
    breaks your feed query, not the average case.
    """
    now = now or int(time.time())
    horizon = window_days * 86400
    out: list[dict] = []
    for u in users:
        if u["status"] in ("deleted",):
            scale = 0.05
        elif u["status"] == "suspended":
            scale = 0.2
        elif u["status"] == "pending_verification":
            scale = 0.35
        else:
            scale = 1.0
        base = int(min(max_events, max(0, rng.pareto(alpha=0.9, lo=1.0) * 9 * scale)))
        if base == 0:
            continue
        signup = u["signup_ts"]
        # Never date activity after "now": a fixture whose history runs into next
        # week wins every `ORDER BY ts DESC` page and silently breaks feeds,
        # dashboards, and "recent activity" checks.
        room = now - signup
        if room < 60:
            continue
        span = max(3600, min(horizon, room, rng.int(6 * 3600, horizon)))
        for _ in range(base):
            ts = min(now, signup + int(rng.raw.random() ** 0.72 * span))
            kind = str(rng.weighted(EVENT_KINDS))
            weight = 1 if kind != "reaction" else rng.int(1, 12)
            out.append({
                "user_id": u["id"],
                "ts": ts,
                "kind": kind,
                "weight": weight,
                "ip": u["signup_ip"],
                "meta": None,
            })
    out.sort(key=lambda e: e["ts"])
    return out


def generate_sessions(users: list[dict], rng: Rng, *, max_per_user: int = 6,
                      now: int | None = None) -> list[dict]:
    """A couple of live sessions per active user, so the login-path benchmarks
    have something to invalidate instead of minting fresh tokens forever."""
    now = now or int(time.time())
    out: list[dict] = []
    for u in users:
        if u["status"] not in ("active", "suspended"):
            continue
        n = rng.int(1, max_per_user) if u["status"] == "active" else rng.int(0, 1)
        for _ in range(n):
            room = max(1, now - u["signup_ts"])
            created = u["signup_ts"] + rng.int(0, min(25 * 86400, room))
            last = min(now, created + rng.int(60, 9 * 86400))
            out.append({
                "user_id": u["id"],
                "token": f"ses_{rng.hex_id(14)}",
                "ip": u["signup_ip"] if rng.chance(0.7) else f"{rng.int(1, 223)}.{rng.int(0, 255)}.{rng.int(0, 255)}.{rng.int(1, 254)}",
                "ua": u["signup_ua"],
                "device_class": u["device_class"],
                "created_ts": created,
                "last_seen_ts": last,
                "revoked": 1 if rng.chance(0.12) else 0,
            })
    return out
