"""Seed a throwaway database with bulk test accounts + activity.

    python -m seeds.seed --users 25000 --db var/test.db --seed 42

Everything derives from one seed, so re-running produces an identical fixture.
Only ever point this at a database you own (local, ephemeral CI, or staging).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from itertools import count

from . import corpus
from .activity import generate_activity, generate_sessions
from .db import connect, migrate, reset, set_meta, table_counts
from .distribution import DEFAULT_COHORTS, Burst, SignupCurve, make_bursts
from .profile import PasswordPolicy, build_profile
from .report import render
from .rng import Rng

BATCH = 4000
USER_COLS = (
    "username", "email", "email_domain", "display_name", "dob", "country", "region", "timezone",
    "locale", "signup_ts", "signup_ip", "signup_ua", "device_class", "source", "invited_by",
    "status", "verified_ts", "has_phone", "newsletter", "bio", "avatar_seed", "is_synthetic_abuse",
)


def _parse_when(value: str) -> int:
    if value in ("now", ""):
        return int(time.time() // 3600 * 3600)
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


def build_user_rows(
    rng: Rng,
    *,
    n_users: int,
    window: tuple[int, int],
    days: int,
    growth: float,
    burst_count: int,
    burst_share: float,
    bots: int,
    policy: PasswordPolicy,
    password: str,
    iterations: int,
    algo: str = "pbkdf2_sha256",
) -> tuple[list[dict], list[Burst]]:
    """Generate user dicts in chronological order (ids follow signup order)."""
    lo, hi = window
    bots = max(0, min(bots, n_users))  # --users is the total *including* injected bots
    curve = SignupCurve(lo, days, tuple((r[3], r[5]) for r in corpus.REGIONS), growth=growth)

    n_organic = max(0, n_users - bots)

    n_burst = int(n_organic * burst_share)
    organic = curve.sample(rng, n_organic - n_burst)

    bursts = make_bursts(rng, (lo, hi), burst_count) if n_burst else []
    burst_times: list[int] = []
    for b in bursts:
        t = b.start_epoch
        for _ in range(b.count):
            burst_times.append(min(hi - 1, t))
            t += int(rng.jitter(b.spacing_seconds, 0.6))
    # Trim/pad the burst pool to exactly the share we promised.
    while len(burst_times) > n_burst:
        burst_times.pop()
    while len(burst_times) < n_burst:
        burst_times.append(curve.sample(rng, 1)[0])

    timestamps = sorted(organic + burst_times[: len(burst_times)])

    taken_users: set[str] = set()
    taken_emails: set[str] = set()
    # A few shared /24s model NAT/mobile-carrier exit nodes: real, and the
    # reason naive "1 signup per IP" rate limiting is a false-positive machine.
    ip_pool = [(rng.int(24, 223), rng.int(0, 255), rng.int(0, 255)) for _ in range(14)]
    cohort_weights = [c.weight for c in DEFAULT_COHORTS]
    cohorts = list(DEFAULT_COHORTS)

    rows: list[dict] = []
    i = count(1)
    for idx, ts in enumerate(timestamps):
        cohort = cohorts[rng.weighted_index(cohort_weights)[0]]
        row, _ = build_profile(
            rng, seq=idx, signup_ts=ts, cohort=cohort, taken_usernames=taken_users,
            taken_emails=taken_emails, ip_prefix_pool=ip_pool, policy=policy,
            password=password, algo=algo, iterations=iterations,
        )
        rows.append({
            "id": next(i), "username": row.username, "email": row.email, "email_domain": row.email_domain,
            "display_name": row.display_name, "dob": row.dob, "country": row.country, "region": row.region,
            "timezone": row.timezone, "locale": row.locale, "signup_ts": row.signup_ts, "signup_ip": row.signup_ip,
            "signup_ua": row.signup_ua, "device_class": row.device_class, "source": row.source,
            "invited_by": None, "status": row.status, "verified_ts": row.verified_ts, "has_phone": row.has_phone,
            "newsletter": row.newsletter, "bio": row.bio, "avatar_seed": row.avatar_seed,
            "_salt": row.password_salt, "_hash": row.password_hash, "_iter": iterations,
            "_algo": row.password_algo, "is_synthetic_abuse": 0,
        })

    # Injected automation cohort: one /24, one UA, sequential names, instant
    # verification, all invited by a single amplifier account.
    if bots:
        bot_ip_prefix = (rng.int(45, 198), rng.int(0, 255), rng.int(0, 255))
        ip_pool.insert(0, bot_ip_prefix)
        amp_id = rows[-1]["id"] if rows else 1
        start = hi - 900
        for j in range(bots):
            row, _ = build_profile(
                rng, seq=10_000 + j, signup_ts=min(hi - 1, start + j), cohort=cohorts[-1],
                taken_usernames=taken_users, taken_emails=taken_emails, ip_prefix_pool=ip_pool,
                policy=policy, password=password, algo=algo, iterations=iterations, bot=True,
            )
            rows.append({
                "id": next(i), "username": row.username, "email": row.email, "email_domain": row.email_domain,
                "display_name": row.display_name, "dob": row.dob, "country": row.country, "region": row.region,
                "timezone": row.timezone, "locale": row.locale, "signup_ts": row.signup_ts,
                "signup_ip": row.signup_ip, "signup_ua": row.signup_ua, "device_class": row.device_class,
                "source": "campaign", "invited_by": amp_id if j % 3 == 0 else None, "status": row.status,
                "verified_ts": row.verified_ts, "has_phone": 0, "newsletter": 0, "bio": "",
                "avatar_seed": row.avatar_seed, "_salt": row.password_salt, "_hash": row.password_hash,
                "_iter": iterations, "_algo": row.password_algo, "is_synthetic_abuse": 1,
            })

    # Preferential-ish attachment for referral cohorts: earlier ids accumulate
    # more invitees, so the fan-in distribution looks like a real one.
    for idx, row in enumerate(rows):
        if row["invited_by"] is not None or row["source"] not in ("referral",):
            continue
        if not rng.chance(0.62):
            continue
        pool_top = max(1, idx)
        pick_at = int(pool_top * rng.raw.random() ** 2.4)
        row["invited_by"] = rows[pick_at]["id"]
    return rows, bursts


def build_server_rows(rng, rows: list[dict], n: int) -> list[dict]:
    """A handful of servers to join, sized so membership skew is visible.

    Names come from the same corpus as usernames so they look app-generated, and the
    owner is always an existing user. One server in six gets a small capacity so the
    "server full" rejection path is reachable rather than theoretical.
    """
    if n <= 0 or not rows:
        return []
    out: list[dict] = []
    slugs: set[str] = set()
    for _ in range(n * 3):  # oversample, then keep the first N unique slugs
        if len(out) >= n:
            break
        adj = str(rng.pick(corpus.ADJECTIVES)).replace("-", "")
        noun = str(rng.pick(corpus.NOUNS)).replace("-", "")
        slug = f"{adj}-{noun}"[:28]
        if slug in slugs:
            continue
        slugs.add(slug)
        owner = rows[rng.int(0, len(rows) - 1)]
        out.append({
            "name": f"{adj.title()} {noun.title()}", "slug": slug, "created_ts": owner["signup_ts"],
            "owner_id": owner["id"], "capacity": rng.int(3, 40) if rng.chance(1 / 6) else None,
            "private": 1 if rng.chance(0.15) else 0,
        })
    for i, s in enumerate(out, start=1):
        s["id"] = i
    return out


def insert_servers(conn, servers: list[dict]) -> None:
    if not servers:
        return
    conn.execute("BEGIN")
    try:
        conn.executemany(
            "INSERT OR REPLACE INTO servers (id, name, slug, created_ts, owner_id, capacity, private) "
            "VALUES (?,?,?,?,?,?,?)",
            [(s["id"], s["name"], s["slug"], s["created_ts"], s["owner_id"], s["capacity"], s["private"])
             for s in servers],
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def insert_rows(conn, rows: list[dict]) -> None:
    user_sql = f"INSERT INTO users ({', '.join(USER_COLS)}, id) VALUES ({', '.join('?' * (len(USER_COLS) + 1))})"
    for s in range(0, len(rows), BATCH):
        chunk = rows[s: s + BATCH]
        conn.execute("BEGIN")
        for r in chunk:
            conn.execute(user_sql, tuple(r[c] for c in USER_COLS) + (r["id"],))
        conn.executemany(
            "INSERT INTO credentials(user_id, algo, salt, iterations, hash) VALUES(?,?,?,?,?)",
            [(r["id"], r["_algo"], r["_salt"], r["_iter"], r["_hash"]) for r in chunk],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO invite_edges(inviter, invitee, ts) VALUES(?,?,?)",
            [(r["invited_by"], r["id"], r["signup_ts"]) for r in chunk if r["invited_by"]],
        )
        conn.execute("COMMIT")


def insert_events(conn, events: list[dict]) -> None:
    sql = "INSERT INTO events(user_id, ts, kind, weight, ip, meta) VALUES(?,?,?,?,?,?)"
    for s in range(0, len(events), BATCH):
        conn.execute("BEGIN")
        conn.executemany(sql, [(e["user_id"], e["ts"], e["kind"], e["weight"], e["ip"], e["meta"])
                              for e in events[s: s + BATCH]])
        conn.execute("COMMIT")


def insert_sessions(conn, sessions: list[dict]) -> None:
    sql = ("INSERT INTO sessions(user_id, token, ip, ua, device_class, created_ts, last_seen_ts, revoked)"
           " VALUES(?,?,?,?,?,?,?,?)")
    for s in range(0, len(sessions), BATCH):
        conn.execute("BEGIN")
        conn.executemany(sql, [(x["user_id"], x["token"], x["ip"], x["ua"], x["device_class"],
                               x["created_ts"], x["last_seen_ts"], x["revoked"]) for x in sessions[s: s + BATCH]])
        conn.execute("COMMIT")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m seeds.seed", description=__doc__,
                               formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--users", type=int, default=25_000, help="number of accounts to create")
    p.add_argument("--db", default="var/test.db", help="sqlite path (must not be production)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--days", type=int, default=180, help="signup history window")
    p.add_argument("--end", default="now", help="ISO date for the newest signup (default: this hour)")
    p.add_argument("--growth", type=float, default=0.6, help="traffic growth across the window")
    p.add_argument("--burst-count", type=int, default=8, help="launch/spike clusters to inject")
    p.add_argument("--burst-share", type=float, default=0.11, help="fraction of users inside bursts")
    p.add_argument("--inject-bots", type=int, default=600,
                   help="synthetic automated-signup accounts (detection fixtures)")
    p.add_argument("--events", type=float, default=1.0, help="activity volume multiplier")
    p.add_argument("--sessions", type=int, default=6, help="max seeded sessions per active user")
    p.add_argument("--test-password", default="Fixture-Test-Pass-2026!",
                   help="shared password for every fixture account; empty = random per user")
    p.add_argument("--pbkdf2-iterations", type=int, default=1_200,
                   help="KDF cost; set your production value to benchmark hashing")
    p.add_argument("--hash-algo", choices=("pbkdf2_sha256", "sha256_fast"), default="pbkdf2_sha256",
                   help="sha256_fast = throwaway speed for 100k+ account runs")
    p.add_argument("--min-password-length", type=int, default=10)
    p.add_argument("--servers", type=int, default=6,
                   help="shared servers/join targets to create (0 disables)")
    p.add_argument("--no-activity", action="store_true")
    p.add_argument("--fresh", action="store_true", help="wipe rows first (schema stays)")
    p.add_argument("--quiet", action="store_true")
    a = p.parse_args(argv)

    if "prod" in a.db and not a.quiet:
        print("refusing to look like a production target; pass an explicit fixture path", file=sys.stderr)
        return 3

    end = _parse_when(a.end)
    start = end - a.days * 86400
    rng = Rng(a.seed)
    policy = PasswordPolicy(min_length=a.min_password_length)

    conn = connect(a.db)
    migrate(conn)
    if a.fresh:
        reset(conn)
    existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if existing and not a.fresh:
        print(f"{a.db} already has {existing} users; use --fresh to rebuild", file=sys.stderr)
        return 3

    t0 = time.perf_counter()
    rows, bursts = build_user_rows(
        rng, n_users=a.users, window=(start, end), days=a.days, growth=a.growth,
        burst_count=a.burst_count, burst_share=a.burst_share, bots=a.inject_bots,
        policy=policy, password=a.test_password, iterations=a.pbkdf2_iterations, algo=a.hash_algo,
    )
    t_gen = time.perf_counter() - t0

    if rows:
        insert_rows(conn, rows)

    servers = build_server_rows(rng, rows, max(0, a.servers))
    insert_servers(conn, servers)

    n_events = 0
    if not a.no_activity and rows:
        events = generate_activity(rows, rng, max_events=int(900 * a.events))
        events = [e for i, e in enumerate(events) if i % max(1, int(1 / a.events) if a.events < 1 else 1) == 0]
        insert_events(conn, events)
        n_events = len(events)
        sessions = generate_sessions(rows, rng, max_per_user=a.sessions)
        insert_sessions(conn, sessions)
        conn.execute("ANALYZE")
        n_sessions = len(sessions)
    else:
        n_sessions = 0

    params = {
        "users": a.users, "days": a.days, "seed": a.seed, "start": start, "end": end,
        "growth": a.growth, "inject_bots": a.inject_bots, "bursts": len(bursts),
        "events_multiplier": a.events, "pbkdf2_iterations": a.pbkdf2_iterations, "hash_algo": a.hash_algo,
        "shared_password": bool(a.test_password),
    }
    set_meta(conn, "seed_params", json.dumps(params, sort_keys=True))
    set_meta(conn, "fixture_hash", _digest(conn))

    if not a.quiet:
        dt = time.perf_counter() - t0
        print(render(conn, counts=table_counts(conn)))
        print(f"\nwrote {a.db}  signup window "
              f"{datetime.fromtimestamp(start, UTC):%Y-%m-%d} .. "
              f"{datetime.fromtimestamp(end, UTC):%Y-%m-%d} UTC")
        print(f"timing: generate {t_gen:.1f}s  insert {dt:.1f}s  "
              f"events {n_events:,}  sessions {n_sessions:,}")
    conn.close()
    return 0


def _digest(conn) -> str:
    """Canonical hash of the user table, for the determinism test."""
    import hashlib

    h = hashlib.sha256()
    for row in conn.execute(
        "SELECT id, username, email, signup_ts, signup_ip, status, verified_ts, source "
        "FROM users ORDER BY id"
    ):
        h.update(repr(tuple(row)).encode())
    return h.hexdigest()[:16]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
