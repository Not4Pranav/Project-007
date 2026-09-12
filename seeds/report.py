from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .corpus import DISPOSABLE_DOMAINS as DISPOSABLE_HINT
from .db import get_meta
from .text import entropy, username_template


def _fmt_ts(ts: int | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M")


def pct(part: float, whole: float) -> str:
    return f"{(100.0 * part / whole):5.1f}%" if whole else "   0%"


def quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    pos = (len(sorted_vals) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def bar(n: float, max_n: float, width: int = 26) -> str:
    if max_n <= 0:
        return ""
    return "#" * max(1, int(width * n / max_n)) if n else ""


def render(conn, counts: dict[str, int] | None = None) -> str:
    counts = counts or {}
    users = counts.get("users") or conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    if not users:
        return "empty database"
    lines: list[str] = []
    add = lines.append

    span = conn.execute("SELECT MIN(signup_ts) a, MAX(signup_ts) b FROM users").fetchone()
    days = max(1, (span["b"] - span["a"]) // 86400 + 1)
    add("SEED REPORT")
    add("=" * 74)
    add(f"{'users':<16}{users:>10,}   {'events':<10}{counts.get('events', 0):>9,}   "
        f"{'sessions':<9}{counts.get('sessions', 0):>8,}")
    add(f"{'credentials':<16}{counts.get('credentials', 0):>10,}   "
        f"{'invites':<10}{counts.get('invite_edges', 0):>9,}   {'flags':<9}{counts.get('flags', 0):>8,}")
    add(f"window        {_fmt_ts(span['a'])} -> {_fmt_ts(span['b'])}  ({days}d, "
        f"{users / days:,.0f} signups/day avg)")

    per_day_avg = conn.execute(
        "SELECT AVG(c) c FROM (SELECT COUNT(*) c FROM users GROUP BY signup_ts/86400)").fetchone()["c"]
    peak_day = conn.execute(
        "SELECT signup_ts/86400 AS d, COUNT(*) c FROM users GROUP BY d ORDER BY c DESC LIMIT 1").fetchone()
    add(f"peak day      {peak_day['c']:,} signups on {_fmt_ts(peak_day['d'] * 86400)[:10]} "
        f"({peak_day['c'] / max(1, per_day_avg):.1f}x the daily average)")

    peak_hour = conn.execute(
        "SELECT signup_ts/3600 AS h, COUNT(*) c FROM users GROUP BY h ORDER BY c DESC LIMIT 1").fetchone()
    add(f"peak hour     {peak_hour['c']:,} at {_fmt_ts(peak_hour['h'] * 3600)} UTC "
        f"(this is what your rate limiter will actually see)")

    add("")
    add("STATUS                                     VERIFICATION DELAY (signup -> verified)")
    for r in conn.execute("SELECT status, COUNT(*) c FROM users GROUP BY status ORDER BY c DESC"):
        add(f"  {r['status']:<28}{r['c']:>8,}  {pct(r['c'], users)}")
    delays = [row["d"] for row in conn.execute(
        "SELECT verified_ts - signup_ts d FROM users WHERE verified_ts IS NOT NULL AND verified_ts >= signup_ts"
    ) if row["d"] is not None]
    delays.sort()
    if delays:
        add(f"  {'p50 / p90 / p99':<28}{quantile(delays, .5):>6.0f}s {quantile(delays, .9):>8.0f}s "
            f"{quantile(delays, .99):>9.0f}s")
        sub = sum(1 for d in delays if d <= 10)
        add(f"  {'verified in <=10s':<28}{sub:>8,}  {pct(sub, users)}   <- automation tell, see abuse.detector")

    add("")
    add("ACQUISITION SOURCE")
    for r in conn.execute("SELECT source, COUNT(*) c FROM users GROUP BY source ORDER BY c DESC"):
        add(f"  {(r['source'] or '-'):<28}{r['c']:>8,}  {pct(r['c'], users)}  {bar(r['c'], users * 0.5)}")

    add("")
    add("DEVICE / PLATFORM")
    for r in conn.execute("SELECT device_class, COUNT(*) c FROM users GROUP BY device_class ORDER BY c DESC"):
        add(f"  {(r['device_class'] or '-'):<28}{r['c']:>8,}  {pct(r['c'], users)}")

    add("")
    add("EMAIL DOMAINS (top 10)")
    doms = conn.execute("SELECT email_domain d, COUNT(*) c FROM users GROUP BY d ORDER BY c DESC LIMIT 10").fetchall()
    for r in doms:
        tag = "  <- disposable" if r["d"] in DISPOSABLE_HINT else ""
        add(f"  {r['d']:<28}{r['c']:>8,}  {pct(r['c'], users)}{tag}")
    disp = conn.execute(
        f"SELECT COUNT(*) c FROM users WHERE email_domain IN ({','.join('?' * len(DISPOSABLE_HINT))})",
        tuple(sorted(DISPOSABLE_HINT))).fetchone()["c"]
    add(f"  {'disposable total':<28}{disp:>8,}  {pct(disp, users)}")

    add("")
    add("COUNTRIES (top 8)")
    for r in conn.execute("SELECT country, COUNT(*) c FROM users GROUP BY country ORDER BY c DESC LIMIT 8"):
        add(f"  {r['country']:<28}{r['c']:>8,}  {pct(r['c'], users)}")

    add("")
    add("WRITE SKEW (per-user event counts) - feeds your pagination benchmarks")
    per_user_desc = [r["c"] for r in conn.execute(
        "SELECT COUNT(*) c FROM events GROUP BY user_id ORDER BY c DESC")]
    if not per_user_desc:
        per_user_desc = [0]
    per_user_asc = sorted(per_user_desc)
    total_events = sum(per_user_desc) or 1
    top5 = sum(per_user_desc[: max(1, len(per_user_desc) // 20)])
    add(f"  users with events {len(per_user_asc):>6,}   mean {total_events / len(per_user_asc):6.1f}   "
        f"p50 {quantile(per_user_asc, .5):.0f}   p90 {quantile(per_user_asc, .9):.0f}   "
        f"p99 {quantile(per_user_asc, .99):.0f}   max {per_user_desc[0]:,}")
    add(f"  top 5% of accounts produce {pct(top5, total_events)} of all writes")

    add("")
    add("LOGIN-PATH DATA")
    fan = [r["c"] for r in conn.execute(
        "SELECT COUNT(*) c FROM invite_edges GROUP BY inviter ORDER BY c DESC")]
    if fan:
        add(f"  invite fan-in: max {fan[0]:,}   accounts with >25 invitees {sum(1 for f in fan if f > 25):,}")
    ua = conn.execute("SELECT COUNT(DISTINCT signup_ua) n FROM users").fetchone()["n"]
    add(f"  distinct signup user agents: {ua:,}")
    templates: dict[str, int] = {}
    for r in conn.execute("SELECT username FROM users"):
        t = username_template(r["username"])
        templates[t] = templates.get(t, 0) + 1
    shared = sum(1 for v in templates.values() if v >= 4)
    add(f"  username templates shared by >=4 accounts: {shared:,} (largest {max(templates.values()):,})")

    params = get_meta(conn, "seed_params")
    if params:
        pj: dict[str, Any] = json.loads(params)
        add("")
        add(f"seed params   {json.dumps(pj, sort_keys=True)}")
        add(f"fixture hash  {get_meta(conn, 'fixture_hash')}")
    add("=" * 74)
    return "\n".join(lines)


def entropy_report(conn, limit: int = 8) -> list[tuple[str, float]]:
    """Mean local-part entropy per domain: cheap way to spot generated mailboxes."""
    by_domain: dict[str, list[float]] = {}
    for r in conn.execute("SELECT substr(email, 1, instr(email, '@') - 1) local, email_domain d FROM users"):
        local = (r["local"] or "").split("+")[0]
        by_domain.setdefault(r["d"], []).append(entropy(local) if local else 0.0)
    out = [(d, sum(v) / len(v)) for d, v in by_domain.items() if len(v) >= 12]
    out.sort(key=lambda x: x[1])
    return out[:limit]

