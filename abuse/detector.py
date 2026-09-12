"""Score fixture accounts for automated-signup signals, then grade the rules
against the ground-truth label the seeder writes.

Read-only view of the problem: what these bulk registrars *leak* (shared /24,
one user agent, digit-walking usernames, sub-10s email verification, zero
activity) is the useful part if you run a service. The seeder injects a labeled
cohort so you can tune thresholds and watch precision/recall move.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

from seeds.corpus import DISPOSABLE_DOMAINS
from seeds.db import connect, migrate
from seeds.text import email_local_part, entropy, ip_prefix24, username_template

BOT_UA = re.compile(
    r"headless|phantomjs|selenium|webdriver|python-requests|curl/|wget/|okhttp|bot/|puppeteer|playwright",
    re.I,
)


RULES: dict[str, float] = {
    "bot_user_agent": 0.45,
    "signup_velocity": 0.40,
    "disposable_email": 0.30,
    "instant_email_verify": 0.25,
    "username_template_cluster": 0.25,
    "referral_fan_in": 0.20,
    "no_phone_disposable": 0.20,
    "low_entropy_local_part": 0.15,
    "no_activity_24h": 0.12,
    "template_shared_subnet": 0.20,
}


class RuleEngine:
    def __init__(self, conn, *, allow_domains: frozenset[str] = frozenset(),
                 velocity_window: int = 120, velocity_min: int = 25,
                 template_min: int = 6, fan_in_min: int = 40, instant_verify_s: int = 10,
                 entropy_floor: float = 2.6, min_rules: int = 1,
                 batch_seconds_per_account: float = 90.0) -> None:
        self.batch_seconds_per_account = batch_seconds_per_account
        # Corroboration floor: one signal is a review queue, two is an action.
        # Real moderation almost always needs the second signal, and it is the
        # cheapest way to buy precision back.
        self.min_rules = max(1, min_rules)
        self.allow_domains = {d.lower() for d in allow_domains}
        self.conn = conn
        self.velocity_window = velocity_window
        self.velocity_min = velocity_min
        self.template_min = template_min
        self.fan_in_min = fan_in_min
        self.instant_verify_s = instant_verify_s
        self.entropy_floor = entropy_floor

    def load(self) -> list[dict]:
        """Allow-listed domains (your own load-test or staging domains) are kept
        out of scoring entirely: leaving them in makes every metric you read a
        lie, and they will always look like abuse."""
        where, args = "", ()
        if self.allow_domains:
            where = f" WHERE lower(email_domain) NOT IN ({','.join('?' * len(self.allow_domains))})"
            args = tuple(sorted(self.allow_domains))
        sql = ("SELECT id, username, email, email_domain, signup_ts, signup_ip, signup_ua, status, "
               "       verified_ts, invited_by, has_phone, is_synthetic_abuse "
               f"FROM users{where} ORDER BY signup_ts")
        rows = self.conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def hits(self, users: list[dict]) -> dict[int, set[str]]:
        """Every rule below returns account ids, never credentials or inboxes."""
        flags: dict[int, set[str]] = defaultdict(set)

        # --- user agent signature
        for u in users:
            if u["signup_ua"] and BOT_UA.search(u["signup_ua"]):
                flags[u["id"]].add("bot_user_agent")

        # --- signups per /24 inside a sliding window
        by_prefix: dict[str, list[dict]] = defaultdict(list)
        for u in users:
            by_prefix[ip_prefix24(u["signup_ip"])].append(u)
        for cluster in by_prefix.values():
            if len(cluster) < self.velocity_min:
                continue
            cluster.sort(key=lambda x: x["signup_ts"])
            stamps = [c["signup_ts"] for c in cluster]
            lo = 0
            in_window = Counter()
            for hi in range(len(stamps)):
                while stamps[hi] - stamps[lo] > self.velocity_window:
                    lo += 1
                if hi - lo + 1 >= self.velocity_min:
                    for j in range(lo, hi + 1):
                        in_window[cluster[j]["id"]] += 1
            for uid in in_window:
                flags[uid].add("signup_velocity")

        # --- shared username templates, but only when they are also *batched*:
        # a common shape alone is weak (plenty of people pick `adjective+noun`),
        # a common shape created minutes apart is a registrar walking a list.
        tmpl: dict[str, list[dict]] = defaultdict(list)
        for u in users:
            tmpl[username_template(u["username"])].append(u)
        for group in tmpl.values():
            if len(group) < self.template_min:
                continue
            stamps = sorted(g["signup_ts"] for g in group)
            span = stamps[-1] - stamps[0]
            seconds_per_account = span / max(1, len(group) - 1)
            if seconds_per_account > self.batch_seconds_per_account:
                continue
            prefixes = {ip_prefix24(g["signup_ip"]) for g in group}
            for g in group:
                flags[g["id"]].add("username_template_cluster")
                if len(prefixes) <= max(2, len(group) // 8):
                    flags[g["id"]].add("template_shared_subnet")

        # --- email domain + local-part shape
        for u in users:
            if (u["email_domain"] or "").lower() in DISPOSABLE_DOMAINS:
                flags[u["id"]].add("disposable_email")
                if not u["has_phone"]:
                    flags[u["id"]].add("no_phone_disposable")
            local = email_local_part(u["email"])
            if len(local) >= 5 and entropy(local) < self.entropy_floor:
                flags[u["id"]].add("low_entropy_local_part")

        # --- instant verification (a human cannot click an inbox link that fast)
        for u in users:
            if u["verified_ts"] is not None and 0 <= u["verified_ts"] - u["signup_ts"] <= self.instant_verify_s:
                flags[u["id"]].add("instant_email_verify")

        # --- invite graph fan-in
        fan = self.conn.execute(
            "SELECT inviter, COUNT(*) c FROM invite_edges GROUP BY inviter HAVING c >= ?",
            (self.fan_in_min,),
        ).fetchall()
        for row in fan:
            invitees = self.conn.execute(
                "SELECT invitee FROM invite_edges WHERE inviter=?", (row["inviter"],)).fetchall()
            for r in invitees:
                flags[r["invitee"]].add("referral_fan_in")
            flags[row["inviter"]].add("referral_fan_in")

        # --- activity gap
        quiet = {r["user_id"] for r in self.conn.execute(
            "SELECT u.id user_id FROM users u WHERE u.status='active' AND u.signup_ts < ? "
            "AND NOT EXISTS (SELECT 1 FROM events e WHERE e.user_id = u.id "
            "                 AND e.ts BETWEEN u.signup_ts AND u.signup_ts + 86400)",
            (int(time.time()) - 86400,),
        )}
        for uid in quiet:
            flags[uid].add("no_activity_24h")
        return flags

    @staticmethod
    def score(rules: set[str]) -> float:
        """Noisy-OR combination: overlapping evidence saturates instead of summing."""
        return 1.0 - math.prod(1.0 - RULES[r] for r in rules) if rules else 0.0

    def persist(self, flags: dict[int, set[str]], threshold: float) -> tuple[int, int]:
        run_ts = int(time.time())
        self.conn.execute("BEGIN")
        self.conn.execute("DELETE FROM flags")
        kept = 0
        total = 0
        rows = []
        for uid, rules in flags.items():
            s = self.score(rules)
            total += 1
            if s < threshold or len(rules) < self.min_rules:
                continue
            kept += 1
            for r in sorted(rules):
                # score = the account's composite risk, repeated per rule row so
                # `SELECT user_id, MAX(score) FROM flags GROUP BY 1` is enough
                # to build a queue; the rule's own weight goes in detail.
                rows.append((uid, r, round(s, 4), f"rule_weight={RULES[r]:.2f}", run_ts))
        self.conn.executemany(
            "INSERT OR REPLACE INTO flags(user_id, rule, score, detail, run_ts) VALUES(?,?,?,?,?)", rows
        )
        self.conn.execute("COMMIT")
        return kept, total


def grade(conn, flagged: set[int]) -> dict[str, float]:
    truth = {r["id"] for r in conn.execute("SELECT id FROM users WHERE is_synthetic_abuse = 1")}
    tp = len(flagged & truth)
    fp = len(flagged - truth)
    fn = len(truth - flagged)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    base_rate = len(truth) / max(1, conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"])
    return {
        "positives": len(truth), "flagged": len(flagged), "true_positives": tp,
        "false_positives": fp, "missed": fn, "precision": precision, "recall": recall,
        "f1": f1, "base_rate": base_rate, "lift": (precision / base_rate if base_rate else 0.0),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m abuse.detector",
                               description="flag likely-automated signups in a fixture database")
    p.add_argument("--db", default="var/test.db")
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--velocity-window", type=int, default=120)
    p.add_argument("--velocity-min", type=int, default=25)
    p.add_argument("--template-min", type=int, default=6)
    p.add_argument("--fan-in-min", type=int, default=40)
    p.add_argument("--instant-verify-s", type=int, default=10)
    p.add_argument("--entropy-floor", type=float, default=2.6)
    p.add_argument("--batch-seconds-per-account", type=float, default=90.0,
                   help="template clusters tighter than this look batch-registered")
    p.add_argument("--allow-domain", action="append", default=[],
                   help="exclude a domain from scoring (repeatable); e.g. loadtest.invalid")
    p.add_argument("--min-rules", type=int, default=1,
                   help="require N corroborating signals before flagging (auto-reviews need 2+)")
    p.add_argument("--export", default="", help="csv path for user_id,score,rules (no PII)")
    p.add_argument("--top", type=int, default=8)
    a = p.parse_args(argv)

    conn = connect(a.db)
    migrate(conn)
    eng = RuleEngine(
        conn,
        allow_domains=frozenset(a.allow_domain),
        velocity_window=a.velocity_window,
        velocity_min=a.velocity_min,
        template_min=a.template_min,
        fan_in_min=a.fan_in_min,
        instant_verify_s=a.instant_verify_s,
        entropy_floor=a.entropy_floor,
        min_rules=a.min_rules,
        batch_seconds_per_account=a.batch_seconds_per_account,
    )
    t0 = time.perf_counter()
    users = eng.load()
    flags = eng.hits(users)
    kept, _total = eng.persist(flags, a.threshold)
    dt = time.perf_counter() - t0

    flagged_ids = {r["user_id"] for r in conn.execute("SELECT DISTINCT user_id FROM flags")}
    g = grade(conn, flagged_ids)

    print("SIGNUP ABUSE DETECTION")
    print("=" * 74)
    skipped = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] - len(users)
    print(f"users scored      {len(users):>8,}" + (f"   ({skipped:,} allow-listed)" if skipped else ""))
    print(f"flagged >= {a.threshold:<2} w/ >={a.min_rules} rule(s)  {kept:>6,}  "
          f"({100 * kept / max(1, len(users)):.1f}% of population)   {dt:.1f}s")
    rule_counts = Counter(r["rule"] for r in conn.execute("SELECT rule FROM flags"))
    print("\nRULE TRIGGERS (within flagged set)")
    for rule, c in rule_counts.most_common(a.top):
        active = sum(1 for u in users if rule in flags.get(u["id"], ()))
        print(f"  {rule:<26}{c:>8,}  {100 * c / max(1, kept):5.1f}% of flagged   "
              f"(fires on {active:,} overall)")
    print("\nGRADE AGAINST FIXTURE GROUND TRUTH (seeder-labeled)")
    print(f"  labeled positives {g['positives']:>8,}   flagged {g['flagged']:,}")
    print(f"  tp {g['true_positives']:,}   fp {g['false_positives']:,}   missed {g['missed']:,}")
    print(f"  precision {g['precision']:.3f}   recall {g['recall']:.3f}   f1 {g['f1']:.3f}   "
          f"lift {g['lift']:.1f}x over a {100 * g['base_rate']:.1f}% base rate")
    hist = [0] * 10
    for rules in flags.values():
        hist[min(9, int(eng.score(rules) * 10))] += 1
    print("\nSCORE HISTOGRAM (all scored accounts, per 0.1 bucket)")
    for i, h in enumerate(hist):
        print(f"  {i / 10:.1f}-{(i + 1) / 10:.1f}  {h:>7,}  {'#' * min(40, int(40 * h / max(1, max(hist))))}")
    if a.export:
        out = Path(a.export)
        out.parent.mkdir(parents=True, exist_ok=True)
        agg: dict[int, tuple[float, list[str]]] = {}
        for r in conn.execute("SELECT user_id, rule, score FROM flags ORDER BY score DESC"):
            cur = agg.setdefault(r["user_id"], (r["score"], []))
            cur[1].append(r["rule"])
        with out.open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["user_id", "score", "rules"])
            for uid, (score, rules) in sorted(agg.items(), key=lambda kv: -kv[1][0]):
                w.writerow([uid, f"{score:.3f}", "|".join(sorted(set(rules)))])
        print(f"\nexported {len(agg):,} rows -> {out}")
    print("=" * 74)
    conn.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
