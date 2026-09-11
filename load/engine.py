"""Concurrency-ramped load engine + SLO gate (stdlib only).

    python -m load.engine --base-url http://127.0.0.1:8000 --scenario mixed \\
        --stages 25,100,250 --stage-seconds 15 \\
        --slo p95_ms=250,error_rate_pct=0.5,min_rps=150

Closed-loop by default (each worker fires as fast as it can), which finds the
target's ceiling. Pass --rps to pace a fixed arrival rate instead, which is the
question "can it hold production traffic". Percentiles for the overall rollup are
computed from pooled samples, never from averaging stage percentiles.
"""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
import statistics
import sys
import threading
import time
from array import array
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mockapi.client import ApiClient

from .scenarios import SCENARIOS, LoadOptions, available

MAX_SAMPLES = 400_000


@dataclass
class Recorder:
    """Thread-safe sample sink: latencies in a dense array, outcomes in counters."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    lat: array = field(default_factory=lambda: array("d"))
    by_kind: Counter = field(default_factory=Counter)
    by_op: dict[str, array] = field(default_factory=lambda: defaultdict(array))

    def add(self, op: str, kind: str, ms: float) -> None:
        with self.lock:
            if len(self.lat) >= MAX_SAMPLES:
                self.dropped += 1
                return
            self.lat.append(ms)
            self.by_kind[kind] += 1
            self.by_op.setdefault(op, array("d")).append(ms)

    dropped: int = 0

    @property
    def total(self) -> int:
        return int(sum(self.by_kind.values()))

    def merge(self, other: Recorder) -> None:
        with self.lock:
            room = MAX_SAMPLES - len(self.lat)
            if room > 0:
                self.lat.extend(other.lat[:room])
            else:
                self.dropped += len(other.lat)
            self.by_kind.update(other.by_kind)
            for op, vals in other.by_op.items():
                self.by_op.setdefault(op, array("d")).extend(vals)


def quantile(vals, q: float) -> float:
    if len(vals) == 0:
        return 0.0
    s = sorted(vals)
    pos = (len(s) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


@dataclass
class Stats:
    label: str
    concurrency: int
    seconds: float
    ops: int
    mean: float
    p50: float
    p90: float
    p95: float
    p99: float
    p999: float
    max: float
    rps: float
    errors: float
    throttled: float
    kinds: dict[str, int]
    per_op: dict[str, dict[str, float]]
    dropped: int = 0

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def summarize(rec: Recorder, *, label: str, concurrency: int, seconds: float,
              throttle_is_error: bool) -> Stats:
    lat = rec.lat
    kinds = dict(rec.by_kind)
    total = max(1, rec.total)
    err_kinds = ["server_error", "transport"] + (["throttled"] if throttle_is_error else [])
    errs = sum(kinds.get(k, 0) for k in err_kinds)
    per_op = {}
    for op, vals in rec.by_op.items():
        per_op[op] = {
            "n": float(len(vals)),
            "p50": round(quantile(vals, 0.5), 2),
            "p95": round(quantile(vals, 0.95), 2),
            "p99": round(quantile(vals, 0.99), 2),
            "max": round(max(vals), 2) if len(vals) else 0.0,
        }
    return Stats(
        label=label,
        concurrency=concurrency,
        seconds=round(seconds, 2),
        ops=rec.total,
        mean=round(statistics.fmean(lat), 2) if len(lat) else 0.0,
        p50=round(quantile(lat, 0.5), 2),
        p90=round(quantile(lat, 0.90), 2),
        p95=round(quantile(lat, 0.95), 2),
        p99=round(quantile(lat, 0.99), 2),
        p999=round(quantile(lat, 0.999), 2),
        max=round(max(lat), 2) if len(lat) else 0.0,
        rps=round(rec.total / max(0.001, seconds), 1),
        errors=round(100.0 * errs / total, 3),
        throttled=round(100.0 * kinds.get("throttled", 0) / total, 3),
        kinds=kinds,
        per_op=per_op,
        dropped=rec.dropped,
    )


def parse_stages(spec: str) -> list[tuple[int, float]]:
    """`25,100,250` or `25:10,100:20,250:30` (concurrency:seconds per stage)."""
    out: list[tuple[int, float]] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        conc, _, secs = part.partition(":")
        out.append((int(conc), float(secs) if secs else 0.0))
    return out or [(10, 0.0)]


def parse_slo(spec: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for chunk in filter(None, spec.replace(" ", "").split(",")):
        k, _, v = chunk.partition("=")
        out[k] = float(v)
    return out


def check_slo(stats: Stats, slo: dict[str, float]) -> list[str]:
    breaches: list[str] = []
    for key, limit in slo.items():
        if key.endswith("_ms"):
            actual = getattr(stats, key[:-3], None)
            if actual is not None and actual > limit:
                breaches.append(f"{key}: {actual:.1f} > {limit:.1f}")
        elif key == "error_rate_pct" and stats.errors > limit:
            breaches.append(f"error_rate_pct: {stats.errors:.3f} > {limit:.3f}")
        elif key == "throttle_pct" and stats.throttled > limit:
            breaches.append(f"throttle_pct: {stats.throttled:.3f} > {limit:.3f}")
        elif key == "min_rps" and stats.rps < limit:
            breaches.append(f"min_rps: {stats.rps:.1f} < {limit:.1f}")
    return breaches


def identifier_pool(args) -> tuple[list[str], str]:
    """Where the login path gets accounts: read the fixture DB directly, or ask
    the target for a sample if it exposes that endpoint."""
    if args.fixture_db:
        uri = f"file:{Path(args.fixture_db).expanduser().resolve()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=10)  # read-only: never mutate a fixture mid-run
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT email FROM users WHERE status='active' ORDER BY RANDOM() LIMIT ?", (args.identifier_pool,)
        ).fetchall()
        conn.close()
        if rows:
            return [r["email"] for r in rows], f"fixture db ({args.fixture_db})"
    resp = ApiClient(args.base_url).sample_identifiers(args.identifier_pool)
    if resp.ok and isinstance(resp.data, dict):
        return list(resp.data.get("identifiers") or []), "GET /auth/sample-identifiers"
    return [], "unavailable"


def run_stage(client: ApiClient, scenario, opts: LoadOptions, *, concurrency: int, seconds: float,
              rps: float, think_ms: float, seed: int, label: str) -> tuple[Stats, Recorder]:
    """`rps` is the total for the stage; each worker paces to its share.

    0 keeps it closed-loop. A saturated closed-loop run reports throughput your
    target cannot sustain, which is why both modes exist.
    """
    rec = Recorder()
    stop_at = time.monotonic() + seconds
    barrier = threading.Barrier(concurrency + 1)
    per_worker = (concurrency / rps) if rps > 0 else 0.0
    problems: list[str] = []

    def worker(idx: int) -> None:
        ctx = {"rnd": random.Random(seed * 1_000_003 + idx), "token": None, "cursor": None}
        next_due = time.monotonic()
        try:
            barrier.wait(timeout=60)
        except threading.BrokenBarrierError:
            problems.append("worker could not sync with the others")
            return
        while time.monotonic() < stop_at:
            if per_worker:
                now = time.monotonic()
                if now < next_due:
                    time.sleep(min(0.002, next_due - now))
                    continue
                next_due += per_worker
            try:
                kind, ms, op = scenario.run(client, ctx, opts)
            except Exception as exc:
                kind, ms, op = "transport", 0.0, scenario.name
                if len(problems) < 5:
                    problems.append(f"{type(exc).__name__}: {exc}")
            rec.add(op, kind, ms)
            if think_ms:
                time.sleep(think_ms / 1000.0)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True, name=f"load-{label}-{i}")
               for i in range(concurrency)]
    for t in threads:
        t.start()
    barrier.wait(timeout=60)  # everything armed; now start the clock
    started = time.perf_counter()
    for t in threads:
        t.join(timeout=max(10.0, seconds + 60.0))
    stats = summarize(rec, label=label, concurrency=concurrency,
                      seconds=max(0.001, time.perf_counter() - started),
                      throttle_is_error=opts.count_throttled_as_error)
    if problems:
        stats.kinds["scenario_bug"] = len(problems)
        stats.per_op["scenario_bug"] = {"n": float(len(problems)), "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
        print(f"  [{label}] scenario raised {len(problems)}x, e.g. {problems[0]}", file=sys.stderr)
    return stats, rec


def write_report(out_dir: Path, payload: dict) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    jp, mp = out_dir / f"load-{stamp}.json", out_dir / f"load-{stamp}.md"
    jp.write_text(json.dumps(payload, indent=2, sort_keys=True))

    lines = [
        f"# load report {stamp}", "",
        f"- target `{payload['base_url']}` — scenario `{payload['scenario']}` "
        f"(mix `{json.dumps(payload['mix'])}`)",
        f"- {payload['pacing']}; warmup {payload['warmup_seconds']}s per stage excluded from stats",
        f"- login identities: {payload['identifiers']:,} from {payload['identifier_source']}",
        f"- source IPs: {payload.get('ip_pool') or 'all workers share the test host'}",
        "",
        "| stage | conc | ops | rps | mean | p50 | p95 | p99 | max | err% | 429% |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for s in payload["stages"]:
        lines.append(f"| {s['label']} | {s['concurrency']} | {s['ops']:,} | {s['rps']:.0f} | {s['mean']:.1f} "
                     f"| {s['p50']:.1f} | {s['p95']:.1f} | {s['p99']:.1f} | {s['max']:.1f} | {s['errors']:.2f} "
                     f"| {s['throttled']:.2f} |")
    lines += ["", "## per-op latency (ms)", "", "| stage | op | n | p50 | p95 | p99 | max |",
              "|---|---|---:|---:|---:|---:|---:|"]
    for s in payload["stages"]:
        for op, d in sorted(s["per_op"].items()):
            if op.startswith("__"):
                continue
            lines.append(f"| {s['label']} | {op} | {int(d['n']):,} | {d['p50']:.1f} | {d['p95']:.1f} "
                         f"| {d['p99']:.1f} | {d['max']:.1f} |")
    lines += ["", "## outcome mix", ""]
    for s in payload["stages"]:
        mix = ", ".join(f"{k} {v:,}" for k, v in sorted(s["kinds"].items(), key=lambda kv: -kv[1]) if v)
        lines.append(f"- **{s['label']}** (conc {s['concurrency']}): {mix or 'none'}")
    if payload.get("server_metrics"):
        lines += ["", "## server-side metrics (what the target saw)", "", "```json",
                  json.dumps(payload["server_metrics"], indent=2)[:3000], "```"]
    lines += ["", f"- SLO `{payload['slo_spec'] or 'none'}` on `{payload['slo_scope']}` stage: "
              f"**{payload['slo_result']}**{' — ' + '; '.join(payload['slo_breaches']) if payload['slo_breaches'] else ''}",
              f"- overall: {payload['overall']['ops']:,} ops, p95 {payload['overall']['p95']:.1f} ms, "
              f"p99 {payload['overall']['p99']:.1f} ms, errors {payload['overall']['errors']:.2f}%", ""]
    mp.write_text("\n".join(lines))
    return mp, jp


def main(argv: list[str] | None = None) -> int:
    from .scenarios import LoadOptions as _LO

    p = argparse.ArgumentParser(prog="python -m load.engine", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--scenario", default="mixed", choices=available())
    p.add_argument("--mix", default="register=4,login=40,feed=45,post=11", help="weights for --scenario mixed")
    p.add_argument("--stages", default="25,100,250", help="concurrency levels, or conc:seconds")
    p.add_argument("--stage-seconds", type=float, default=15.0)
    p.add_argument("--warmup-seconds", type=float, default=3.0)
    p.add_argument("--rps", type=float, default=0.0, help="total arrival rate; 0 = closed loop")
    p.add_argument("--think-ms", type=float, default=0.0, help="per-iteration idle time")
    p.add_argument("--password", default="Fixture-Test-Pass-2026!", help="shared fixture password")
    p.add_argument("--fixture-db", default="", help="pull login identifiers straight from the fixture DB")
    p.add_argument("--identifier-pool", type=int, default=2000)
    p.add_argument("--register-domain", default="loadtest.invalid",
                   help="reserved domain so generated signups can never reach a real mailbox")
    p.add_argument("--verify-first", action="store_true", help="also POST /auth/verify after registering")
    p.add_argument("--ip-pool", type=int, default=0,
                   help="give each worker its own TEST-NET source IP (per-IP limits then scale)")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--slo", default="", help="e.g. p95_ms=250,error_rate_pct=0.5,min_rps=150")
    p.add_argument("--slo-scope", choices=["final", "overall"], default="final")
    p.add_argument("--out", default="var/reports")
    p.add_argument("--count-throttled-as-error", action="store_true")
    a = p.parse_args(argv)

    if not a.register_domain.endswith((".invalid", ".test", ".example")):
        print("generated signup domains must be reserved (.invalid/.test/.example) so they can never "
              "reach a real mailbox", file=sys.stderr)
        return 5

    client = ApiClient(a.base_url, ip_pool=a.ip_pool)
    health = client.health()
    if not health.ok:
        print(f"target unreachable at {a.base_url}: status={health.status} {health.data}", file=sys.stderr)
        print("  start it with:  python -m mockapi.server --db var/test.db", file=sys.stderr)
        return 2

    idents, ident_source = identifier_pool(a)
    if a.scenario in ("login", "mixed", "post") and not idents:
        print("no identifiers for the login path; pass --fixture-db var/test.db (or seed the target)",
              file=sys.stderr)
        return 2

    mix: dict[str, float] = {}
    for chunk in filter(None, a.mix.replace(" ", "").split(",")):
        k, _, v = chunk.partition("=")
        if k not in SCENARIOS:
            print(f"unknown scenario in --mix: {k} (have {', '.join(available())})", file=sys.stderr)
            return 2
        mix[k] = float(v)

    opts = _LO(password=a.password, identifiers=idents, register_domain=a.register_domain,
               verify_first=a.verify_first, count_throttled_as_error=a.count_throttled_as_error,
               mix_weights=mix)
    scenario = SCENARIOS[a.scenario]
    stages = parse_stages(a.stages)
    slo = parse_slo(a.slo)

    print(f"target      {a.base_url}   scenario={a.scenario}   identifiers={len(idents):,} ({ident_source})")
    print(f"stages      {[c for c, _ in stages]} x {a.stage_seconds}s "
          f"(warmup {a.warmup_seconds}s excluded)   pacing={'closed loop' if not a.rps else f'{a.rps:.0f} rps total'}")
    print()
    head = (f"{'stage':>8} {'conc':>5} {'ops':>9} {'rps':>7} {'mean':>7} {'p50':>7} {'p95':>8} "
            f"{'p99':>9} {'max':>9} {'err%':>6} {'429%':>6}")
    print(head)
    print("-" * len(head))

    stage_stats: list[Stats] = []
    pooled = Recorder()
    for i, (conc, secs_override) in enumerate(stages, 1):
        label = f"s{i}"
        seconds = secs_override or a.stage_seconds
        if a.warmup_seconds > 0:
            run_stage(client, scenario, opts, concurrency=conc, seconds=a.warmup_seconds,
                      rps=(a.rps / max(1, len(stages))) if a.rps else 0.0, think_ms=a.think_ms,
                      seed=a.seed + 100 * i, label=f"{label}w")
        stats, rec = run_stage(client, scenario, opts, concurrency=conc, seconds=seconds,
                               rps=(a.rps / max(1, len(stages))) if a.rps else 0.0, think_ms=a.think_ms,
                               seed=a.seed + 100 * i, label=label)
        stage_stats.append(stats)
        pooled.merge(rec)
        print(f"{label:>8} {conc:>5} {stats.ops:>9,} {stats.rps:>7.0f} {stats.mean:>7.1f} {stats.p50:>7.1f} "
              f"{stats.p95:>8.1f} {stats.p99:>9.1f} {stats.max:>9.1f} {stats.errors:>6.2f} {stats.throttled:>6.2f}")
        kinds = ", ".join(f"{k} {v:,}" for k, v in sorted(stats.kinds.items(), key=lambda kv: -kv[1]) if v)
        print(f"{'':>8} {kinds}")
        if stats.dropped:
            print(f"{'':>8} (sample cap reached; {stats.dropped:,} observations not kept)")

    overall = summarize(pooled, label="overall", concurrency=max(s.concurrency for s in stage_stats),
                        seconds=sum(s.seconds for s in stage_stats), throttle_is_error=a.count_throttled_as_error)
    target_stats = overall if a.slo_scope == "overall" else stage_stats[-1]
    breaches = check_slo(target_stats, slo) if slo else []
    server = client.metrics().data
    payload = {
        "base_url": a.base_url, "scenario": a.scenario, "mix": mix,
        "stages": [s.as_dict() for s in stage_stats], "overall": overall.as_dict(),
        "stage_seconds": a.stage_seconds, "warmup_seconds": a.warmup_seconds,
        "identifier_source": ident_source, "identifiers": len(idents),
        "pacing": "closed-loop (max throughput)" if not a.rps else f"open-loop {a.rps} rps",
        "ip_pool": a.ip_pool,
        "slo_spec": a.slo, "slo": slo, "slo_scope": a.slo_scope,
        "slo_result": ("pass" if not breaches else "fail") if slo else "not checked",
        "slo_breaches": breaches,
        "server_metrics": server if isinstance(server, dict) else None,
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    mp, jp = write_report(Path(a.out), payload)
    print()
    print(f"report      {mp}")
    print(f"raw         {jp}")
    if slo:
        print(f"slo         {a.slo_scope}: {'PASS' if not breaches else 'FAIL -> ' + '; '.join(breaches)}")
    return 4 if breaches else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
