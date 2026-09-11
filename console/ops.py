"""The console's hands: jobs, the mock API it owns, and the two Operational options.

Nothing here parses HTTP or renders HTML. Two reasons, both load-bearing:

1. the same actions have to be reachable from tests without a browser, and
2. the console is a *control plane over this repo's own CLIs*, so the argv it builds
   is the contract. Keeping it in one module makes "the UI can only do what these
   functions do" checkable by reading one file.

Consequently there is no path anywhere that accepts a URL, a SQL fragment, a shell
string, or a module name from the browser. The load target is always
`Settings.api_url()` (loopback, the API this process started), and seed/export paths
are validated in `console.settings`.
"""

from __future__ import annotations

import contextlib
import io
import itertools
import json
import queue
import sqlite3
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from load.accounts import parse_file
from load.engine import main as load_main
from mockapi.client import ApiClient
from mockapi.server import Config, build_server
from seeds.export import main as export_main
from seeds.seed import main as seed_main

from .settings import Settings

MAX_LOG_LINES = 400


@dataclass
class Job:
    id: int
    kind: str
    state: str = "queued"          # queued | running | done | failed
    started: float = 0.0
    finished: float = 0.0
    code: int = -1
    log: list[str] = field(default_factory=list)
    result: dict = field(default_factory=dict)

    def say(self, line: object) -> None:
        for part in str(line).rstrip("\n").splitlines() or [""]:
            self.log.append(part)
            if len(self.log) > MAX_LOG_LINES:
                del self.log[: len(self.log) - MAX_LOG_LINES]

    def as_dict(self) -> dict:
        seconds = round((self.finished or time.time()) - self.started, 2) if self.started else 0.0
        return {"id": self.id, "kind": self.kind, "state": self.state, "code": self.code,
                "seconds": seconds, "result": self.result, "log_tail": self.log[-40:]}


class Runner:
    """One worker thread on purpose.

    SQLite is single-writer and `seeds.seed --fresh` truncates tables: two generator jobs
    at once produce a corrupt fixture and a confusing error, so serialising the queue is
    a correctness feature, not a limitation to route around.
    """

    def __init__(self) -> None:
        self._q: queue.Queue[Job] = queue.Queue()
        self._lock = threading.Lock()
        self._jobs: dict[int, Job] = {}
        self._ids = itertools.count(1)
        self._fn: dict[int, Callable[[Job], dict]] = {}
        self._thread: threading.Thread | None = None

    def submit(self, kind: str, fn: Callable[[Job], dict]) -> Job:
        with self._lock:
            job = Job(id=next(self._ids), kind=kind)
            self._jobs[job.id] = job
            self._fn[job.id] = fn
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._drain, name="console-jobs", daemon=True)
                self._thread.start()
        self._q.put(job)
        return job

    def busy(self) -> str | None:
        with self._lock:
            for job in self._jobs.values():
                if job.state in ("queued", "running"):
                    return f"{job.kind} #{job.id}"
        return None

    def snapshot(self, limit: int = 12) -> list[dict]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: -j.id)[:limit]
        return [j.as_dict() for j in jobs]

    def _drain(self) -> None:
        while True:
            job = self._q.get()
            fn = self._fn.pop(job.id, None)
            with self._lock:
                job.state, job.started = "running", time.time()
            buf = io.StringIO()
            try:
                if fn is None:  # pragma: no cover - defensive
                    raise RuntimeError("job lost its handler")
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    result = fn(job)
                job.state, job.code = "done", 0
                if isinstance(result, dict):
                    job.code = int(result.get("__code__", 0))
                    job.result = {k: v for k, v in result.items() if k != "__code__"}
                if job.code:
                    job.state = "failed"
            except Exception as exc:  # a job must never take the console down
                job.state, job.code = "failed", 1
                job.result = {"error": f"{type(exc).__name__}: {exc}"}
                job.say(traceback.format_exc(limit=2))
            finally:
                for line in buf.getvalue().splitlines():
                    job.say(line)
                job.finished = time.time()
            self._q.task_done()


# --------------------------------------------------------------------- fixture state
def fixture_status(settings: Settings) -> dict:
    """Everything the tabs need to render, from one read-only connection."""
    out: dict = {"db": settings.db, "exists": False, "tables": {}, "fixture_hash": "",
                 "seed_params": {}, "servers": [], "dumps": []}
    path = Path(settings.db)
    if not path.exists():
        return out
    out["exists"] = True
    conn = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        for table in ("users", "credentials", "sessions", "events", "invite_edges", "flags",
                      "servers", "memberships"):
            try:
                out["tables"][table] = conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"]
            except sqlite3.Error:
                out["tables"][table] = -1  # schema predates this table
        row = conn.execute("SELECT value FROM meta WHERE key='fixture_hash'").fetchone()
        if row:
            out["fixture_hash"] = row["value"]
        row = conn.execute("SELECT value FROM meta WHERE key='seed_params'").fetchone()
        if row:
            with contextlib.suppress(json.JSONDecodeError):
                out["seed_params"] = json.loads(row["value"])
        try:
            out["servers"] = [dict(r) for r in conn.execute(
                "SELECT s.id, s.name, s.slug, s.capacity, s.private, "
                "  (SELECT COUNT(*) FROM memberships m WHERE m.server_id = s.id AND m.left_ts IS NULL) AS members,"
                "  (SELECT COUNT(*) FROM memberships m WHERE m.server_id = s.id AND m.left_ts IS NOT NULL) "
                "    AS departed "
                "FROM servers s ORDER BY s.id LIMIT 50").fetchall()]
        except sqlite3.Error:
            out["servers"] = []
    finally:
        conn.close()
    dumps_dir = Path(settings.accounts_dir)
    dumps = sorted(dumps_dir.glob("accounts-*.txt"), key=lambda p: p.stat().st_mtime, reverse=True) \
        if dumps_dir.exists() else []
    out["dumps"] = [{"path": str(p), "name": p.name, "tokens": _count_dump(p)} for p in dumps[:10]]
    return out


def _count_dump(path: Path) -> int:
    try:
        return len(parse_file(path))
    except OSError:
        return 0


# ------------------------------------------------------------------- mock API control
class ApiControl:
    """Runs `mockapi.server` in a thread of this process, so start/stop is instant and
    there is no orphaned child process when the console exits."""

    def __init__(self) -> None:
        self._httpd = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def status(self, settings: Settings) -> dict:
        base = {"running": self.running, "url": settings.api_url(), "pid": None}
        if not self.running:
            return base
        try:
            client = ApiClient(settings.api_url(), timeout=3.0)
            health, metrics = client.health(), client.metrics()
            client.close()
            data = metrics.data if isinstance(metrics.data, dict) else {}
            base["health"] = health.data if health.ok else {"error": f"http {health.status}"}
            base["metrics"] = {"requests": data.get("requests"), "throttled": data.get("throttled"),
                               "by_status": data.get("by_status"), "routes": data.get("by_route")}
        except Exception as exc:  # the page must still render
            base["error"] = f"{type(exc).__name__}: {exc}"
        return base

    def start(self, settings: Settings, job: Job) -> dict:
        with self._lock:
            if self.running:
                return {"state": "already-running", "url": settings.api_url()}
            if not Path(settings.db).exists():
                raise RuntimeError(f"{settings.db} does not exist — run Generator Mode first")
            # log stays off — the API is hosted in this process, and the Runner redirects
            # stderr per job, so request lines would be filed into whichever job happens to
            # be running. For request-level tracing run `python3 -m mockapi.server --log`.
            cfg = Config(**settings.server_config_kwargs(), log=False)
            self._httpd = build_server(cfg)
            self._thread = threading.Thread(target=self._httpd.serve_forever, name="console-mockapi",
                                            daemon=True)
            self._thread.start()
            job.say(f"mock api listening on {settings.api_url()}  db={settings.db}")
            job.say(f"config: register {cfg.rate_limit_per_min}/min, login {cfg.login_rate_limit_per_min}/min, "
                    f"join {cfg.join_rate_limit_per_min}/min, in-flight {cfg.max_inflight}")
            probe = ApiClient(settings.api_url(), timeout=5.0)
            try:
                health = probe.health()
            finally:
                probe.close()  # the console outlives this job; an unshared client leaks its socket
            return {"state": "started", "url": settings.api_url(), "health": health.data}

    def stop(self, settings: Settings, job: Job) -> dict:
        with self._lock:
            if not self.running:
                return {"state": "not-running"}
            httpd, self._httpd, self._thread = self._httpd, None, None
            httpd.shutdown()
            httpd.server_close()
            job.say("mock api stopped; listening socket closed")
            return {"state": "stopped"}


API = ApiControl()
JOBS = Runner()


def job_start_api(settings: Settings) -> Callable[[Job], dict]:
    return lambda job: API.start(settings, job)


def job_stop_api(settings: Settings) -> Callable[[Job], dict]:
    return lambda job: API.stop(settings, job)


# --------------------------------------------------------------------- job builders
def job_generate(settings: Settings) -> Callable[[Job], dict]:
    def run(job: Job) -> dict:
        argv = settings.base_argv()
        job.say(f"python3 -m seeds.seed {' '.join(argv)}")
        code = seed_main(argv)
        if code:
            job.say(f"seeder exited {code}")
        status = fixture_status(settings)
        return {"__code__": code, "tables": status["tables"], "fixture_hash": status["fixture_hash"],
                "servers": len(status["servers"]), "seed_params": status["seed_params"]}
    return run


def job_export(settings: Settings, tables: str, fmts: str) -> Callable[[Job], dict]:
    allowed_tables = {"users", "credentials", "sessions", "events", "invite_edges", "flags",
                      "servers", "memberships"}

    def run(job: Job) -> dict:
        picked = [t.strip() for t in tables.split(",") if t.strip()]
        bad = [t for t in picked if t not in allowed_tables]
        if bad or not picked:
            raise RuntimeError(f"tables must come from {', '.join(sorted(allowed_tables))}")
        bad_fmt = [f for f in fmts.split(",") if f.strip() and f.strip() not in ("csv", "jsonl")]
        if bad_fmt:
            raise RuntimeError("export formats are csv and jsonl only")
        out_dir = str(Path(settings.accounts_dir).parent / "out")
        argv = ["--db", settings.db, "--out", out_dir, "--tables", ",".join(picked), "--format", fmts]
        job.say(f"python3 -m seeds.export {' '.join(argv)}")
        code = export_main(argv)
        listing = sorted(p.name for p in Path(out_dir).glob("*") if p.is_file())[:12]
        return {"__code__": code, "out": out_dir, "files": listing}
    return run


def job_scan(settings: Settings) -> Callable[[Job], dict]:
    def run(job: Job) -> dict:
        from abuse.detector import main as detect_main

        argv = ["--db", settings.db, "--allow-domain", settings.register_domain,
                "--export", str(Path(settings.accounts_dir) / "flagged.csv")]
        job.say(f"python3 -m abuse.detector {' '.join(argv)}")
        code = detect_main(argv)
        return {"__code__": code, "export": argv[-1]}
    return run


def job_load(settings: Settings, token_file: str) -> Callable[[Job], dict]:
    def run(job: Job) -> dict:
        if not API.running:
            raise RuntimeError("the mock API is not running — start it from the same tab")
        argv = settings.load_argv()
        if token_file:
            path = Path(token_file) if Path(token_file).is_absolute() else Path(settings.accounts_dir) / token_file
            if not path.exists():
                raise RuntimeError(f"no such token file: {token_file}")
            argv += ["--token-file", str(path)]
        job.say(f"python3 -m load.engine {' '.join(argv)}")
        code = load_main(argv)
        reports = sorted(Path(settings.accounts_dir).glob("load-*.md"))
        return {"__code__": code, "report": str(reports[-1]) if reports else "", "exit": code}
    return run


# ------------------------------------------------------- operational: server join
def usable_accounts(settings: Settings, source: str, token_file: str, limit: int) -> list[tuple[int, str]]:
    """(user_id, bearer) pairs to drive joins with.

    `source` is deliberately narrow: a previously dumped token file, or fixture
    accounts through the login path. Tokens from the file are only usable if they
    resolve to a live session *in this fixture*, so a stale or foreign dump cannot
    drive anything.
    """
    if source == "token-file":
        path = Path(token_file)
        if not path.is_absolute():
            path = Path(settings.accounts_dir) / token_file
        if ".." in Path(token_file).parts or not path.exists():
            raise RuntimeError(f"no such token file under {settings.accounts_dir}: {token_file}")
        pairs = parse_file(path)[:limit]
        if not pairs:
            raise RuntimeError(f"{path.name} has no usable 'identity<TAB>token' lines")
        out: list[tuple[int, str]] = []
        conn = sqlite3.connect(f"file:{Path(settings.db).resolve()}?mode=ro", uri=True, timeout=5)
        try:
            for _ident, token in pairs:
                row = conn.execute("SELECT user_id FROM sessions WHERE token=? AND revoked=0", (token,)).fetchone()
                if row is not None:
                    out.append((int(row[0]), token))
        finally:
            conn.close()
        if not out:
            raise RuntimeError("every token in that file is revoked or unknown to this fixture; "
                               "run a load job to mint a fresh dump")
        return out
    if source == "fixture-logins":
        conn = sqlite3.connect(f"file:{Path(settings.db).resolve()}?mode=ro", uri=True, timeout=5)
        try:
            idents = [r[0] for r in conn.execute(
                "SELECT email FROM users WHERE status='active' ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
        finally:
            conn.close()
        out = []
        client = ApiClient(settings.api_url(), timeout=10.0)
        try:
            for email in idents:
                resp = client.login(email, settings.test_password)
                if resp.status != 200 or not isinstance(resp.data, dict) or "token" not in resp.data:
                    continue  # throttled or unknown: the counts must show it, not hide it
                out.append((int(resp.data["user_id"]), resp.data["token"]))
                if len(out) >= limit:
                    break
        finally:
            client.close()
        if not out:
            raise RuntimeError("no fixture login produced a token — login may be throttled, the fixture "
                             "may be empty, or Settings › test_password does not match the password this "
                             "fixture was seeded with")
        return out
    raise RuntimeError(f"unknown account source {source!r}")


def job_join(settings: Settings, server_id: int, source: str, token_file: str, limit: int,
              pacing_ms: float) -> Callable[[Job], dict]:
    """Join `server_id` as each selected account, through the mock API's own route.

    `server_id` addresses a row in `settings.db` — that is the whole difference between
    this and "join a server out there": the console has no field that takes a URL, an
    invite link, or an external identifier of any kind.
    """
    def run(job: Job) -> dict:
        if not API.running:
            raise RuntimeError("the mock API is not running — start it from the same tab")
        accounts = usable_accounts(settings, source, token_file, limit)
        job.say(f"{len(accounts)} account(s) via {source} joining server {server_id}")
        client = ApiClient(settings.api_url(), timeout=10.0)
        counts: dict[str, int] = {}
        joined: list[int] = []
        latencies: list[float] = []
        outcome_labels = {201: "joined", 200: "rejoined", 409: "already-member", 403: "refused",
                          429: "throttled", 404: "no-such-server", 401: "unauthenticated"}
        try:
            for user_id, token in accounts:
                if pacing_ms:
                    time.sleep(pacing_ms / 1000.0)
                resp = client.request("POST", f"/servers/{server_id}/join", {},
                                      extra_headers={"Authorization": f"Bearer {token}"})
                key = outcome_labels.get(resp.status, f"http-{resp.status}")
                counts[key] = counts.get(key, 0) + 1
                latencies.append(resp.ms)
                if key in ("joined", "rejoined"):
                    joined.append(user_id)
                if key in ("refused", "no-such-server", "unauthenticated"):
                    job.say(f"user {user_id}: {key} {str(resp.data)[:90]}")
        finally:
            client.close()
        latencies.sort()
        return {"server_id": server_id, "accounts": len(accounts), "counts": counts,
                "p50_ms": round(latencies[len(latencies) // 2], 2) if latencies else 0.0,
                "max_ms": round(latencies[-1], 2) if latencies else 0.0,
                "joined_user_ids": joined[:500]}
    return run


def job_leave(settings: Settings, server_id: int, user_ids: list[int]) -> Callable[[Job], dict]:
    """Undo a join: the accounts just listed leave again, through the API's own route.

    Deliberately an explicit action over an explicit id list (the ids a join job
    reported), not a scheduler: `left_ts` is a column your app owns, and the console
    does not run membership timing on a timer.
    """
    def run(job: Job) -> dict:
        if not API.running:
            raise RuntimeError("the mock API is not running — start it from the same tab")
        if not user_ids:
            raise RuntimeError("no user ids given: leave acts on the ids a join job reported")
        client = ApiClient(settings.api_url(), timeout=10.0)
        conn = sqlite3.connect(settings.db, timeout=10)
        left = skipped = 0
        try:
            for user_id in user_ids:
                row = conn.execute("SELECT token FROM sessions WHERE user_id=? AND revoked=0 "
                                   "ORDER BY last_seen_ts DESC LIMIT 1", (int(user_id),)).fetchone()
                if row is None:
                    skipped += 1
                    continue
                resp = client.request("POST", f"/servers/{server_id}/leave", {},
                                      extra_headers={"Authorization": f"Bearer {row[0]}"})
                left += 1 if resp.status == 200 else 0
                skipped += 0 if resp.status == 200 else 1
        finally:
            conn.close()
            client.close()
        job.say(f"left {left}, skipped {skipped}")
        return {"server_id": server_id, "left": left, "skipped": skipped}
    return run
