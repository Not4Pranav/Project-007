"""The console's hands: jobs, the mock API it owns, and the two Operational options.

Nothing here parses HTTP or renders HTML. Two reasons, both load-bearing:

1. the same actions have to be reachable from tests without a browser, and
2. the console is a *control plane over this repo's own CLIs*, so the argv it builds
   is the contract. Keeping it in one module makes "the UI can only do what these
   functions do" checkable by reading one file.

Consequently there is no path anywhere that takes a SQL fragment, a shell string, or a
module name from the browser, and the request target is always `Settings.api_url()`
(loopback, the API this process started) — seed/export paths are validated in
`console.settings`. The one URL-*shaped* input is Option B's room field, and it is parsed
as a name to look up in your own `servers` table: a host that is not this loopback API is
refused before the lookup, because there is no other target for a job here to reach.
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
from urllib.parse import unquote, urlsplit

from load.accounts import parse_file
from load.engine import main as load_main
from mockapi.client import ApiClient
from mockapi.server import Config, build_server
from seeds import roster as roster_mod
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
    out["roster"] = roster_status(settings, conn=None)
    dumps_dir = Path(settings.accounts_dir)
    dumps = sorted(dumps_dir.glob("accounts-*.txt"), key=lambda p: p.stat().st_mtime, reverse=True) \
        if dumps_dir.exists() else []
    protected = protected_names(settings)
    out["dumps"] = [{"path": str(p), "name": p.name, "tokens": _count_dump(p)}
                    for p in dumps[:10] if p.name not in protected]
    return out


def protected_names(settings: Settings) -> set[str]:
    """Names that live in `accounts_dir` but are not run dumps: the account list itself and
    its two plaintext exports.

    They sit in the same scratch directory (`var/`) and they match `accounts-*.txt`, so the
    dumps table, the dump reader and the revoke action would all happily offer a
    `user:pass` file. That is wrong twice over: the table is a list of token dumps, and
    `--revoke` on a password file is a no-op that looks like a success. Refuse them by name
    in each of those three places rather than trusting the UI to hide them.
    """
    try:
        return {Path(settings.account_list).name,
                *[roster_export_path(settings, kind).name for kind in ("userpass", "token")]}
    except (OSError, ValueError):  # settings we cannot read are not a licence to serve secrets
        return set()


def roster_status(settings: Settings, *, conn: sqlite3.Connection | None) -> dict:
    """The account list the operator edits, compared against the fixture.

    The file is a *selection*, not a copy: it says which fixture accounts the Operational
    tab may use. So the honest status is "file lists N, fixture has M, K are not listed" —
    and the unlisted ones are what a Sync would delete, which is why the number is on the
    page before any button is clicked.
    """
    path = Path(settings.account_list)
    own = conn is None
    handle = conn or sqlite3.connect(f"file:{Path(settings.db).resolve()}?mode=ro", uri=True, timeout=5)
    try:
        in_fixture = roster_mod.fixture_identities(handle)
    except sqlite3.Error:
        in_fixture = []
    finally:
        if own:
            handle.close()
    out: dict = {"path": str(path), "exists": path.exists(), "listed": 0, "in_fixture": len(in_fixture),
                 "unlisted": [], "unknown": [], "duplicates": []}
    if not path.exists():
        out["unlisted"] = in_fixture[:20]
        return out
    try:
        read = roster_mod.read_roster(path)
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    out["listed"] = len(read.identities)
    out["duplicates"] = read.duplicates[:10]
    listed = {i.lower() for i in read.identities}
    in_fixture_lower = {i.lower() for i in in_fixture}
    # names in the file that are not in the fixture (typos, or synced away) and the other
    # way round (accounts the file does not list yet) — the two directions of drift, apart
    out["unknown"] = [i for i in read.identities if i.lower() not in in_fixture_lower][:20]
    drift = [i for i in in_fixture if i.lower() not in listed]
    out["unlisted_count"] = len(drift)
    out["unlisted"] = drift[:20]
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
        before = 0
        if Path(settings.db).exists():
            probe = sqlite3.connect(settings.db)
            try:
                before = int(probe.execute("SELECT COALESCE(MAX(id), 0) FROM users").fetchone()[0])
            finally:
                probe.close()
        code = seed_main(argv)
        if code:
            job.say(f"seeder exited {code}")
        roster_info: dict = {}
        if not code:
            roster_info = _sync_roster_after_generate(settings, job, after_id=before)
        status = fixture_status(settings)
        # merged into the return value, not job.result: the Runner assigns the result after
        # the job returns, so anything written to job.result mid-flight would be dropped
        return {"__code__": code, "tables": status["tables"], "fixture_hash": status["fixture_hash"],
                "servers": len(status["servers"]), "seed_params": status["seed_params"], **roster_info}
    return run


def _sync_roster_after_generate(settings: Settings, job: Job, *, after_id: int) -> dict:
    """Add exactly the accounts this run created to the roster file.

    Two modes, because a generate click means two different things. In append mode only ids
    greater than `after_id` are new, so a batch somebody deleted from the file but has not
    synced yet is not resurrected by an unrelated click. In replace mode the seeder truncated
    the table and re-numbered it, which invalidates every name the file held — so the file is
    rewritten from the fixture instead of appended to, and cannot be left pointing at accounts
    that no longer exist (which would show up as `unknown` here and as a refused join later).

    Inactive accounts are included on purpose: the list mirrors the fixture, and Sync deletes
    what the list omits (see `seeds.roster.fixture_identities`).
    """
    path = Path(settings.account_list)
    rebuild = settings.write_mode == "replace"
    conn = sqlite3.connect(settings.db)
    try:
        if rebuild:
            new_names = roster_mod.fixture_identities(conn)
        else:
            new_names = [r[0] for r in conn.execute(
                "SELECT username FROM users WHERE id > ? ORDER BY id", (after_id,))]
        current: list[str] = []
        if path.exists() and not rebuild:
            with contextlib.suppress(OSError):
                current = roster_mod.read_roster(path).identities
    finally:
        conn.close()
    merged = list(dict.fromkeys([*current, *new_names]))
    written = roster_mod.write_roster(path, merged)
    job.say(f"roster {path.name}: "
            + (f"rewritten from the rebuilt fixture, {written} listed" if rebuild
               else f"{len(new_names)} new, {written} listed in total"))
    return {"roster": str(path), "roster_added": len(new_names), "roster_total": written}


def job_roster(settings: Settings, action: str) -> Callable[[Job], dict]:
    """preview | sync | rewrite | seed — the account list, and the only destructive pair.

    `sync` deletes fixture accounts the file does not list. It is offered as a preview
    first for that reason: a hand-edited text file should not be able to wipe a fixture
    through a mis-click.
    """
    def run(job: Job) -> dict:
        path = Path(settings.account_list)
        if action == "rewrite":
            conn = sqlite3.connect(settings.db)
            try:
                names = roster_mod.fixture_identities(conn)
            finally:
                conn.close()
            written = roster_mod.write_roster(path, names)
            job.say(f"roster rewritten from the fixture: {written} accounts")
            return {"written": written, "path": str(path)}
        if action == "seed":
            # first-run setup: hand the newest N fixture accounts to the file, so the tool
            # opens with a usable list instead of an empty one
            conn = sqlite3.connect(settings.db)
            try:
                # newest N whatever their status: the list mirrors the fixture (see
                # fixture_identities), and an account that cannot log in is refused at join
                # time instead of being quietly left out of the file
                names = [r[0] for r in conn.execute(
                    "SELECT username FROM users ORDER BY id DESC LIMIT ?",
                    (max(1, settings.bootstrap_accounts),))]
            finally:
                conn.close()
            existing = roster_mod.read_roster(path).identities if path.exists() else []
            merged = list(dict.fromkeys([*names, *existing]))
            written = roster_mod.write_roster(path, merged)
            job.say(f"roster seeded with {len(names)} account(s): {written} listed")
            return {"written": written, "path": str(path), "seeded": len(names)}
        if not path.exists():
            raise RuntimeError(f"{path} does not exist — use Rewrite from fixture to create it")
        listed = roster_mod.read_roster(path).identities
        conn = sqlite3.connect(settings.db)
        try:
            result = roster_mod.sync(conn, listed, apply=(action == "sync"))
            conn.commit()
        finally:
            conn.close()
        if action == "sync":
            job.say(f"removed {result.get('deleted', 0)} account(s); "
                    f"kept {result['kept']}  children={json.dumps(result.get('children', {}))}")
        else:
            job.say(f"preview: {result['would_delete']} account(s) would be removed, "
                    f"{result['kept']} kept")
        result["action"] = action
        return result

    return run


def job_accounts_info(settings: Settings, kind: str, limit: int, use_roster: bool) -> Callable[[Job], dict]:
    """Write `user:pass` or `user:token` for the roster (or for the whole fixture).

    Both kinds are plaintext on purpose — that is what was asked for — so the file lands
    next to the roster at 0600, the job reports its path, and *Revoke*/**delete** stay one
    click away in Settings. `user:pass` is the fixture's shared password; `user:token` is
    a live session of the local mock API. Neither is a credential for any other service.
    """
    def run(job: Job) -> dict:
        path = Path(settings.account_list)
        listed = roster_mod.read_roster(path).identities if (use_roster and path.exists()) else None
        if use_roster and not listed:
            raise RuntimeError(f"{path} lists no accounts to export — Generate adds them, "
                               f"or Settings > Seed the list from the newest fixture accounts")
        conn = sqlite3.connect(settings.db)
        try:
            rows = roster_mod.rows_for_export(conn, listed, password=settings.test_password, limit=limit)
            unknown = []
            if listed is not None:
                # Two different reasons a listed line yields nothing, measured apart: a name no
                # fixture row has is a stale or hand-edited file, a name with a row is an account
                # whose own status gets it refused. Reported as one number, the first sends
                # somebody hunting for a verification state that does not exist.
                have = {i.lower() for i in roster_mod.fixture_identities(conn)}
                unknown = [i for i in listed if i.lower() not in have]
        finally:
            conn.close()
        if not rows:
            raise RuntimeError("nothing to export: no active fixture accounts in that selection"
                               + (f" — and {len(unknown)} of the {len(listed)} listed names match no "
                                  f"fixture account at all, so that file is stale: Settings > "
                                  f"Rewrite file from fixture, or Sync to drop them" if unknown else ""))
        stem = Path(settings.account_list).with_suffix("")
        out = Path(str(stem) + ("-tokens.txt" if kind == "token" else "-userpass.txt"))
        report = roster_mod.write_export(out, kind, rows)
        if listed is not None and len(listed) > len(rows):
            # rows_for_export only hands back accounts that can authenticate, so a file
            # shorter than the roster is expected — say so instead of letting the difference
            # read as a bug, and say which of the two reasons it is
            known = len(listed) - len(unknown)
            report["skipped_unknown"] = len(unknown)
            if unknown:
                job.say(f"{len(unknown)} listed line(s) match no fixture account at all (e.g. "
                        f"{', '.join(unknown[:3])}) — a stale or hand-edited list, not an account "
                        f"to fix: Settings > Rewrite file from fixture, or Sync to drop them")
            if not limit:  # with a cap set, the un-written ones are the cap's doing, not a status
                report["skipped_inactive"] = max(0, known - len(rows))
                if report["skipped_inactive"]:
                    job.say(f"{report['skipped_inactive']} listed account(s) are not active "
                            f"(pending verification or banned), so there is no credential to "
                            f"write for them")
            elif limit:
                job.say(f"the max-lines cap ({limit}) stopped the export, so further accounts "
                        f"were neither written nor skipped for a reason")
        job.say(f"{kind}: {report['written']} line(s) -> {report['path']}"
                + (f"  ({report['skipped_no_session']} skipped: no live session)"
                   if report["skipped_no_session"] else ""))
        if kind == "token" and report["skipped_no_session"]:
            job.say("accounts with no live session: start the API and run a load pass, "
                    "or use the user:pass export")
        report["selection"] = "roster" if listed else "whole fixture"
        return report

    return run


def roster_export_path(settings: Settings, which: str) -> Path:
    """Where an accounts-info export lands: next to the roster, with a name that says what it is."""
    stem = Path(settings.account_list).with_suffix("")
    return Path(str(stem) + ("-tokens.txt" if which == "token" else "-userpass.txt"))


def job_roster_revoke(settings: Settings, which: str) -> Callable[[Job], dict]:
    """Clean up an accounts-info export: revoke the sessions, then remove the plaintext.

    Tokens go first — an unreadable file is worthless, a readable file with live tokens is
    the risk. A `user:pass` export has nothing to revoke (the fixture's password is shared
    and not rotatable here), so removing the file *is* the whole action, and the account
    itself stays in the fixture until the roster says otherwise.
    """
    def run(job: Job) -> dict:
        path = roster_export_path(settings, which)
        if not path.exists():
            raise RuntimeError(f"{path} was never written — use Option A's Write the file first")
        report: dict = {"path": str(path)}
        if which == "token":
            import contextlib
            import io

            from load.accounts import main as accounts_main

            args = ["--revoke", str(path), "--db", settings.db, "--delete"]
            with contextlib.redirect_stdout(io.StringIO()) as cap, contextlib.redirect_stderr(io.StringIO()):
                code = accounts_main(args)
            report["output"] = cap.getvalue().strip() or f"exit {code}"
            report["code"] = code
            job.say(report["output"])
        else:
            path.unlink()
            report["output"] = f"removed {path.name} (no sessions to revoke: it held passwords)"
            job.say(report["output"])
        return report

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
    if source == "roster":
        path = Path(settings.account_list)
        if not path.exists():
            raise RuntimeError(f"{path} does not exist — Generator Mode writes it, or use "
                               f"Settings > Seed the list from the newest fixture accounts")
        names = roster_mod.read_roster(path).identities[:limit]
        if not names:
            raise RuntimeError(f"{path} is empty: nothing to drive")
        conn = sqlite3.connect(f"file:{Path(settings.db).resolve()}?mode=ro", uri=True, timeout=5)
        try:
            idents = roster_mod.resolve(conn, names)
        finally:
            conn.close()
        out = []
        client = ApiClient(settings.api_url(), timeout=10.0)
        try:
            for identity in idents:  # names the fixture does not know were already dropped
                resp = client.login(identity, settings.test_password)
                if resp.status != 200 or not isinstance(resp.data, dict) or "token" not in resp.data:
                    continue  # unknown name, or a login the fixture's rules refused
                out.append((int(resp.data["user_id"]), resp.data["token"]))
                if len(out) >= limit:
                    break
        finally:
            client.close()
        if not out:
            raise RuntimeError(f"none of the {len(names)} name(s) in {path.name} could log in — "
                               f"check Settings > test_password matches this fixture")
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


LOCAL_LINK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def resolve_server(settings: Settings, text: str) -> dict:
    """Turn whatever the operator typed for the target room into a row of *their own* fixture.

    Accepted, all local: a numeric id, the room's `slug`, its name, or a link to the room as
    this fixture would print it (`http://127.0.0.1:8000/servers/amber-lantern`, `/servers/7`,
    even a bare `amber-lantern`). The candidate is looked up in `settings.db`'s `servers`
    table and nothing else — so this names a room you operate, and cannot name one you do
    not. A link whose host is not the loopback API the console talks to is refused *before*
    the lookup, because the lookup would be a lie about where the job is going: there is no
    outbound target in this tool to point at.
    """
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("no room named: put an id, a slug, a name, or the fixture's own link in it")
    candidate = raw
    matched_by = "text"
    if "://" in raw:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        if host not in LOCAL_LINK_HOSTS:
            raise ValueError(
                f"that link points at {host or '?'} — this console only joins rooms of its own "
                f"fixture, reached at {settings.api_url()}; a room somebody else operates is "
                f"not something this tool drives, at any port and in any form")
        if parts.port is not None and parts.port != settings.api_port:
            raise ValueError(f"that link names port {parts.port}, but the fixture's API is on "
                             f"{settings.api_port}; the job would not reach the room you pasted")
        segments = [s for s in parts.path.split("/") if s]
        matched_by = "link"
    elif "/" in raw:
        segments = [s for s in raw.split("/") if s]
        matched_by = "link"
    else:
        segments = []
    if segments:
        candidate = unquote(segments[-1]).strip()
    if not candidate:
        raise ValueError(f"no room id or slug in {raw!r}")

    conn = sqlite3.connect(f"file:{Path(settings.db).resolve()}?mode=ro", uri=True, timeout=5)
    try:
        # -1 rather than a CAST of the text: a non-numeric candidate must not match row 0 by
        # accident, and ids start at 1
        rows = conn.execute(
            "SELECT id, name, slug, capacity, private FROM servers "
            " WHERE slug = ? COLLATE NOCASE OR lower(name) = ? OR id = ?",
            (candidate, candidate.lower(), int(candidate) if candidate.isdigit() else -1)).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"cannot read the server list from {settings.db}: {exc}") from exc
    finally:
        conn.close()
    if not rows:
        raise ValueError(f"no room matching {candidate!r} in {settings.db}: the fixture's own "
                         f"servers are the only ones this can drive — the picker beside this "
                         f"field lists them")
    by_id = [r for r in rows if candidate.isdigit() and int(r[0]) == int(candidate)]
    by_slug = [r for r in rows if str(r[2]).lower() == candidate.lower()]
    picked = (by_id or by_slug or list(rows))[0]
    if len(rows) > 1 and not by_id and not by_slug:
        raise ValueError(f"{candidate!r} matches {len(rows)} rooms (ids "
                         f"{', '.join(str(r[0]) for r in rows[:6])}): use the id or the slug")
    how = "id" if by_id else ("slug" if by_slug else "name")
    return {"server_id": int(picked[0]), "name": picked[1], "slug": picked[2], "capacity": picked[3],
            "private": bool(picked[4]), "matched_by": f"link->{how}" if matched_by == "link" else how,
            "candidates": len(rows)}


def job_join(settings: Settings, server_id: int, source: str, token_file: str, limit: int,
              pacing_ms: float, invite: str = "") -> Callable[[Job], dict]:
    """Join `server_id` as each selected account, through the mock API's own route.

    `server_id` addresses a row in `settings.db`, which is the whole difference between this
    and "join a server out there": the identifier is looked up in the fixture you operate, and
    the request goes to the fixed loopback URL — there is no field anywhere that reaches a
    host this tool does not run. `invite` is that row's own code, for the fixture's private
    gate; it is read out of your database, not off somebody's invite link.
    """
    def run(job: Job) -> dict:
        if not API.running:
            raise RuntimeError("the mock API is not running — start it from the same tab")
        accounts = usable_accounts(settings, source, token_file, limit)
        job.say(f"{len(accounts)} account(s) via {source} joining server {server_id}")
        hint_given = False
        if invite:
            shown = invite if len(invite) <= 6 else f"{invite[:4]}…({len(invite)} chars)"
            job.say(f"each join carries the room's own invite code: {shown}")
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
                resp = client.request("POST", f"/servers/{server_id}/join",
                                      {"invite": invite} if invite else {},
                                      extra_headers={"Authorization": f"Bearer {token}"})
                key = outcome_labels.get(resp.status, f"http-{resp.status}")
                counts[key] = counts.get(key, 0) + 1
                latencies.append(resp.ms)
                if key in ("joined", "rejoined"):
                    joined.append(user_id)
                if key in ("refused", "no-such-server", "unauthenticated"):
                    job.say(f"user {user_id}: {key} {str(resp.data)[:90]}")
                    if key == "refused" and not invite and not hint_given:
                        hint_given = True
                        job.say("this fixture gates a private room on the row's own slug — paste "
                                "that value in the invite box (SELECT slug FROM servers WHERE id="
                                f"{server_id}), or join a public room; the room listing hides it "
                                "for private rows so the gate stays a gate")
        finally:
            client.close()
        latencies.sort()
        return {"server_id": server_id, "accounts": len(accounts), "counts": counts,
                "invited": bool(invite),
                "p50_ms": round(latencies[len(latencies) // 2], 2) if latencies else 0.0,
                "max_ms": round(latencies[-1], 2) if latencies else 0.0,
                "joined_user_ids": joined[:500]}
    return run


def job_leave(settings: Settings, server_id: int, user_ids: list[int], *, note: str = "") -> Callable[[Job], dict]:
    """Undo a join: the accounts just listed leave again, through the API's own route.

    Deliberately an explicit action over an explicit id list (the ids a join job
    reported), not a scheduler: `left_ts` is a column your app owns, and the console
    does not run membership timing on a timer.
    """
    def run(job: Job) -> dict:
        if note:
            job.say(note)
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
