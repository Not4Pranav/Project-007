"""A small fake app + signup/login/feed API, backed by the seeded fixture DB.

It exists so the seeder and the load generator have something honest to point
at without touching a real service: register/verify/login/pagination paths, a
per-IP token bucket that emits real 429 + Retry-After, and a /metrics endpoint
so you can compare what the client saw against what the server did.

    python -m mockapi.server --db var/test.db --port 8000

Stdlib only (http.server + sqlite3), throttled by design: this is a *shape* of
an API for load-test plumbing, not a production server.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sqlite3
import threading
import time
import traceback
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from seeds.db import connect, migrate
from seeds.profile import derive

MAX_BODY = 64 * 1024
REG_ITERATIONS = 600  # what a live API would use for a brand-new account


@dataclass
class Config:
    db: str = "var/test.db"
    host: str = "0.0.0.0"
    port: int = 8000
    max_inflight: int = 256
    rate_limit_per_min: int = 300
    login_rate_limit_per_min: int = 600
    latency_ms: float = 0.0
    block_disposable: bool = False
    min_password_length: int = 10
    require_email_verify: bool = False
    log: bool = False


@dataclass
class Metrics:
    lock: threading.Lock = field(default_factory=threading.Lock)
    by_route: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    by_error: dict[str, int] = field(default_factory=dict)
    latencies: dict[str, list[float]] = field(default_factory=dict)
    throttled: int = 0
    db_wait_ms: float = 0.0
    started: float = field(default_factory=time.time)

    def record(self, route: str, status: int, ms: float) -> None:
        with self.lock:
            self.by_route[route] = self.by_route.get(route, 0) + 1
            key = f"{status // 100}xx"
            self.by_status[key] = self.by_status.get(key, 0) + 1
            if status == 429:
                self.throttled += 1
            self.latencies.setdefault(route, []).append(ms)
            if len(self.latencies[route]) > 20_000:
                del self.latencies[route][:10_000]  # bounded memory, approximate tail

    def error(self, kind: str) -> None:
        with self.lock:
            self.by_error[kind] = self.by_error.get(kind, 0) + 1

    def snapshot(self) -> dict:
        with self.lock:
            lat = {r: _pcts(v) for r, v in self.latencies.items()}
            return {
                "uptime_s": round(time.time() - self.started, 1),
                "requests": sum(self.by_route.values()),
                "by_route": dict(sorted(self.by_route.items(), key=lambda kv: -kv[1])),
                "by_status": dict(sorted(self.by_status.items())),
                "by_error": dict(self.by_error),
                "throttled": self.throttled,
                "server_latency_ms": lat,
            }


def _pcts(vals: list[float]) -> dict[str, float]:
    if not vals:
        return {}
    s = sorted(vals)
    n = len(s)
    return {f"p{int(q * 100)}": round(s[min(n - 1, int(q * (n - 1)))], 2) for q in (0.5, 0.9, 0.95, 0.99)} | {
        "max": round(s[-1], 2)
    }


class Bucket:
    """Per-IP token bucket, minute resolution. Enough to make 429s real."""

    def __init__(self, per_min: int) -> None:
        self.per_min = per_min
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> tuple[bool, float]:
        if self.per_min <= 0:
            return True, 0.0
        now = time.time()
        with self._lock:
            window = self._hits.setdefault(key, [])
            cutoff = now - 60.0
            while window and window[0] < cutoff:
                window.pop(0)
            if len(window) >= self.per_min:
                return False, 60.0 - (now - window[0])
            window.append(now)
            return True, max(0.0, self.per_min - len(window))

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


DISPOSABLE = {
    "mailinator.com", "10minutemail.com", "temp-mail.org", "guerrillamail.com", "yopmail.com",
    "trashmail.com", "throwawaymail.com", "sharklasers.com", "getnada.com", "dispostable.com",
}


class Store:
    """Connection-per-thread over a WAL database shared with the seeder."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._local = threading.local()

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = connect(self.path)
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


INDEX_HTML = """<!doctype html><meta charset=utf-8><title>fixture mock API</title>
<style>body{font:14px/1.6 ui-monospace,Menlo,monospace;background:#0d1117;color:#c9d1d9;padding:28px;max-width:58rem}
a{color:#79c0ff}h1{font-size:1.2rem;margin:0 0 .2rem}code{color:#ffab70}table{border-collapse:collapse;margin:.6rem 0}
td,th{padding:.2rem .7rem .2rem 0;text-align:left;border-bottom:1px solid #21262d}small{color:#8b949e}
.tag{background:#1f6feb22;border:1px solid #1f6feb55;padding:0 .35rem;border-radius:.3rem}</style>
<h1>fixture mock API <small>— signup / login / feed, backed by the seeded SQLite DB</small></h1>
<p><small>Stdlib <code>ThreadingHTTPServer</code>. It is a load-test target and a schema
shape, not a production service. Start your own app and point the load engine at that instead.</small></p>
<table><tr><th>route</th><th>notes</th></tr>
<tr><td><code>GET /healthz</code></td><td>row counts</td></tr>
<tr><td><code>POST /auth/register</code></td><td>policy + dup checks + per-IP token bucket</td></tr>
<tr><td><code>POST /auth/verify</code></td><td>flip pending -> active</td></tr>
<tr><td><code>POST /auth/login</code></td><td>reads credentials.{algo,iterations}</td></tr>
<tr><td><code>GET /users/me</code></td><td><span class="tag">bearer</span></td></tr>
<tr><td><code>GET /feed?limit=25&amp;cursor=ts:id</code></td><td>keyset pagination, no OFFSET</td></tr>
<tr><td><code>POST /messages</code></td><td><span class="tag">bearer</span> writes an event</td></tr>
<tr><td><code>GET /metrics</code></td><td>server-side p50/p90/p95/p99 + throttle count</td></td></tr>
</table>
<h2>live</h2><pre id=m>loading…</pre>
<script>async function tick(){try{const r=await fetch('/metrics');document.getElementById('m').textContent=
JSON.stringify(await r.json(),null,2)}catch(e){document.getElementById('m').textContent='offline'}}
tick();setInterval(tick,2000)</script>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Idle keep-alive connections must expire, or a load run's leftover sockets
    # pin a handler thread (and its DB handle) open forever.
    timeout = 30
    server_version = "FixtureMockAPI/1.0"

    # Everything lives on the server instance, not on the class: two RunningApi
    # objects in one process (tests, or a second port for a blue/green check)
    # must not share buckets, metrics, or the DB handle.
    @property
    def cfg(self) -> Config:
        return self.server.cfg  # type: ignore[attr-defined]

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def metrics(self) -> Metrics:
        return self.server.metrics  # type: ignore[attr-defined]

    @property
    def reg_bucket(self) -> Bucket:
        return self.server.reg_bucket  # type: ignore[attr-defined]

    @property
    def login_bucket(self) -> Bucket:
        return self.server.login_bucket  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:  # pragma: no cover
        if self.cfg.log:
            super().log_message(fmt, *args)

    # ------------------------------------------------------------- plumbing
    _raw_body: bytes = b""

    def _send(self, status: int, payload: object, extra: dict[str, str] | None = None) -> None:
        body = payload if isinstance(payload, (bytes, str)) else json.dumps(payload, separators=(",", ":"))
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8" if isinstance(payload, str)
                         and str(payload).lstrip().startswith("<") else "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _drain_body(self) -> bool:
        """Read the whole request body up front.

        Skipping this is the classic keep-alive footgun: a handler that answers
        429 (or 413) without consuming `Content-Length` bytes leaves the body in
        the socket, and the next request line the server parses is JSON - which
        looks like a mysterious 400 from the client's side, on a connection that
        is now permanently misaligned.
        """
        length = int(self.headers.get("Content-Length") or 0)
        self._raw_body = b""
        if length <= 0:
            return True
        if length > MAX_BODY:
            self._send(413, {"error": f"body exceeds {MAX_BODY} bytes"})
            self.close_connection = True
            return False
        self._raw_body = self.rfile.read(length)
        return True

    def _json_body(self) -> dict:
        if not self._raw_body:
            return {}
        try:
            data = json.loads(self._raw_body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid json: {exc}") from exc
        return data if isinstance(data, dict) else {"value": data}

    def _client_ip(self) -> str:
        fwd = self.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "?"

    def _bearer(self) -> str | None:
        head = self.headers.get("Authorization", "")
        return head[7:].strip() if head.lower().startswith("bearer ") else None

    def _user_from_token(self) -> sqlite3.Row | None:
        token = self._bearer()
        if not token:
            return None
        return self.store.conn.execute(
            "SELECT u.*, s.token AS session_token FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.revoked = 0",
            (token,),
        ).fetchone()

    # --------------------------------------------------------------- routes
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        started = time.perf_counter()
        parts = urlsplit(self.path)
        route = parts.path
        key = f"{method} {route}"
        try:
            if not self._drain_body():
                return
            status, payload, extra = self._route(method, route, parse_qs(parts.query))
        except Exception as exc:  # pragma: no cover - defensive
            self.metrics.error(type(exc).__name__)
            status, payload, extra = 500, {"error": f"{type(exc).__name__}: {exc}"}, {}
            if self.cfg.log:
                traceback.print_exc()
        ms = (time.perf_counter() - started) * 1000
        self.metrics.record(f"{method} {route}" if "{" not in route else key, status, ms)
        if self.cfg.latency_ms > 0:
            time.sleep(self.cfg.latency_ms / 1000.0 * (0.5 + (ms % 100) / 100.0))
        try:
            self._send(status, payload, extra)
        except (BrokenPipeError, ConnectionResetError):
            # The client hung up - a load worker hitting its own timeout. Expected
            # at saturation, so count it once instead of dumping a traceback per abort.
            self.metrics.error("client_aborted")

    def _route(self, method: str, route: str, qs: dict) -> tuple[int, object, dict[str, str]]:
        c = self.store.conn
        if route == "/":
            return 200, INDEX_HTML, {}
        if route == "/healthz":
            users = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
            return 200, {"status": "ok", "users": users, "db": str(self.cfg.db),
                         "uptime_s": round(time.time() - self.metrics.started, 1)}, {}
        if route == "/metrics":
            snap = self.metrics.snapshot()
            snap["config"] = {
                "rate_limit_per_min": self.cfg.rate_limit_per_min,
                "login_rate_limit_per_min": self.cfg.login_rate_limit_per_min,
                "injected_latency_ms": self.cfg.latency_ms,
                "block_disposable": self.cfg.block_disposable,
            }
            return 200, snap, {}

        if route == "/auth/sample-identifiers":
            n = int((qs.get("n") or ["500"])[0])
            rows = c.execute(
                "SELECT email, username FROM users WHERE status = 'active' ORDER BY RANDOM() LIMIT ?", (n,)
            ).fetchall()
            return 200, {"identifiers": [r["email"] for r in rows]}, {}

        if method == "GET" and route == "/users/me":
            u = self._user_from_token()
            if u is None:
                return 401, {"error": "missing or invalid bearer token"}, {}
            stats = c.execute(
                "SELECT COUNT(*) n, MAX(ts) last FROM events WHERE user_id = ?", (u["id"],)
            ).fetchone()
            return 200, {
                "id": u["id"], "username": u["username"], "email": u["email"], "status": u["status"],
                "country": u["country"], "locale": u["locale"], "device_class": u["device_class"],
                "signup_ts": u["signup_ts"], "verified_ts": u["verified_ts"],
                "event_count": stats["n"], "last_active_ts": stats["last"],
            }, {}

        if method == "GET" and route == "/feed":
            limit = min(100, max(1, int((qs.get("limit") or ["25"])[0])))
            cursor = (qs.get("cursor") or [""])[0]
            args: list[object] = []
            where = "e.kind IN ('post','message')"
            if cursor:
                try:
                    cts, cid = cursor.split(":")
                    where += " AND (e.ts < ? OR (e.ts = ? AND e.id < ?))"
                    args += [int(cts), int(cts), int(cid)]
                except ValueError:
                    return 400, {"error": "cursor must be ts:id"}, {}
            rows = c.execute(
                f"SELECT e.id, e.ts, e.kind, e.weight, e.meta, u.id uid, u.username, u.display_name, "
                f"u.avatar_seed FROM events e JOIN users u ON u.id = e.user_id WHERE {where} "
                f"ORDER BY e.ts DESC, e.id DESC LIMIT ?", (*args, limit + 1)
            ).fetchall()
            items = []
            for r in rows[:limit]:
                body = r["meta"] or ""
                if not body:
                    body = f"[fixture {r['kind']} #{r['id']}]"
                items.append({
                    "id": r["id"], "ts": r["ts"], "kind": r["kind"], "weight": r["weight"], "text": body,
                    "author": {"id": r["uid"], "username": r["username"], "display_name": r["display_name"],
                               "avatar_seed": r["avatar_seed"]},
                })
            nxt = f"{rows[limit - 1]['ts']}:{rows[limit - 1]['id']}" if len(rows) > limit else None
            return 200, {"items": items, "next_cursor": nxt, "limit": limit}, {}

        if method == "POST" and route == "/auth/register":
            ok, wait = self.reg_bucket.allow(self._client_ip())
            if not ok:
                return 429, {"error": "rate limit exceeded", "retry_after_s": round(wait, 2)}, {
                    "Retry-After": str(max(1, int(wait))), "X-RateLimit-Remaining": "0"}
            try:
                body = self._json_body()
            except ValueError as exc:
                return 400, {"error": str(exc)}, {}
            email = str(body.get("email") or "").strip().lower()
            username = str(body.get("username") or "").strip()
            password = str(body.get("password") or "")
            err = self._validate_signup(email, username, password)
            if err:
                return 422, {"error": err[0], "field": err[1]}, {}
            if self.cfg.block_disposable and email.rsplit("@", 1)[-1] in DISPOSABLE:
                return 403, {"error": "disposable email domain not accepted", "field": "email"}, {}
            if c.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                return 409, {"error": "email already registered", "field": "email"}, {}
            if c.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                return 409, {"error": "username taken", "field": "username"}, {}
            now = int(time.time())
            salt = secrets.token_bytes(16)
            h = derive("pbkdf2_sha256", password, salt, REG_ITERATIONS)
            token = f"ver_{secrets.token_urlsafe(16)}"
            c.execute("BEGIN IMMEDIATE")
            try:
                uid = c.execute(
                    "INSERT INTO users (username, email, email_domain, display_name, dob, country, region, "
                    "timezone, locale, signup_ts, signup_ip, signup_ua, device_class, source, status, has_phone, "
                    "newsletter, is_synthetic_abuse) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                    (username, email, email.rsplit("@", 1)[-1], body.get("display_name") or username,
                     body.get("dob") or "2000-01-01", "US", "load-test", "UTC", "en-US", now,
                     self._client_ip(), self.headers.get("User-Agent", ""), "desktop", "api",
                     "pending_verification", 0, 0),
                ).lastrowid
                c.execute("INSERT INTO credentials(user_id, algo, salt, iterations, hash) VALUES(?,?,?,?,?)",
                          (uid, "pbkdf2_sha256", salt, REG_ITERATIONS, h))
                c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('loadtest_last_uid', ?)", (str(uid),))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
            payload = {"user_id": uid, "status": "pending_verification", "verify_token": token,
                       "verify_path": f"/auth/verify?token={token}"}
            if not self.cfg.require_email_verify:
                c.execute("UPDATE users SET status='active', verified_ts=? WHERE id=?", (now, uid))
                payload["status"] = "active"
            return 201, payload, {}

        if method == "POST" and route == "/auth/verify":
            try:
                body = self._json_body()
            except ValueError as exc:
                return 400, {"error": str(exc)}, {}
            email = str(body.get("email") or "").lower()
            if not email:
                return 422, {"error": "email required", "field": "email"}, {}
            cur = c.execute("UPDATE users SET status='active', verified_ts=? "
                            "WHERE email=? AND status='pending_verification'", (int(time.time()), email))
            if cur.rowcount == 0:
                return 404, {"error": "no pending account for that email"}, {}
            return 200, {"status": "active"}, {}

        if method == "POST" and route == "/auth/login":
            ok, wait = self.login_bucket.allow(self._client_ip())
            if not ok:
                return 429, {"error": "too many login attempts", "retry_after_s": round(wait, 2)}, {
                    "Retry-After": str(max(1, int(wait)))}
            try:
                body = self._json_body()
            except ValueError as exc:
                return 400, {"error": str(exc)}, {}
            ident = str(body.get("email") or body.get("identifier") or body.get("username") or "").strip().lower()
            password = str(body.get("password") or "")
            if not ident or not password:
                return 422, {"error": "identifier and password required"}, {}
            row = c.execute(
                "SELECT u.id, u.status, cr.algo, cr.salt, cr.iterations, cr.hash FROM users u "
                "LEFT JOIN credentials cr ON cr.user_id = u.id "
                "WHERE lower(u.email) = ? OR lower(u.username) = ?", (ident, ident)
            ).fetchone()
            if row is None or row["algo"] is None:
                return 401, {"error": "invalid credentials"}, {}
            if row["status"] == "suspended":
                return 403, {"error": "account suspended"}, {}
            if not verify_login(row, password):
                self.metrics.error("bad_password")
                return 401, {"error": "invalid credentials"}, {}
            now = int(time.time())
            token = f"ses_{secrets.token_urlsafe(18)}"
            c.execute("INSERT INTO sessions(user_id, token, ip, ua, device_class, created_ts, last_seen_ts, revoked)"
                      " VALUES(?,?,?,?,?,?,?,0)",
                      (row["id"], token, self._client_ip(), self.headers.get("User-Agent", ""), "desktop", now, now))
            return 200, {"token": token, "user_id": row["id"], "token_type": "bearer", "expires_in": 86400}, {}

        if method == "POST" and route == "/messages":
            u = self._user_from_token()
            if u is None:
                return 401, {"error": "auth required"}, {}
            try:
                body = self._json_body()
            except ValueError as exc:
                return 400, {"error": str(exc)}, {}
            text = str(body.get("text") or "")
            if not text:
                return 422, {"error": "text required", "field": "text"}, {}
            if len(text) > 2000:
                return 422, {"error": "text too long", "field": "text"}, {}
            now = int(time.time())
            eid = c.execute("INSERT INTO events(user_id, ts, kind, weight, ip, meta) VALUES(?,?,?,?,?,?)",
                            (u["id"], now, "message", 1, self._client_ip(), text)).lastrowid
            return 201, {"id": eid, "ts": now, "kind": "message"}, {}

        return 404, {"error": "no such route", "route": f"{method} {route}"}, {}

    def _validate_signup(self, email: str, username: str, password: str) -> tuple[str, str] | None:
        if "@" not in email or len(email) > 254 or email.count("@") != 1:
            return ("not a valid email address", "email")
        if not 2 <= len(username) <= 32 or any(ch.isspace() for ch in username):
            return ("username must be 2-32 characters, no whitespace", "username")
        if len(password) < self.cfg.min_password_length:
            return (f"password must be at least {self.cfg.min_password_length} characters", "password")
        return None


def verify_login(row: sqlite3.Row, password: str) -> bool:
    import hashlib
    import hmac

    algo = row["algo"]
    if algo == "sha256_fast":
        got = hashlib.sha256(bytes(row["salt"]) + password.encode()).digest()
    else:
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes(row["salt"]), int(row["iterations"]))
    return hmac.compare_digest(got, bytes(row["hash"]))


class AdmissionServer(ThreadingHTTPServer):
    """Thread-per-connection, but with a hard cap on admitted connections.

    Unpatched, a saturated `ThreadingHTTPServer` accepts every socket first and
    queues *after* that - so 250 concurrent clients cost 250 fds and 250
    threads, and the process ends up unable to open its own database file.
    Gating in `process_request` instead parks the excess in the kernel backlog,
    which is bounded, and clients see connect latency / timeouts - i.e. the same
    failure shape a real saturated service produces.
    """

    daemon_threads = True
    request_queue_size = 128

    def process_request(self, request, client_address) -> None:  # type: ignore[override]
        sem = getattr(self, "accept_sem", None)
        if sem is None:
            super().process_request(request, client_address)
            return
        sem.acquire()
        try:
            threading.Thread(target=self._admitted, args=(request, client_address), daemon=True).start()
        except Exception:
            sem.release()
            raise

    def _admitted(self, request, client_address) -> None:
        """Release the admission slot in `finally`, whatever happens to the socket.

        Releasing from the handler's finish() looked equivalent and was not: a
        connection reset during setup never reaches finish(), and every aborted
        connection permanently consumed a slot. After a 250-connection stage the
        server had 0 permits left and stopped accepting - it looked alive, it
        just never answered again.
        """
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            try:
                self.shutdown_request(request)
            finally:
                self.accept_sem.release()


def build_server(cfg: Config) -> AdmissionServer:
    """Configure + bind without blocking. Port 0 is fine, so tests can share a
    machine without fighting over 8000."""
    conn = connect(cfg.db)
    migrate(conn)
    conn.close()
    AdmissionServer.request_queue_size = max(64, cfg.max_inflight * 2)
    httpd = AdmissionServer((cfg.host, cfg.port), Handler)
    httpd.accept_sem = threading.Semaphore(cfg.max_inflight if cfg.max_inflight > 0 else 1_000_000)
    httpd.cfg = cfg  # type: ignore[attr-defined]
    httpd.store = Store(cfg.db)  # type: ignore[attr-defined]
    httpd.metrics = Metrics()  # type: ignore[attr-defined]
    httpd.reg_bucket = Bucket(cfg.rate_limit_per_min)  # type: ignore[attr-defined]
    httpd.login_bucket = Bucket(cfg.login_rate_limit_per_min)  # type: ignore[attr-defined]
    return httpd


def serve(cfg: Config) -> ThreadingHTTPServer:
    httpd = build_server(cfg)
    httpd.serve_forever()
    return httpd


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m mockapi.server", description=__doc__,
                               formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="var/test.db")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--rate-limit-per-min", type=int, default=300, help="0 disables the register bucket")
    p.add_argument("--login-rate-limit-per-min", type=int, default=600)
    p.add_argument("--latency-ms", type=float, default=0.0, help="simulate a slow downstream dependency")
    p.add_argument("--block-disposable", action="store_true", help="403 signups from throwaway domains")
    p.add_argument("--require-email-verify", action="store_true", help="new accounts stay pending until /auth/verify")
    p.add_argument("--min-password-length", type=int, default=10)
    p.add_argument("--max-inflight", type=int, default=256,
                   help="connections handled at once; above that they queue in the listen "
                        "backlog. Set it over your largest load stage.")
    p.add_argument("--log", action="store_true", help="print request lines")
    a = p.parse_args(argv)
    if not Path(a.db).exists():
        print(f"no such database: {a.db}\n  run:  python -m seeds.seed --db {a.db}", flush=True)
        return 2
    cfg = Config(db=a.db, host=a.host, port=a.port, rate_limit_per_min=a.rate_limit_per_min,
                 login_rate_limit_per_min=a.login_rate_limit_per_min, latency_ms=a.latency_ms,
                 block_disposable=a.block_disposable, min_password_length=a.min_password_length,
                 require_email_verify=a.require_email_verify, log=a.log, max_inflight=a.max_inflight)
    try:  # a fixture target should not be the reason your run fails
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65536, hard), hard))
    except Exception:
        soft = hard = 0
    print(f"mock api on http://{a.host}:{a.port}  db={a.db}  register limit={a.rate_limit_per_min}/min  "
          f"max in-flight={a.max_inflight}  fds={soft}/{hard}", flush=True)
    try:
        serve(cfg)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
