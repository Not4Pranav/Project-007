from __future__ import annotations

import json
import ssl
import time
from contextlib import suppress
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection
from itertools import count
from threading import Lock, local
from typing import Any
from urllib.parse import urlsplit


@dataclass(slots=True)
class Response:
    status: int
    data: Any
    ms: float
    headers: dict[str, str]

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def get(self, *keys: str, default: Any = None) -> Any:
        cur = self.data
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur


class ApiClient:
    """Keep-alive JSON client, one TCP connection per thread.

    Thread-local connections matter for load tests: a client that reconnects per
    request spends its wall clock in the TCP handshake and reports latency your
    real users would never see.
    """

    def __init__(self, base_url: str, *, timeout: float = 10.0, user_agent: str = "fixture-load/1.0",
                 ip_pool: int = 0, verify_tls: bool = True) -> None:
        """TLS is supported and verified by default, because a staging target over
        `https://` is the normal case for `--spec` runs. `verify_tls=False` exists for
        a self-signed dev box and must be reached by an explicit flag, never a default.

        `ip_pool` > 0 stamps each worker thread with its own X-Forwarded-For.

        Without it, 250 concurrent workers look like one abusive client and every
        per-IP limit you have fires at 1/250th of the traffic. Addresses come from
        203.0.113.0/24 (TEST-NET-3, reserved for docs/tests) so nothing can leak
        toward a real host.
        """
        u = urlsplit(base_url)
        if u.scheme not in ("http", "https", ""):
            raise ValueError(f"expected http(s), got {u.scheme!r}")
        self.tls = u.scheme == "https"
        if self.tls and not verify_tls:
            # Ruff's `S` rules are not enabled here, and verification is opt-out by an
            # explicit flag, so this is deliberate rather than suppressed.
            self._ssl = ssl._create_unverified_context()
        elif self.tls:
            self._ssl = ssl.create_default_context()
        else:
            self._ssl = None
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.tls else 80)
        self.timeout = timeout
        self.user_agent = user_agent
        self.ip_pool = max(0, ip_pool)
        self._local = local()
        self._ip_lock = Lock()
        self._ip_next = count(1)

    # ------------------------------------------------------------- internals
    def _conn(self) -> HTTPConnection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self.tls:
                conn = HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self._ssl)
            else:
                conn = HTTPConnection(self.host, self.port, timeout=self.timeout)
            conn.sock = None
            self._local.conn = conn
        return conn

    def _thread_ip(self) -> str | None:
        if not self.ip_pool:
            return None
        ip = getattr(self._local, "ip", None)
        if ip is None:
            with self._ip_lock:
                n = next(self._ip_next)
            ip = f"203.0.113.{(n - 1) % min(254, self.ip_pool) + 1}"
            self._local.ip = ip
        return ip

    def request(self, method: str, path: str, body: Any = None,
                extra_headers: dict[str, str] | None = None) -> Response:
        """Any route, any body, any headers - the shape `load/generic.py` needs."""
        return self._request(method, path, body, extra_headers=extra_headers)

    def _request(self, method: str, path: str, body: Any = None, token: str | None = None,
                 extra_headers: dict[str, str] | None = None) -> Response:
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json", "User-Agent": self.user_agent,
                   "Connection": "keep-alive", "Host": f"{self.host}:{self.port}"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(payload))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        ip = self._thread_ip()
        if ip:
            headers["X-Forwarded-For"] = ip
        if extra_headers:
            headers.update({k: v for k, v in extra_headers.items() if v})
        t0 = time.perf_counter()
        last_exc: Exception | None = None
        for _attempt in (0, 1):  # one retry for a stale keep-alive socket
            conn = self._conn()
            try:
                if conn.sock is None:
                    conn.connect()
                conn.request(method, path, body=payload, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                data: Any = None
                if raw:
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        data = raw[:200].decode(errors="replace")
                return Response(resp.status, data, (time.perf_counter() - t0) * 1000.0, dict(resp.getheaders()))
            except (ConnectionError, TimeoutError, OSError) as exc:
                last_exc = exc
                with suppress(Exception):
                    conn.close()
                self._local.conn = None
        ms = (time.perf_counter() - t0) * 1000.0
        return Response(0, {"error": f"{type(last_exc).__name__}: {last_exc}"}, ms, {})

    def close(self) -> None:
        """Drop this thread's pooled socket (other threads keep theirs)."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            with suppress(Exception):
                conn.close()
            self._local.conn = None

    # ---------------------------------------------------------------- routes
    def health(self) -> Response:
        return self._request("GET", "/healthz")

    def metrics(self) -> Response:
        return self._request("GET", "/metrics")

    def sample_identifiers(self, n: int = 500) -> Response:
        return self._request("GET", f"/auth/sample-identifiers?n={n}")

    def register(self, email: str, username: str, password: str, **extra: Any) -> Response:
        return self._request("POST", "/auth/register", {"email": email, "username": username,
                                                        "password": password, **extra})

    def verify(self, email: str) -> Response:
        return self._request("POST", "/auth/verify", {"email": email})

    def login(self, identifier: str, password: str) -> Response:
        return self._request("POST", "/auth/login", {"identifier": identifier, "password": password})

    def me(self, token: str) -> Response:
        return self._request("GET", "/users/me", token=token)

    def feed(self, limit: int = 25, cursor: str | None = None, token: str | None = None) -> Response:
        path = f"/feed?limit={limit}" + (f"&cursor={cursor}" if cursor else "")
        return self._request("GET", path, token=token)

    def message(self, text: str, token: str) -> Response:
        return self._request("POST", "/messages", {"text": text}, token=token)
