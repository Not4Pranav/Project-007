"""Scenario definitions for the load engine.

Each scenario is a stateful callable with a per-worker `ctx` dict, so a worker
can hold its own bearer token and feed cursor instead of re-doing work that
real users only do once per session.
"""

from __future__ import annotations

import itertools
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

OutcomeKind = str  # ok | throttled | conflict | client_error | auth_fail | server_error | transport


def classify(resp_status: int, exc: bool = False) -> OutcomeKind:
    if exc or resp_status == 0:
        return "transport"
    if resp_status == 429:
        return "throttled"
    if resp_status in (401, 403):
        return "auth_fail"
    if resp_status == 409:
        return "conflict"
    if 200 <= resp_status < 300:
        return "ok"
    if 400 <= resp_status < 500:
        return "client_error"
    return "server_error"


@dataclass
class Scenario:
    name: str
    run: Callable[[Any, dict, LoadOptions], tuple[OutcomeKind, float, str]]
    """run(client, ctx, opts) -> (kind, latency_ms, op_label)"""


class LoadOptions:
    """Knobs shared by scenarios; the engine fills these from CLI args."""

    def __init__(self, *, password: str, identifiers: list[str], register_domain: str,
                 register_prefix: str = "lt", feed_limit: int = 25, verify_first: bool = False,
                 count_throttled_as_error: bool = False, mix_weights: dict[str, float] | None = None) -> None:
        self.password = password
        self.identifiers = identifiers
        self.register_domain = register_domain
        self.register_prefix = register_prefix
        self.feed_limit = feed_limit
        self.verify_first = verify_first
        self.count_throttled_as_error = count_throttled_as_error
        self.mix_weights: dict[str, float] = mix_weights or {"login": 40, "feed": 45, "register": 4, "post": 11}
        self._seq = itertools.count(1)
        self._lock = threading.Lock()
        # Unique per run: without a nonce, stage 2 collides with the usernames
        # stage 1 created and the report fills with 409s that are a fixture
        # artifact rather than a measurement.
        self.nonce = f"{int(time.time()) % 100000:05d}"

    def next_seq(self) -> int:
        with self._lock:
            return next(self._seq)

    def identifier(self, rnd: random.Random) -> str:
        if not self.identifiers:
            raise RuntimeError("no fixture identifiers available for login scenario")
        return rnd.choice(self.identifiers)

    def new_identity(self) -> tuple[str, str]:
        seq = self.next_seq()
        stamp = int(time.time() * 1000) % 100_000
        email = f"{self.register_prefix}{seq}-{stamp}@{self.register_domain}"
        username = f"{self.register_prefix}{self.nonce}{seq:06d}"
        return email, username


# --------------------------------------------------------------------- ops
def _op_login(client: Any, ctx: dict, opts: LoadOptions) -> tuple[OutcomeKind, float, str]:
    rnd: random.Random = ctx["rnd"]
    ident = opts.identifier(rnd)
    resp = client.login(ident, opts.password)
    if resp.status == 200 and isinstance(resp.data, dict):
        ctx["token"] = resp.data.get("token")
        ctx["as"] = ident
    return classify(resp.status), resp.ms, "login"


def _op_feed(client: Any, ctx: dict, opts: LoadOptions) -> tuple[OutcomeKind, float, str]:
    cursor = ctx.get("cursor")
    resp = client.feed(limit=opts.feed_limit, cursor=cursor, token=ctx.get("token"))
    if isinstance(resp.data, dict):
        ctx["cursor"] = resp.data.get("next_cursor")
    return classify(resp.status), resp.ms, "feed"


def _op_register(client: Any, ctx: dict, opts: LoadOptions) -> tuple[OutcomeKind, float, str]:
    email, username = opts.new_identity()
    resp = client.register(email, username, opts.password)
    ms = resp.ms
    kind = classify(resp.status)
    if kind == "ok" and opts.verify_first and resp.get("status", default="") == "pending_verification":
        r2 = client.verify(email)
        ms += r2.ms
        kind = classify(r2.status)
    return kind, ms, "register"


def _op_post(client: Any, ctx: dict, opts: LoadOptions) -> tuple[OutcomeKind, float, str]:
    token = ctx.get("token")
    if not token:
        kind, ms, _ = _op_login(client, ctx, opts)
        if kind != "ok":
            return kind, ms, "post.login"
        token = ctx.get("token")
    rnd: random.Random = ctx["rnd"]
    resp = client.message(f"load probe {rnd.randrange(10**6):06d} t={time.time():.3f}", token or "")
    return classify(resp.status), resp.ms, "post"


def _op_mixed(client: Any, ctx: dict, opts: LoadOptions) -> tuple[OutcomeKind, float, str]:
    """Only /auth/register is throttled by the mock API, so a registration-heavy
    mix is how you find the point where backpressure starts eating real users."""
    total = sum(opts.mix_weights.values())
    r = ctx["rnd"].random() * total
    acc = 0.0
    for name, w in opts.mix_weights.items():
        acc += w
        if r <= acc:
            return SCENARIOS[name].run(client, ctx, opts)
    return SCENARIOS["feed"].run(client, ctx, opts)


_ops = {"login": _op_login, "feed": _op_feed, "register": _op_register, "post": _op_post}

SCENARIOS: dict[str, Scenario] = {
    **{k: Scenario(k, v) for k, v in _ops.items()},
    "mixed": Scenario("mixed", _op_mixed),
    "signup": Scenario("signup", _op_register),
}
def available() -> list[str]:
    return sorted(SCENARIOS)
