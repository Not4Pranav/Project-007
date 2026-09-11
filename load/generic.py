"""Spec-driven scenarios: drive a real API from JSON, no code edits.

    python -m load.engine --spec docs/examples/myapp.load.json --stages 25,100

The spec describes the ops and how to thread state between them (log in, capture
a token, use it on the next call). It exists because the moment this harness
leaves the mock API you need a client that is *not* hardcoded to
`/auth/login`-shaped routes.

Schema (all of `headers`/`query`/`json`/`path` accept `{{var}}` templates):

    {
      "name": "myapp",
      "base_url": "http://localhost:3000",          // optional; --base-url wins
      "headers": {"Authorization": "Bearer {{token}}"},
      "ops": [
        {"name": "login", "weight": 40,
         "method": "POST", "path": "/session",
         "json": {"email": "{{ident}}", "password": "{{password}}"},
         "expect": [200, 401],
         "capture": {"token": "data.token"}},
        {"name": "feed", "weight": 60,
         "method": "GET", "path": "/feed",
         "query": {"limit": "{{feed_limit}}", "cursor": "{{cursor}}"},
         "requires": ["token"],
         "capture": {"cursor": "next_cursor"}}
      ]
    }
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from .scenarios import classify

_TEMPLATE = re.compile(r"\{\{\s*([a-zA-Z0-9_:.]+)\s*\}\}")


@dataclass
class Op:
    name: str
    method: str = "GET"
    path: str = "/"
    weight: float = 1.0
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    body: Any = None
    expect: tuple[int, ...] = (200, 201, 204)
    capture: dict[str, str] = field(default_factory=dict)
    requires: tuple[str, ...] = ()
    think_ms: float = 0.0

    @classmethod
    def from_dict(cls, raw: dict) -> Op:
        if "name" not in raw:
            raise ValueError(f"op needs a name: {raw}")
        expect = raw.get("expect") or [200, 201, 204]
        return cls(
            name=str(raw["name"]),
            method=str(raw.get("method", "GET")).upper(),
            path=str(raw.get("path", "/")),
            weight=float(raw.get("weight", 1.0)),
            headers=dict(raw.get("headers") or {}),
            query=dict(raw.get("query") or {}),
            body=raw.get("json", raw.get("body")),
            expect=tuple(int(x) for x in expect),
            capture=dict(raw.get("capture") or {}),
            requires=tuple(raw.get("requires") or ()),
            think_ms=float(raw.get("think_ms", 0.0)),
        )


@dataclass
class Spec:
    name: str
    base_url: str
    headers: dict[str, str]
    ops: list[Op]

    @classmethod
    def load(cls, path: str | Path) -> Spec:
        raw = json.loads(Path(path).read_text())
        ops = [Op.from_dict(o) for o in raw.get("ops") or []]
        if not ops:
            raise ValueError(f"{path}: no ops defined")
        if any(o.weight < 0 for o in ops):
            raise ValueError(f"{path}: negative weight")
        if sum(o.weight for o in ops) <= 0:
            raise ValueError(f"{path}: all weights are zero")
        return cls(name=str(raw.get("name", Path(path).stem)), base_url=str(raw.get("base_url", "")),
                   headers=dict(raw.get("headers") or {}), ops=ops)

    def total_weight(self) -> float:
        return sum(o.weight for o in self.ops)

    def describe(self) -> str:
        return ", ".join(f"{o.name}({o.weight:g})" for o in self.ops)


def dig(data: Any, dotted: str) -> Any:
    """`a.b.0.c` over dicts and lists; None if any hop is missing."""
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            idx = int(part)
            cur = cur[idx] if -len(cur) <= idx < len(cur) else None
        else:
            return None
    return cur


class Template:
    """Resolves `{{var}}` against per-worker state, then built-ins.

    Anything captured from a previous response lives in `ctx` and wins over the
    built-ins, so `{{token}}` means "this worker's token".

    Built-ins: `{{seq}}` (monotonic per run), `{{rand:N}}`, `{{uuid}}`,
    `{{email}}`/`{{username}}` (fresh fixture identities), `{{ident}}` (a
    login identifier from the pool), `{{password}}`, `{{feed_limit}}`,
    `{{token}}`, `{{cursor}}`, `{{now}}`. A `:arg` on a built-in that has no
    other meaning is passed through as the value, e.g. `{{feed_limit:5}}`.
    """

    def __init__(self, opts: Any) -> None:
        self.opts = opts

    def values(self, ctx: dict) -> dict[str, str]:
        return {
            "password": getattr(self.opts, "password", ""),
            "feed_limit": str(getattr(self.opts, "feed_limit", 25)),
            "token": ctx.get("token") or "",
            "cursor": ctx.get("cursor") or "",
            "now": str(int(time.time())),
        }

    def resolve(self, text: str, ctx: dict) -> tuple[str, str | None]:
        """Returns (rendered, error). An unknown/empty required var is an error so
        a misconfigured spec is loud instead of quietly sending 'Bearer '."""
        problem: str | None = None

        def sub(match: re.Match[str]) -> str:
            nonlocal problem
            key = match.group(1)
            # Present-but-empty must fall through to the built-ins: the engine
            # starts a worker with token=None, and str(None) is "None", which a
            # real API happily parses as a cursor and rejects. Every feed request
            # in the first spec run 400'd that way.
            if ctx.get(key) not in (None, ""):
                return str(ctx[key])
            name, _, arg = key.partition(":")
            if name == "rand":
                return str(secrets.randbelow(int(arg or 1_000_000)))
            if name == "seq":
                return str(self.opts.next_seq())
            if name == "uuid":
                return f"{secrets.token_hex(4)}-{secrets.token_hex(2)}-{secrets.token_hex(4)}"
            if name == "email":
                email, _ = self.opts.new_identity()
                ctx["last_email"] = email
                return email
            if name == "username":
                _, username = self.opts.new_identity()
                return username
            if name == "ident":
                ident = self.opts.identifier(ctx["rnd"])
                ctx["last_ident"] = ident
                return ident
            builtin = self.values(ctx).get(name)
            if builtin is None:
                problem = f"unresolved template variable {{{{{name}}}}}"
                return ""
            if arg:
                return arg
            return builtin

        out = _TEMPLATE.sub(sub, text)
        return out, problem

    def walk(self, node: Any, ctx: dict) -> tuple[Any, str | None]:
        if isinstance(node, str):
            return self.resolve(node, ctx)
        if isinstance(node, list):
            out = []
            for item in node:
                val, err = self.walk(item, ctx)
                if err:
                    return out, err
                out.append(val)
            return out, None
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                val, err = self.walk(v, ctx)
                if err:
                    return out, err
                out[k] = val
            return out, None
        return node, None


class GenericScenario:
    """Duck-types `Scenario`: the engine only needs `.name` and `.run`."""

    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        self.name = spec.name
        self.template = Template(None)  # rebound by run() with the live opts

    def pick(self, rnd: Any) -> Op:
        r = rnd.random() * self.spec.total_weight()
        acc = 0.0
        for op in self.spec.ops:
            acc += op.weight
            # strict > : a weight-0 op must never be reachable, including at r == 0.0
            if r < acc:
                return op
        return self.spec.ops[-1]

    def run(self, client: Any, ctx: dict, opts: Any) -> tuple[str, float, str]:
        self.template.opts = opts
        op = self.pick(ctx["rnd"])
        if op.think_ms:
            time.sleep(op.think_ms / 1000.0)
        if any(not ctx.get(var) for var in op.requires):
            return "skipped", 0.0, op.name

        headers, err = self.template.walk({**self.spec.headers, **op.headers}, ctx)
        if err:
            return "spec_error", 0.0, op.name
        body, err = self.template.walk(op.body, ctx)
        if err:
            return "spec_error", 0.0, op.name
        path, err = self.template.resolve(op.path, ctx)
        if err:
            return "spec_error", 0.0, op.name
        query, err = self.template.walk(op.query, ctx)
        if err:
            return "spec_error", 0.0, op.name

        if isinstance(query, dict):
            clean = {k: v for k, v in query.items() if v not in (None, "")}
            if clean:
                path = f"{path}?{urlencode(clean)}"

        resp = client.request(op.method, path, body, extra_headers=headers or None)
        ms = resp.ms
        if resp.status in op.expect:
            kind = "ok"
        elif resp.status == 0:
            kind = "transport"
        elif resp.status == 429:
            kind = "throttled"
        elif resp.status >= 500:
            kind = "server_error"
        else:
            kind = classify(resp.status)
        # Captures are success-only. A 401/500 body that happens to carry the field
        # (an error payload echoing a stale token, a 2-stage auth flow returning
        # `{"token": null}`-adjacent junk) must not populate state, because `requires`
        # reads that state and would then start firing authed traffic with a bad token.
        if resp.status in op.expect and resp.status < 400:
            for var, dotted in op.capture.items():
                value = dig(resp.data, dotted)
                if value is not None:
                    ctx[var] = value
                    if var == "token":
                        # provenance for the account dump: a --token-file worker that then
                        # logged in is browsing *its own* session, not the pre-minted one
                        ctx["token_source"] = f"{op.name} capture"
        return kind, ms, op.name


def scenario_from(path: str | Path) -> GenericScenario:
    return GenericScenario(Spec.load(path))
