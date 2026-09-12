"""Shared helpers: build a small fixture DB once per test session."""

from __future__ import annotations

import atexit
import shutil
import tempfile
import threading
from pathlib import Path

from mockapi.server import Config, build_server
from seeds.seed import main as seed_main

TMP = Path(tempfile.mkdtemp(prefix="fixture-tests-"))
atexit.register(shutil.rmtree, TMP, ignore_errors=True)

SMALL = {
    "users": 900,
    "days": 45,
    "seed": 42,
    "inject_bots": 250,
    "burst_count": 3,
    "events": 0.6,
    "password": "Fixture-Test-Pass-2026!",
}


def seed_db(name: str, **over) -> Path:
    opts = {**SMALL, **over}
    path = TMP / f"{name}.db"
    code = seed_main([
        "--users", str(opts["users"]), "--days", str(opts["days"]), "--seed", str(opts["seed"]),
        "--inject-bots", str(opts["inject_bots"]), "--burst-count", str(opts["burst_count"]),
        "--events", str(opts["events"]), "--db", str(path), "--fresh", "--quiet",
        "--test-password", opts["password"], "--hash-algo", "sha256_fast",
    ])
    assert code == 0, f"seeder exited {code}"
    return path


class RunningApi:
    """Boot the mock API on an ephemeral port against a fixture DB."""

    def __init__(self, db: Path, **cfg) -> None:
        self.cfg = Config(db=str(db), host="127.0.0.1", port=cfg.pop("port", 0), **cfg)
        self.httpd = build_server(self.cfg)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        host, port = self.httpd.server_address[0], self.httpd.server_address[1]
        host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> RunningApi:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
