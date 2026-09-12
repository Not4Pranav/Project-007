"""Tool settings for the console, persisted as one JSON file.

The file *is* the settings: `var/console.json` holds the same knobs the Makefile
variables hold (DB/USERS/DAYS/BOTS/SEED/STAGES/SLO/PORT) plus the mock API's own
`Config` fields, so there is one source of truth for "what does this tool default
to" and the Generator/Operational forms read it rather than keeping their own copy.

Validation lives here, not in the UI, because the console is also a JSON API and a
hand-typed request must be refused the same way a form value is.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import ClassVar

DEFAULT_DB = "var/test.db"
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,30}$")


class SettingsError(ValueError):
    """Raised with a human sentence; the console shows it inline rather than 500-ing."""


@dataclass
class Settings:
    # --- where the fixture lives
    db: str = DEFAULT_DB
    accounts_dir: str = "var/reports"
    # --- generator
    users: int = 4000
    days: int = 30
    seed: int = 42
    bots: int = 200
    servers: int = 6
    events: float = 1.0
    hash_algo: str = "sha256_fast"
    pbkdf2_iterations: int = 1200
    min_password_length: int = 10
    register_domain: str = "loadtest.invalid"
    test_password: str = "Fixture-Test-Pass-2026!"
    # "append" keeps the accounts already in the file and adds to them; "replace" truncates.
    # One knob, not a `fresh` bool next to it, so the two can never disagree.
    write_mode: str = "append"
    # --- the account list the operator edits by hand
    account_list: str = "var/accounts.txt"
    bootstrap_accounts: int = 5
    # --- targets
    api_port: int = 8000
    console_port: int = 8010
    # --- operational
    stages: str = "20,60:8"
    slo: str = "p95_ms=400,error_rate_pct=0.5"
    warmup_seconds: float = 1.0
    rate_limit_per_min: int = 240
    login_rate_limit_per_min: int = 0
    join_rate_limit_per_min: int = 600
    max_inflight: int = 256
    block_disposable: bool = False
    require_email_verify: bool = False
    latency_ms: float = 0.0
    unknown: dict[str, str] = field(default_factory=dict)

    # -------------------------------------------------------------- ranges
    # ClassVar, not a field: these are the validation rules, and a dataclass turns any
    # annotated mutable default into a per-instance field (which it then refuses).
    INT_RANGE: ClassVar[dict[str, tuple[int, int]]] = {
        "users": (1, 200_000), "days": (1, 3650), "bots": (0, 100_000), "servers": (0, 200),
        "min_password_length": (6, 64), "api_port": (1024, 65535), "console_port": (1024, 65535),
        "rate_limit_per_min": (0, 100_000), "login_rate_limit_per_min": (0, 100_000),
        "join_rate_limit_per_min": (0, 100_000), "max_inflight": (1, 4096),
        "bootstrap_accounts": (0, 100_000),
        "pbkdf2_iterations": (1, 1_000_000), "seed": (0, 2_147_483_647),
    }
    FLOAT_RANGE: ClassVar[dict[str, tuple[float, float]]] = {
        "events": (0.05, 5.0), "warmup_seconds": (0.0, 60.0), "latency_ms": (0.0, 2000.0),
    }
    CHOICES: ClassVar[dict[str, tuple[str, ...]]] = {
        "hash_algo": ("pbkdf2_sha256", "sha256_fast"),
    }

    def to_json_dict(self) -> dict:
        out = asdict(self)
        out.pop("unknown", None)
        return out

    @property
    def fresh(self) -> bool:
        """Read-only view of "this run truncates", kept because `--fresh` is the seeder's
        word for it. There is no writable `fresh` setting: `write_mode` is the knob."""
        return self.write_mode == "replace"

    def api_url(self) -> str:
        # Fixed to loopback on purpose: the console hands this to the load engine as
        # --base-url, and there is deliberately no field that lets it be anything else.
        return f"http://127.0.0.1:{self.api_port}"

    def base_argv(self) -> list[str]:
        """Seeder args for the current settings, shared by the generator job and its preview."""
        argv = ["--db", self.db, "--users", str(self.users), "--days", str(self.days),
                "--seed", str(self.seed), "--inject-bots", str(self.bots), "--servers", str(self.servers),
                "--events", str(self.events), "--hash-algo", self.hash_algo,
                "--pbkdf2-iterations", str(self.pbkdf2_iterations),
                "--min-password-length", str(self.min_password_length),
                # The generator seeds this password and the Operational tab logs in with it, so
                # the two cannot drift apart. Fixture-only secret; never leaves 127.0.0.1.
                "--test-password", self.test_password]
        argv.append("--append" if self.write_mode == "append" else "--fresh")
        return argv

    def server_config_kwargs(self) -> dict:
        return {
            "db": self.db, "port": self.api_port, "max_inflight": self.max_inflight,
            "rate_limit_per_min": self.rate_limit_per_min,
            "login_rate_limit_per_min": self.login_rate_limit_per_min,
            "join_rate_limit_per_min": self.join_rate_limit_per_min,
            "latency_ms": self.latency_ms, "block_disposable": self.block_disposable,
            "min_password_length": self.min_password_length,
            "require_email_verify": self.require_email_verify,
        }

    def load_argv(self) -> list[str]:
        """`load.engine` argv for a run against the console's own mock API."""
        return ["--base-url", self.api_url(), "--fixture-db", self.db, "--stages", self.stages,
                "--warmup-seconds", str(self.warmup_seconds), "--slo", self.slo,
                "--out", self.accounts_dir, "--accounts-file", "auto"]


def _coerce_int(name: str, value: object, lo: int, hi: int) -> int:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise SettingsError(f"{name} must be a whole number, got {value!r}") from None
    if not lo <= n <= hi:
        raise SettingsError(f"{name} must be between {lo:,} and {hi:,} (got {n:,})")
    return n


def _coerce_float(name: str, value: object, lo: float, hi: float) -> float:
    try:
        f = float(str(value).strip())
    except (TypeError, ValueError):
        raise SettingsError(f"{name} must be a number, got {value!r}") from None
    if not lo <= f <= hi:
        raise SettingsError(f"{name} must be between {lo} and {hi} (got {f})")
    return f


def safe_text_path(raw: object, *, field_name: str = "account_list") -> str:
    """Same scratch-directory rule as the database, for the roster and its exports: a
    hand-editable text file still should not be aimed at somebody's real config."""
    text = str(raw or "").strip()
    if not text:
        raise SettingsError(f"{field_name} must be a path, not empty")
    path = Path(text).expanduser()
    parts = {q.lower() for q in path.resolve().parts}
    if not {"var", "tmp", "tmpdirs"} & parts:
        raise SettingsError(f"{field_name} must live under a var/ or tmp directory, got {text}")
    if path.suffix not in (".txt", ".md", ".list"):
        raise SettingsError(f"{field_name} must be a .txt/.md list file, got {text}")
    if re.search(r"prod|live|production", path.name, re.I):
        raise SettingsError(f"{field_name} looks like a real credential file ({path.name}); refusing")
    return path.as_posix()


def safe_fixture_path(raw: object, *, field_name: str = "db") -> str:
    """Only a path under a scratch directory, and never something that smells like a
    real database. `seeds.seed` has the same rule for its --db; the console repeats it
    because it is the layer where a typed string becomes a file write."""
    text = str(raw or "").strip()
    if not text:
        raise SettingsError(f"{field_name} must be a path, not empty")
    path = Path(text).expanduser()
    # Judged on the resolved path, so `seeds/../real.db` cannot walk out of the scratch
    # dirs while still spelling like a relative path.
    parts = {p.lower() for p in path.resolve().parts}
    if not {"var", "tmp", "tmpdirs"} & parts:
        raise SettingsError(f"{field_name} must live under a var/ or tmp directory, got {text}")
    if path.suffix not in (".db", ".sqlite", ".sqlite3"):
        raise SettingsError(f"{field_name} must end in .db/.sqlite, got {text}")
    if re.search(r"prod|live|main[_-]db|production", path.name, re.I):
        raise SettingsError(f"{field_name} looks like a real database ({path.name}); refusing")
    return path.as_posix()


def validate(name: str, value: object) -> object:
    """One value, one rule. Public so the API layer can patch a single field."""
    spec = Settings()
    if name in Settings.INT_RANGE:
        lo, hi = Settings.INT_RANGE[name]
        return _coerce_int(name, value, lo, hi)
    if name in Settings.FLOAT_RANGE:
        lo, hi = Settings.FLOAT_RANGE[name]
        return _coerce_float(name, value, lo, hi)
    if name in Settings.CHOICES:
        text = str(value).strip()
        if text not in Settings.CHOICES[name]:
            raise SettingsError(f"{name} must be one of {', '.join(spec.CHOICES[name])}")
        return text
    if name in ("db", "accounts_dir"):
        return safe_fixture_path(value, field_name=name) if name == "db" else str(value)
    if name == "write_mode":
        text = str(value).strip().lower()
        if text not in ("append", "replace"):
            raise SettingsError("write_mode is 'append' (add to the accounts that already exist) "
                                "or 'replace' (truncate and rebuild) — got "
                                f"{value!r}")
        return text
    if name == "account_list":
        return safe_text_path(value)
    if name == "test_password":
        text = str(value)
        if not text.strip():
            raise SettingsError("test_password must not be empty — the generator seeds it and the "
                                "Operational tab logs in with it")
        if len(text) < 8:
            raise SettingsError(f"test_password must be at least 8 characters (got {len(text)})")
        return text
    if name == "register_domain":
        text = str(value).strip().lower()
        if not text.endswith((".invalid", ".test", ".example")):
            raise SettingsError("register_domain must be a reserved TLD (.invalid/.test/.example) "
                               "so a run can never mail a real mailbox")
        return text
    if name in ("stages", "slo"):
        text = str(value).strip()
        if name == "stages" and not re.fullmatch(r"[0-9]+(:[0-9.]+)?(,[0-9]+(:[0-9.]+)?){0,7}", text):
            raise SettingsError("stages must look like '20,60' or '25:10,100:30'")
        if name == "stages":
            # Shape alone lets `0:0` through, which the engine would dutifully run as a
            # no-op stage. Refusing here means the operator sees it in the tab, not in a log.
            for part in text.split(","):
                head, _, tail = part.partition(":")
                if int(head) < 1:
                    raise SettingsError(f"stages need at least 1 concurrent user (got {part!r})")
                if tail and float(tail) <= 0:
                    raise SettingsError(f"stage {part!r} has no duration")
        if name == "slo" and text:
            for chunk in text.split(","):
                key, sep, val = chunk.partition("=")
                if not sep or not val.replace(".", "", 1).isdigit():
                    raise SettingsError(f"slo entries look like p95_ms=250 (got {chunk!r})")
        return text
    declared = {f.name: f for f in fields(Settings)}
    if name not in declared:
        raise SettingsError(f"unknown setting {name!r}")
    # No explicit rule for this field: coerce on its declared type so that a saved file
    # always loads back. Without this, `seed` (an int with no range) was rejected on the
    # read path -- the first save wrote a settings file the console then refused to open.
    current = getattr(spec, name)
    if isinstance(current, bool):
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
        raise SettingsError(f"{name} must be true/false, got {value!r}")
    if isinstance(current, str):
        return str(value)
    if isinstance(current, float):
        return _coerce_float(name, value, -1e18, 1e18)
    if isinstance(current, int):
        return _coerce_int(name, value, -2_147_483_648, 2_147_483_647)
    return value


def apply_updates(current: Settings, patch: dict) -> Settings:
    """Returns a new Settings; unknown keys are kept in `unknown` so a stale tab's
    save can't silently drop a field another tab set."""
    data = current.to_json_dict()
    unknown = dict(current.unknown)  # copied, never mutated in place: callers keep theirs
    known = {f.name for f in fields(Settings)} - {"unknown"}
    for key, value in patch.items():
        if key not in known:
            # carried on the result so the UI can say "ignored", instead of a stale tab's
            # save quietly dropping a field another tab had set
            unknown[key] = "ignored (unknown setting)"
            continue
        data[key] = validate(key, value)
    out = Settings(**data)
    out.unknown = unknown
    return out


def load(path: Path) -> Settings:
    spec = Settings()
    if not path.exists():
        return spec
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SettingsError(f"{path} is unreadable ({exc.__class__.__name__}); fix or delete it") from None
    if not isinstance(raw, dict):
        raise SettingsError(f"{path} must contain a JSON object")
    if "fresh" in raw:
        # An older settings file wrote a `fresh` bool. Honour it as the mode it meant
        # rather than quietly flipping an operator from "replace" to "append".
        wanted = "replace" if str(raw.pop("fresh")).strip().lower() in ("1", "true", "yes", "on") else "append"
        raw.setdefault("write_mode", wanted)
    data: dict = {}
    for key, value in raw.items():
        if key not in {f.name for f in fields(Settings)} - {"unknown"}:
            spec.unknown[key] = "ignored (unknown setting)"
            continue
        try:
            data[key] = validate(key, value)
        except SettingsError:
            raise SettingsError(f"{path}: {key} is invalid — fix the file or delete it") from None
    return Settings(**{**asdict(spec), **data})


def save(path: Path, settings: Settings) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings.to_json_dict(), indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)  # holds test_password, the one login secret in this file
    return path
