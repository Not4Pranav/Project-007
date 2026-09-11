from __future__ import annotations

import datetime as dt
import hashlib
import hmac
from dataclasses import dataclass
from datetime import date

from . import corpus
from .distribution import Cohort, verify_delay_seconds
from .rng import Rng

SYMBOLS = "!@#$%&*"


@dataclass(slots=True)
class UserProfile:
    username: str
    email: str
    email_domain: str
    display_name: str
    dob: str
    country: str
    region: str
    timezone: str
    locale: str
    signup_ts: int
    signup_ip: str
    signup_ua: str
    device_class: str
    source: str
    status: str
    verified_ts: int | None
    password_hash: bytes
    password_salt: bytes
    password_algo: str
    password_iterations: int
    has_phone: int
    newsletter: int
    bio: str
    avatar_seed: str


@dataclass(frozen=True)
class PasswordPolicy:
    """Mirror whatever your app enforces; the fixture should not be laxer."""

    min_length: int = 10
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = False

    def sample(self, rng: Rng) -> str:  # a password that satisfies the policy
        lower = "abcdefghjkmnpqrstuvwxyz"
        upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        digits = "23456789"
        symbols = SYMBOLS
        body = [rng.pick(lower) for _ in range(max(0, self.min_length - 2))]
        if self.require_digit:
            body.append(rng.pick(digits))
        if self.require_upper:
            body.append(rng.pick(upper))
        if self.require_symbol:
            body.append(rng.pick(symbols))
        extra = self.min_length + rng.int(0, 4) - len(body)
        body += [rng.pick(lower + digits) for _ in range(max(0, extra))]
        rng.raw.shuffle(body)
        return "".join(body)

    def is_valid(self, pw: str) -> bool:
        """Pass/fail only. The mock API reports which rule failed per field; this
        is the fixture-side check."""
        return (
            len(pw) >= self.min_length
            and (not self.require_upper or any(c.isupper() for c in pw))
            and (not self.require_digit or any(c.isdigit() for c in pw))
            and (not self.require_symbol or any(c in SYMBOLS for c in pw))
        )


def derive(algo: str, password: str, salt: bytes, iterations: int) -> bytes:
    """`pbkdf2_sha256` mirrors production semantics; `sha256_fast` exists so a
    200k-account run does not spend 20 minutes on KDF work alone. Both are
    recorded per user, so a login path that reads `credentials.algo` verifies
    either - which is also how you would test a hash-algo migration."""
    if algo == "sha256_fast":
        return hashlib.sha256(salt + password.encode()).digest()
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def verify_password(algo: str, password: str, salt: bytes, expected: bytes, iterations: int) -> bool:
    return hmac.compare_digest(derive(algo, password, salt, iterations), expected)


def _normalize(s: str) -> str:
    out = []
    for ch in s.lower():
        if ch.isalnum() or ch in "._-":
            out.append(ch)
    s = "".join(out)
    while s and s[0] in "._-":
        s = s[1:]
    while s and s[-1] in "._-":
        s = s[:-1]
    return s


def make_username(rng: Rng, style: str, seq: int, first: str, last: str) -> str:
    adj = str(rng.pick(corpus.ADJECTIVES))
    noun = str(rng.pick(corpus.NOUNS))
    if style == "first.last.num":
        base = f"{first.lower()}.{last.lower()}{rng.int(1, 99)}"
    elif style == "adjective_noun_num":
        sep = str(rng.pick(["_", ".", "", "-"]))
        base = f"{adj}{sep}{noun}{rng.int(1, 999)}"
    elif style == "handle":
        base = f"{adj}{noun}" if rng.chance(0.5) else f"{first.lower()}{noun[:4]}{rng.int(0, 9)}"
    elif style == "initial_last_num":
        base = f"{first[0].lower()}{last.lower()}{rng.int(1, 9999)}"
    elif style == "nickname_repeat":
        nick = first.lower()
        base = f"{nick}-{nick}" if rng.chance(0.5) else f"{nick}.{nick}{rng.int(2, 99)}"
    elif style == "name_year":
        base = f"{first.lower()}{rng.int(1975, 2009)}"
    elif style == "bot_sequential":
        tpl = str(rng.pick(corpus.BOT_USERNAME_TEMPLATES))
        base = tpl.format(seq=f"{seq:05d}")
    else:
        base = f"{first.lower()}{last.lower()}"
    return _normalize(base)[: 24 if len(base) > 24 else len(base)] or f"user{seq}"


def make_email_local(rng: Rng, username: str, first: str, last: str) -> str:
    r = rng.raw.random()
    if r < 0.42:
        local = username
    elif r < 0.62:
        local = f"{first.lower()}.{last.lower()}"
    elif r < 0.74:
        local = f"{first.lower()}{last.lower()[:rng.int(2, 5)]}{rng.int(1, 999)}"
    elif r < 0.86:
        local = username + str(rng.int(1, 99))
    else:
        local = f"{first.lower()}{rng.int(10, 99)}"
    if rng.chance(0.06):  # plus-addressing: real behaviour, breaks naive dedupe
        local += f"+{rng.pick(['news', 'app', 'signup', 'discord', str(rng.int(100, 999))])}"
    return _normalize(local).replace("-", ".")


def _display_name(rng: Rng, first: str, last: str, username: str) -> str:
    roll = rng.raw.random()
    if roll < 0.25:
        return f"{first} {last[0]}."
    if roll < 0.95:
        return f"{first} {last}"
    return username


def make_bio(rng: Rng) -> str:
    tpl = str(rng.pick(corpus.BIO_TEMPLATES))
    return tpl.format(
        adj=rng.pick(corpus.ADJECTIVES),
        noun=rng.pick(corpus.NOUNS),
        lang=rng.pick(corpus.LANGUAGES),
    )


def make_ip(rng: Rng, prefix_pool: list[str]) -> str:
    """Residential-ish spread: most users get a fresh /24, some reuse one."""
    pool = prefix_pool
    if pool and rng.chance(0.12):
        a, b, c = rng.pick(pool)
    else:
        a = rng.int(11, 223)
        b = rng.int(0, 255)
        c = rng.int(0, 255)
    return f"{a}.{b}.{c}.{rng.int(1, 254)}"


def make_dob(rng: Rng, min_age: int = 13, max_age: int = 78) -> str:
    """Age floor matters: 13 is the compliance line for consumer products.

    We emit it as a real date so you can test your own age gate, but never as
    an ID anyone could plausibly use.
    """
    today = date(2026, 9, 11)
    age = rng.int(min_age, max_age)
    # Derive from a day count, not `today.year - age` + a random month/day:
    # the naive form lands 13-year-olds on a not-yet-reached birthday, i.e. 12.
    birth = today - dt.timedelta(days=int(age * 365.25) + rng.int(0, 365))
    return birth.isoformat()


def build_profile(
    rng: Rng,
    *,
    seq: int,
    signup_ts: int,
    cohort: Cohort,
    taken_usernames: set[str],
    taken_emails: set[str],
    ip_prefix_pool: list[str],
    policy: PasswordPolicy,
    password: str,
    algo: str = "pbkdf2_sha256",
    iterations: int = 1_200,
    bot: bool = False,
) -> tuple[UserProfile, str]:
    """Generate one profile. Returns (profile, plaintext_password_or_empty).

    Plaintext is returned only so the caller can decide to hand out a single
    shared fixture password; it is never written into the database.
    """
    first = str(rng.pick(corpus.FIRST_NAMES))
    last = str(rng.pick(corpus.LAST_NAMES))

    if bot:
        style = "bot_sequential"
    else:
        style = str(rng.raw.choices(
            list(cohort.username_styles) or ["handle"],
            weights=list(cohort.username_styles.values()) or [1],
        )[0])

    username = make_username(rng, style, seq, first, last)
    attempt = 0
    while username in taken_usernames:
        attempt += 1
        username = f"{make_username(rng, style, seq, first, last)[:20]}{attempt}{rng.int(10, 99)}"
    taken_usernames.add(username)

    if bot and rng.chance(0.7) or cohort.domain_bias > 0 and rng.chance(cohort.domain_bias):
        domain = str(rng.pick(sorted(corpus.DISPOSABLE_DOMAINS)))
    else:
        domain = str(rng.weighted([(d, w) for d, w, free in corpus.EMAIL_DOMAINS if free]))

    local = make_email_local(rng, username, first, last)
    email = f"{local}@{domain}"
    attempt = 0
    while email in taken_emails:
        attempt += 1
        email = f"{local}{rng.int(1000, 9999)}@{domain}"
    taken_emails.add(email)

    region = rng.weighted([(r, r[5]) for r in corpus.REGIONS])
    assert isinstance(region, tuple)
    country, region_name, tz, _offset, locale, _w = region  # type: ignore[misc]

    if bot:
        ua = corpus.BOT_USER_AGENT
        device = "desktop"
        status = "pending_verification" if rng.chance(0.25) else "active"
        verified_ts = signup_ts + rng.int(0, 4)  # instant verify: automation tell
        has_phone = 0
    else:
        ua = str(rng.weighted(corpus.USER_AGENTS))
        device = str(rng.weighted(corpus.DEVICE_CLASSES))
        r = rng.raw.random()
        status = ("active" if r < 0.86 else "pending_verification" if r < 0.94 else
                  "suspended" if r < 0.985 else "deleted")
        delay = verify_delay_seconds(rng, cohort.verify_delay_mu)
        verified_ts = None if status == "pending_verification" else signup_ts + delay
        has_phone = 1 if rng.chance(0.34) else 0

    if bot:
        signup_ip = f"{ip_prefix_pool[0][0]}.{ip_prefix_pool[0][1]}.{ip_prefix_pool[0][2]}.{rng.int(1, 254)}"
    else:
        signup_ip = make_ip(rng, ip_prefix_pool)

    salt = bytes(rng.raw.getrandbits(8) for _ in range(16))
    pw = password if password else policy.sample(rng)
    profile = UserProfile(
        username=username,
        email=email,
        email_domain=domain,
        display_name=_display_name(rng, first, last, username),
        dob=make_dob(rng),
        country=country,
        region=region_name,
        timezone=tz,
        locale=locale,
        signup_ts=signup_ts,
        signup_ip=signup_ip,
        signup_ua=ua,
        device_class=device,
        source=("campaign" if bot else str(rng.weighted(corpus.SOURCES))),
        status=status,
        verified_ts=verified_ts,
        password_hash=derive(algo, pw, salt, iterations),
        password_salt=salt,
        password_algo=algo,
        password_iterations=iterations,
        has_phone=has_phone,
        newsletter=1 if rng.chance(0.28) else 0,
        bio=make_bio(rng),
        avatar_seed=rng.hex_id(6),
    )
    return profile, pw
