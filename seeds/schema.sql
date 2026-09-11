PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- structure
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    email_domain  TEXT    NOT NULL,
    display_name  TEXT,
    dob           TEXT    NOT NULL,
    country       TEXT    NOT NULL,
    region        TEXT,
    timezone      TEXT,
    locale        TEXT,
    signup_ts     INTEGER NOT NULL,          -- epoch seconds, UTC
    signup_ip     TEXT    NOT NULL,
    signup_ua     TEXT,
    device_class  TEXT,
    source        TEXT,
    invited_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status        TEXT    NOT NULL,          -- active|pending_verification|suspended|deleted
    verified_ts   INTEGER,
    has_phone     INTEGER NOT NULL DEFAULT 0,
    newsletter    INTEGER NOT NULL DEFAULT 0,
    bio           TEXT,
    avatar_seed   TEXT,
    is_synthetic_abuse INTEGER NOT NULL DEFAULT 0   -- fixture-only ground truth label
);

CREATE TABLE IF NOT EXISTS credentials (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    algo       TEXT    NOT NULL,             -- pbkdf2_sha256
    salt       BLOB    NOT NULL,
    iterations INTEGER NOT NULL,
    hash       BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token        TEXT    NOT NULL UNIQUE,
    ip           TEXT,
    ua           TEXT,
    device_class TEXT,
    created_ts   INTEGER NOT NULL,
    last_seen_ts INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ts      INTEGER NOT NULL,
    kind    TEXT    NOT NULL,   -- login|message|post|comment|reaction|profile_update|logout
    weight  INTEGER NOT NULL DEFAULT 1,
    ip      TEXT,
    meta    TEXT
);

CREATE TABLE IF NOT EXISTS invite_edges (
    inviter INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invitee INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ts      INTEGER NOT NULL,
    PRIMARY KEY (invitee)
);

-- ------------------------------------------------------------------- flags
-- Written by `python -m abuse.detector`; deliberately generic so you can join
-- it against your own moderation queue instead of a vendor-specific schema.
CREATE TABLE IF NOT EXISTS flags (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule     TEXT    NOT NULL,
    score    REAL    NOT NULL,
    detail   TEXT,
    run_ts   INTEGER NOT NULL,
    PRIMARY KEY (user_id, rule)
);

-- --------------------------------------------------------------- servers
-- Membership is a first-class table so "these 400 test accounts joined that server"
-- is something the fixture can answer with a query. `left_ts` makes the lifecycle
-- (join / leave / rejoin) representable; `capacity` exists so the "server full"
-- rejection path is reachable in a load run instead of theoretical.
CREATE TABLE IF NOT EXISTS servers (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    slug       TEXT    NOT NULL UNIQUE,
    created_ts INTEGER NOT NULL,
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capacity   INTEGER,
    private    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS memberships (
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_ts  INTEGER NOT NULL,
    left_ts    INTEGER,
    role       TEXT    NOT NULL DEFAULT 'member',
    source     TEXT    NOT NULL DEFAULT 'app',
    PRIMARY KEY (server_id, user_id)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ----------------------------------------------------------------- indexes
CREATE INDEX IF NOT EXISTS idx_users_signup_ts   ON users(signup_ts);
CREATE INDEX IF NOT EXISTS idx_users_domain      ON users(email_domain);
CREATE INDEX IF NOT EXISTS idx_users_ip          ON users(signup_ip);
-- The login path looks identifiers up case-insensitively. Without these
-- expression indexes, `WHERE lower(email) = ?` is a full scan of the users
-- table: the load engine measured p50 1558ms before, 1.4ms after.
CREATE INDEX IF NOT EXISTS idx_users_email_lc    ON users(lower(email));
CREATE INDEX IF NOT EXISTS idx_users_username_lc ON users(lower(username));
CREATE INDEX IF NOT EXISTS idx_users_status      ON users(status);
CREATE INDEX IF NOT EXISTS idx_events_user_ts    ON events(user_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts_kind    ON events(ts, kind);
-- Partial index for the two kinds the feed reads, in the feed's sort order.
-- Without it SQLite sorts a 1.6M-row set per request instead of walking a tree.
CREATE INDEX IF NOT EXISTS idx_events_feed        ON events(ts DESC, id DESC) WHERE kind IN ('post','message');
CREATE INDEX IF NOT EXISTS idx_sessions_user     ON sessions(user_id, last_seen_ts);
CREATE INDEX IF NOT EXISTS idx_flags_score       ON flags(score);
-- Live membership list per server, in join order (keyset, like the feed).
CREATE INDEX IF NOT EXISTS idx_memberships_server ON memberships(server_id, joined_ts, user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user   ON memberships(user_id, joined_ts);
