-- Termoso local database. Every value that is not needed for routing is
-- ciphertext: entity payloads are encrypted with their vault key (exactly the
-- envelope the server stores), vault keys and account material are wrapped
-- with the device master key that lives in the OS keychain.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,           -- local | personal | team
    name        TEXT NOT NULL,
    team_id     TEXT,
    role        TEXT NOT NULL,           -- manager | editor | viewer
    wrapped_key TEXT,                    -- vault key wrapped with the master key; NULL = pending
    key_version INTEGER NOT NULL DEFAULT 1,
    cursor      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    session_logging INTEGER NOT NULL DEFAULT 0, -- team vault: record every member's sessions
    logs_cursor INTEGER NOT NULL DEFAULT 0,     -- GET /vaults/{id}/logs cursor (team vaults)
    is_default  INTEGER NOT NULL DEFAULT 0      -- team's first vault: undeletable
);

CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL DEFAULT 0,   -- server version, 0 = never pushed
    seq         INTEGER NOT NULL DEFAULT 0,
    deleted     INTEGER NOT NULL DEFAULT 0,
    key_version INTEGER NOT NULL,
    data        TEXT NOT NULL,                -- envelope, AAD termoso/v1/entity/<kind>/<id>
    updated_at  TEXT NOT NULL,
    dirty       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS entities_vault_kind ON entities (vault_id, kind);
CREATE INDEX IF NOT EXISTS entities_dirty ON entities (dirty) WHERE dirty = 1;

CREATE TABLE IF NOT EXISTS history (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,                -- command | connection
    vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    data        TEXT NOT NULL,                -- envelope, AAD termoso/v1/history/<kind>/<id>
    key_version INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    seq         INTEGER NOT NULL DEFAULT 0,
    deleted     INTEGER NOT NULL DEFAULT 0,
    dirty       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS history_kind_created ON history (kind, created_at DESC);

CREATE TABLE IF NOT EXISTS account (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    server_url          TEXT NOT NULL,
    user_id             TEXT NOT NULL,
    email               TEXT NOT NULL,
    display_name        TEXT,
    is_admin            INTEGER NOT NULL DEFAULT 0,
    device_id           TEXT NOT NULL,
    token               TEXT NOT NULL,        -- session token wrapped with the master key
    public_key          TEXT NOT NULL,
    wrapped_private_key TEXT NOT NULL,        -- account private key wrapped with the master key
    key_version         INTEGER NOT NULL,
    history_cursor      INTEGER NOT NULL DEFAULT 0,
    logs_cursor         INTEGER NOT NULL DEFAULT 0,
    signed_in_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_logs (
    id           TEXT PRIMARY KEY,
    vault_id     TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    meta         TEXT NOT NULL,               -- envelope, AAD termoso/v1/log/<id>
    key_version  INTEGER NOT NULL,
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    local_path   TEXT,                        -- plaintext-on-disk copy is never written; this is the encrypted file
    uploaded     INTEGER NOT NULL DEFAULT 0,
    completed    INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    seq          INTEGER NOT NULL DEFAULT 0,
    deleted      INTEGER NOT NULL DEFAULT 0,
    author_id    TEXT,                          -- NULL = recorded on this device by this account
    author       TEXT,                          -- JSON LogAuthor (plaintext profile, no secrets)
    pinned       INTEGER NOT NULL DEFAULT 0,
    note         TEXT NOT NULL DEFAULT '',
    note_by      TEXT
);

-- Offline copies of remote files (SFTP). Content is an encrypted file on
-- disk (vault key, AAD termoso/v1/fcache/<host>/<path>); the index below is
-- device-local and never synced. Populated only when a file is read.
CREATE TABLE IF NOT EXISTS file_cache_config (
    host_id      TEXT PRIMARY KEY,
    config       TEXT NOT NULL                -- JSON FileCacheConfig
);

CREATE TABLE IF NOT EXISTS file_cache (
    host_id      TEXT NOT NULL,
    vault_id     TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    kind         TEXT NOT NULL,               -- file | dir
    size         INTEGER NOT NULL,            -- remote size (file) / entry count (dir)
    mtime        INTEGER,                     -- remote mtime, unix seconds
    cached_at    TEXT NOT NULL,
    last_used    TEXT NOT NULL,
    local_path   TEXT NOT NULL,               -- encrypted body on disk
    bytes        INTEGER NOT NULL,            -- size of the encrypted body
    PRIMARY KEY (host_id, path)
);
CREATE INDEX IF NOT EXISTS file_cache_lru ON file_cache(host_id, last_used);
