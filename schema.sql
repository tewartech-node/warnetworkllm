-- ServTech — D1 schema.
--
-- This mirrors the schema that is live on the production servtech-d1
-- database. It has been renamed twice on its way here — originally applied
-- under warnetworkllm-db, then servtechdb, now servtech-d1 — each move was
-- a straight schema re-apply against an empty database, never a data
-- migration. Keep this file and the live database in sync going forward:
-- if you change one, change the other the same way.
--
-- Idempotent: CREATE ... IF NOT EXISTS is safe to run repeatedly. The one
-- exception is the `uploads.kind` CHECK constraint below, which was
-- tightened from ('image','audio','video','document','text') to
-- ('image','document','text') to remove audio/video upload — SQLite can't
-- ALTER a CHECK constraint in place, so that change was applied with a
-- DROP + CREATE against the (empty) production table directly.

CREATE TABLE IF NOT EXISTS users (
  id                     INTEGER PRIMARY KEY AUTOINCREMENT,
  username               TEXT NOT NULL UNIQUE,
  email                  TEXT NOT NULL UNIQUE,
  password_hash          TEXT NOT NULL,
  created_at             TEXT NOT NULL DEFAULT (datetime('now')),
  last_login_at          TEXT,
  privacy_notice_version TEXT NOT NULL DEFAULT '2026-07-26',
  privacy_accepted_at    TEXT NOT NULL DEFAULT (datetime('now')),
  locked_until           TEXT,
  is_disabled            INTEGER NOT NULL DEFAULT 0
);

-- Sessions store a hash of the session token, never the token itself, so a
-- read of this table can't be replayed as a live cookie.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  ip_hash    TEXT,
  user_agent TEXT
);

-- One row per attempt at a throttled action. Rate limiting counts rows in
-- `bucket` newer than the window cutoff, then inserts the current attempt —
-- see security.ts::rateLimit. Old rows are swept by the retention cron.
CREATE TABLE IF NOT EXISTS auth_attempts (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket TEXT NOT NULL,
  at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_bucket ON auth_attempts(bucket, at);

CREATE TABLE IF NOT EXISTS messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
  content    TEXT NOT NULL,
  media_id   INTEGER REFERENCES uploads(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id, id);

CREATE TABLE IF NOT EXISTS memories (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  fact       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_memories_user ON memories(user_id);

CREATE TABLE IF NOT EXISTS shared_knowledge (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  insight        TEXT NOT NULL,
  source_session TEXT,
  hits           INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- kind is constrained to 'image', 'document' (PDF — stored, not parsed), or
-- 'text' (read directly). 'audio' and 'video' were removed on purpose: no
-- accept type offers them client-side, and detect() in uploads.ts rejects
-- anything it doesn't recognise by file signature regardless of what the
-- client claims, so this CHECK is a second, independent enforcement layer.
CREATE TABLE IF NOT EXISTS uploads (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  r2_key      TEXT NOT NULL UNIQUE,
  filename    TEXT NOT NULL,
  mime        TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('image', 'document', 'text')),
  bytes       INTEGER NOT NULL,
  sha256      TEXT,
  extracted   TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  purge_after TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(user_id);
CREATE INDEX IF NOT EXISTS idx_uploads_purge ON uploads(purge_after);

-- Support/feedback/privacy/breach reports. email_status stays
-- 'not_configured' — there is no transactional email provider wired up in
-- this deployment, so tickets are read directly from this table rather
-- than promising a send that will never happen.
CREATE TABLE IF NOT EXISTS support_tickets (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ref          TEXT NOT NULL UNIQUE,
  user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  category     TEXT NOT NULL,
  reply_to     TEXT NOT NULL,
  subject      TEXT NOT NULL,
  body         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'open',
  email_status TEXT NOT NULL DEFAULT 'not_configured',
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  action     TEXT NOT NULL,
  detail     TEXT,
  ip_hash    TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
