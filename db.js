const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// Where the SQLite file lives. Defaults to ./data. On a host with a persistent volume (Railway)
// set DATA_DIR to the volume's mount path so the database survives redeploys, e.g. DATA_DIR=/data
const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'voicelink.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
// Overwrite deleted content with zeros so permanently deleted posts don't linger in free pages.
db.pragma('secure_delete = ON');

db.exec(`
  -- Roles: admin, council (staff: username + password, no grade/section),
  --        president, student (name + grade + section + password; account_key covers this).
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_key TEXT UNIQUE,
    username TEXT UNIQUE,
    name TEXT NOT NULL,
    grade TEXT,
    section TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'president', 'council', 'admin')),
    token_version INTEGER NOT NULL DEFAULT 0,  -- bumped on password change; invalidates every existing login token
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    anon INTEGER NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    grade TEXT NOT NULL,
    section TEXT NOT NULL,
    status TEXT CHECK (status IN ('in_review', 'planned', 'resolved')),
    is_archived INTEGER NOT NULL DEFAULT 0,  -- 1 = soft-deleted: hidden from the feed, visible only in the Archive
    deleted_at TEXT,                         -- when it was archived
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Which post is pinned is tracked in the settings table (key 'pinned_post_id'),
  -- not on the post row, since only one post is ever pinned at a time.

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS stars (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, post_id)
  );

  CREATE TABLE IF NOT EXISTS bookmarks (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, post_id)
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_posts_grade_section ON posts (grade, section);
  CREATE INDEX IF NOT EXISTS idx_comments_post ON comments (post_id);
`);

// ---- Auto-migrations ------------------------------------------------------
// Runs on every startup, right after the connection is opened and BEFORE any route file
// can query the database. Every step is idempotent: on a fresh database, an already-upgraded
// database, or a restart, it does nothing. Older production databases (e.g. on a Railway
// volume) get upgraded in place, with their data kept.

// Adds a column only if it's missing. The ALTER is wrapped in try/catch so that a
// "duplicate column name" error (two processes starting at once, or the column existing
// in a form the check didn't see) is ignored. Any OTHER error is rethrown on purpose:
// failing loudly at startup is better than the server booting and answering every login
// with "Something went wrong on our end."
function addColumnIfMissing(table, column, definition) {
  const exists = db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
  if (exists) return;
  try {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    console.log(`[db] migrated: added ${table}.${column}`);
  } catch (e) {
    if (/duplicate column name/i.test(String(e && e.message))) return; // already there: fine
    throw e;
  }
}

// 1) users.role used CHECK (role IN ('student','manager')). SQLite can't alter a
//    CHECK constraint, so rebuild the table (SQLite's documented procedure) and
//    map every legacy 'manager' to 'admin'. Foreign keys must be OFF during the
//    swap, otherwise DROP TABLE would cascade-delete every post/comment/star.
function migrateUsersRoles() {
  const row = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").get();
  if (!row || row.sql.includes("'admin'")) return; // fresh DB, or already on the new schema

  const hasTokenVersion = db.prepare('PRAGMA table_info(users)').all().some(c => c.name === 'token_version');
  const tv = hasTokenVersion ? ', token_version' : '';

  db.pragma('foreign_keys = OFF');
  try {
    db.transaction(() => {
      db.exec(`
        CREATE TABLE users_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_key TEXT UNIQUE,
          username TEXT UNIQUE,
          name TEXT NOT NULL,
          grade TEXT,
          section TEXT,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'president', 'council', 'admin')),
          token_version INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        INSERT INTO users_new (id, account_key, username, name, grade, section, password_hash, role, created_at${tv})
          SELECT id, account_key, username, name, grade, section, password_hash,
                 CASE role WHEN 'manager' THEN 'admin' ELSE role END, created_at${tv}
          FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
      `);
      console.log("[db] migrated: users.role now supports admin/council/president (old 'manager' -> 'admin')");
    })();
  } finally {
    db.pragma('foreign_keys = ON');
  }
}

migrateUsersRoles();

// 2) Session invalidation: JWTs carry the user's token_version; changing the password bumps it,
//    which makes every previously issued token (on every device) stop working.
//    (NOT NULL DEFAULT 0 so existing rows become 0 and a NULL can never appear.)
addColumnIfMissing('users', 'token_version', 'INTEGER NOT NULL DEFAULT 0');

// 3) Status badge (In Review / Planned / Resolved).
addColumnIfMissing('posts', 'status', "TEXT CHECK (status IN ('in_review', 'planned', 'resolved'))");

// 4) Archiving: posts are soft-deleted (is_archived = 1, deleted_at = when) instead of removed.
addColumnIfMissing('posts', 'is_archived', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('posts', 'deleted_at', 'TEXT');
db.exec('CREATE INDEX IF NOT EXISTS idx_posts_archived ON posts (is_archived)');

// 5) Anonymous-author access. Admins can always see who wrote an anonymous post; a council member can
//    only if an admin has set can_see_anon = 1 on their account. Every lookup is written to anon_reveals.
addColumnIfMissing('users', 'can_see_anon', 'INTEGER NOT NULL DEFAULT 0');
db.exec(`
  CREATE TABLE IF NOT EXISTS anon_reveals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,                       -- no FK on purpose: the log outlives a purged post
    viewer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revealed_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// 5) Safety net: if a required column still isn't there, stop now with a clear message
//    instead of booting and failing on every login.
(function verifySchema() {
  const need = { users: ['token_version', 'role', 'can_see_anon'], posts: ['status', 'is_archived', 'deleted_at'] };
  for (const [table, cols] of Object.entries(need)) {
    const have = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
    const missing = cols.filter(c => !have.includes(c));
    if (missing.length) throw new Error(`Database schema is missing ${table}.${missing.join(', ')} — migration failed.`);
  }
})();

module.exports = db;
