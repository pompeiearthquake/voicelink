const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { GRADE_SECTIONS, LIMITS } = require('../config');
const { accountKey, setSessionCookie, clearSessionCookie, requireAuth } = require('../middleware/auth');
const { evaluateText } = require('../filter');

// Secrets: this file contains none. JWT signing uses process.env.JWT_SECRET
// (read and enforced in src/middleware/auth.js, which exits at startup if it's missing).
// Session cookies are issued by setSessionCookie() in that same file.

const router = express.Router();

// Auth responses contain account data — never let a browser or proxy cache them.
router.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// ---- Rate limiting ------------------------------------------------------
// (server.js sets `trust proxy`, so these key on the real client IP on Railway/Render.)

function limiter(windowMinutes, max, message, extra = {}) {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message },
    ...extra
  });
}

// Per client IP: login + signup attempts.
const authLimiter = limiter(15, 20, 'Too many attempts. Try again in a bit.');

// Per ACCOUNT (name + grade + section) on login: stops a botnet spreading guesses
// over many IPs against one student. Successful logins don't count against it.
const loginAccountLimiter = limiter(15, 10, 'Too many failed logins for that account. Try again later.', {
  skipSuccessfulRequests: true,
  keyGenerator: req => {
    const b = req.body || {};
    return 'acct:' + accountKey(b.name ?? '', b.grade ?? '', b.section ?? '').slice(0, 200);
  }
});

const profileLimiter = limiter(15, 30, 'Too many profile changes. Try again in a bit.');
const sessionLimiter = limiter(5, 120, 'Too many requests. Slow down a little.');

// Password changes: per IP, and per logged-in user for FAILED attempts (guessing the
// current password from a hijacked session shouldn't be unlimited).
const passwordIpLimiter = limiter(15, 20, 'Too many password attempts. Try again in a bit.');
const passwordUserLimiter = limiter(15, 8, 'Too many failed password attempts. Try again later.', {
  skipSuccessfulRequests: true,
  keyGenerator: req => 'pw:' + (req.user ? req.user.id : 'anon')
});

// ---- Input hygiene ------------------------------------------------------

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,40}$/;
const USERNAME_RULE = 'Username must be 3-40 characters: letters, numbers, dots, dashes, underscores.';
const STAFF_ROLES = ['admin', 'council'];
const PASSWORD_MAX_BYTES = 72; // bcrypt silently ignores anything past 72 bytes
const NAME_FORBIDDEN = /[<>]/;

// Names are stored as plain text and ALWAYS HTML-escaped when rendered (the front end
// does this; the API only ever returns JSON). On top of that, normalise them here so
// they can't smuggle in invisible or look-alike characters:
//  - Unicode NFC normalisation
//  - whitespace collapsed to single spaces
//  - control characters, zero-width characters and bidi-override characters removed
function cleanName(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .normalize('NFC')
    .replace(/\s+/g, ' ')
    .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function validGradeSection(grade, section) {
  const sections = GRADE_SECTIONS[grade];
  return Array.isArray(sections) && sections.includes(section);
}

function passwordTooLong(password) {
  return Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES;
}

// Compared against when no account matches, so a wrong name and a wrong password
// take the same time (otherwise response timing reveals which accounts exist).
const DUMMY_HASH = bcrypt.hashSync('voicelink-timing-equaliser', 12);

// Shape returned to the client for any user. `name` and `display_name` are the
// same value (the users.name column); both are sent so old and new client code work.
function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    display_name: u.name,
    username: u.username || null,
    grade: u.grade || null,
    section: u.section || null,
    role: u.role,
    // admins always; council only when an admin has allowed it (see managers.js)
    canSeeAnon: u.role === 'admin' || (u.role === 'council' && u.can_see_anon === 1)
  };
}

// ---- Routes -------------------------------------------------------------

// Creating an account requires explicitly agreeing to the Terms of Service &
// Privacy Policy: the client must send agreedToTerms: true (a real boolean —
// the strings "true"/"yes" or any other truthy value are rejected).
router.post('/signup', authLimiter, (req, res) => {
  let { name, grade, section, password, agreedToTerms } = req.body || {};
  name = cleanName(name);
  grade = typeof grade === 'string' ? grade.trim() : '';
  section = typeof section === 'string' ? section.trim() : '';
  password = typeof password === 'string' ? password : '';

  if (!name || !grade || !section || !password) {
    return res.status(400).json({ error: 'Fill in every field.' });
  }
  if (agreedToTerms !== true) {
    return res.status(400).json({ error: 'You need to agree to the Terms of Service & Privacy Policy to create an account.' });
  }
  if (name.length > LIMITS.nameMax) {
    return res.status(400).json({ error: `Name must be under ${LIMITS.nameMax} characters.` });
  }
  if (NAME_FORBIDDEN.test(name)) {
    return res.status(400).json({ error: 'Names can\'t contain < or >.' });
  }
  if (evaluateText(name).blocked) {
    return res.status(400).json({ error: 'Please use an appropriate name.' });
  }
  if (!validGradeSection(grade, section)) {
    return res.status(400).json({ error: 'Pick a valid grade and section.' });
  }
  if (password.length < LIMITS.passwordMin) {
    return res.status(400).json({ error: `Password needs to be at least ${LIMITS.passwordMin} characters.` });
  }
  if (passwordTooLong(password)) {
    return res.status(400).json({ error: `Password is too long (${PASSWORD_MAX_BYTES} bytes max).` });
  }

  const key = accountKey(name, grade, section);
  const existing = db.prepare('SELECT id FROM users WHERE account_key = ?').get(key);
  if (existing) {
    return res.status(409).json({ error: 'An account already exists for that name, grade, and section.' });
  }

  const passwordHash = bcrypt.hashSync(password, 12);
  let info;
  try {
    info = db.prepare(`
      INSERT INTO users (account_key, name, grade, section, password_hash, role)
      VALUES (?, ?, ?, ?, ?, 'student')
    `).run(key, name, grade, section, passwordHash);
  } catch (e) {
    // Two simultaneous signups for the same name: the UNIQUE constraint catches the loser.
    if (e && String(e.code).startsWith('SQLITE_CONSTRAINT')) {
      return res.status(409).json({ error: 'An account already exists for that name, grade, and section.' });
    }
    throw e;
  }

  const user = { id: info.lastInsertRowid, name, grade, section, role: 'student' };
  setSessionCookie(res, user);
  res.status(201).json({ user: { id: user.id, name, grade, section, role: 'student' } });
});

router.post('/login', authLimiter, loginAccountLimiter, (req, res) => {
  let { name, grade, section, password } = req.body || {};
  const rawName = typeof name === 'string' ? name.trim() : '';
  name = cleanName(name);
  grade = typeof grade === 'string' ? grade.trim() : '';
  section = typeof section === 'string' ? section.trim() : '';
  password = typeof password === 'string' ? password : '';

  if (!name || !grade || !section || !password) {
    return res.status(400).json({ error: 'Fill in every field.' });
  }

  // Look up by the cleaned name first, then by the name exactly as typed (so accounts
  // created before names were normalised can still log in).
  const keys = [...new Set([accountKey(name, grade, section), accountKey(rawName, grade, section)])];
  let row;
  for (const key of keys) {
    row = db.prepare('SELECT * FROM users WHERE account_key = ?').get(key);
    if (row) break;
  }

  const ok = bcrypt.compareSync(password, row ? row.password_hash : DUMMY_HASH);
  if (!row || !ok) {
    return res.status(401).json({ error: 'No account found, or the password is wrong.' });
  }

  setSessionCookie(res, row);
  res.json({ user: { id: row.id, name: row.name, grade: row.grade, section: row.section, role: row.role } });
});

router.post('/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

router.get('/session', sessionLimiter, (req, res) => {
  if (!req.user) return res.json({ user: null });
  const row = db.prepare('SELECT id, name, username, grade, section, role, can_see_anon FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.json({ user: null });
  res.json({ user: publicUser(row) });
});

// Update your own display name and/or username.
// Body: { display_name?: string, username?: string | null }  (omit a field to leave it unchanged)
//
// - display_name: 1-60 chars, normalised (see cleanName), no < or >, passes the profanity
//   filter. It lives in users.name. Students log in with name + grade + section, so for
//   them a name change ALSO updates their login key (and is refused if another student
//   in the same section already has that name).
// - username: 3-40 chars (letters, numbers, . _ -), unique case-insensitively.
//   Admin/council log in with it, so they can't clear it; students may leave it blank.
router.put('/profile', requireAuth, profileLimiter, (req, res) => {
  const current = db.prepare('SELECT id, name, username, grade, section, role, can_see_anon FROM users WHERE id = ?').get(req.user.id);
  if (!current) return res.status(404).json({ error: 'Account not found.' });

  const body = req.body || {};
  const hasName = body.display_name !== undefined;
  const hasUsername = body.username !== undefined;
  if (!hasName && !hasUsername) {
    return res.status(400).json({ error: 'Nothing to update.' });
  }

  let name = current.name;
  let username = current.username || null;

  if (hasName) {
    if (typeof body.display_name !== 'string') {
      return res.status(400).json({ error: 'Display name must be text.' });
    }
    name = cleanName(body.display_name);
    if (!name) return res.status(400).json({ error: 'Display name can\'t be empty.' });
    if (name.length > LIMITS.nameMax) {
      return res.status(400).json({ error: `Display name must be under ${LIMITS.nameMax} characters.` });
    }
    if (name !== current.name) {
      if (NAME_FORBIDDEN.test(name)) {
        return res.status(400).json({ error: 'Names can\'t contain < or >.' });
      }
      if (evaluateText(name).blocked) {
        return res.status(400).json({ error: 'Please use an appropriate name.' });
      }
    }
  }

  if (hasUsername) {
    if (body.username !== null && typeof body.username !== 'string') {
      return res.status(400).json({ error: 'Username must be text.' });
    }
    const u = body.username === null ? '' : body.username.trim();
    if (u === '') {
      if (STAFF_ROLES.includes(current.role)) {
        return res.status(400).json({ error: 'Staff accounts need a username to log in.' });
      }
      username = null;
    } else {
      if (!USERNAME_RE.test(u)) return res.status(400).json({ error: USERNAME_RULE });
      username = u;
    }
  }

  if (username) {
    const taken = db.prepare('SELECT id FROM users WHERE lower(username) = lower(?) AND id != ?').get(username, current.id);
    if (taken) return res.status(409).json({ error: 'That username is taken.' });
  }

  // Student/president accounts have an account_key built from name + grade + section.
  const hasAccountKey = !!(current.grade && current.section);
  let newKey = null;
  if (hasAccountKey && name !== current.name) {
    newKey = accountKey(name, current.grade, current.section);
    const clash = db.prepare('SELECT id FROM users WHERE account_key = ? AND id != ?').get(newKey, current.id);
    if (clash) {
      return res.status(409).json({ error: 'Someone in your section already uses that name.' });
    }
  }

  const apply = db.transaction(() => {
    if (newKey) {
      db.prepare('UPDATE users SET name = ?, username = ?, account_key = ? WHERE id = ?')
        .run(name, username, newKey, current.id);
    } else {
      db.prepare('UPDATE users SET name = ?, username = ? WHERE id = ?').run(name, username, current.id);
    }
    // Comments store the author's name as text, so keep them in sync with the rename.
    if (name !== current.name) {
      db.prepare('UPDATE comments SET name = ? WHERE user_id = ?').run(name, current.id);
    }
  });

  try {
    apply();
  } catch (e) {
    if (e && String(e.code).startsWith('SQLITE_CONSTRAINT')) {
      return res.status(409).json({ error: 'That username or name is already taken.' });
    }
    throw e;
  }

  const updated = { id: current.id, name, username, grade: current.grade, section: current.section, role: current.role, can_see_anon: current.can_see_anon };
  setSessionCookie(res, updated); // the JWT carries the name, so refresh it
  res.json({ ok: true, user: publicUser(updated) });
});

// Change your own password (any logged-in role) and sign out EVERYWHERE.
// Body: { current_password, new_password }
//
// On success the account's token_version is incremented. Every JWT carries the version it
// was issued under and attachUser() (middleware/auth.js) rejects any token whose version
// no longer matches, so all sessions on all devices and browsers stop working immediately.
// This device's cookie is cleared too; the client then asks the user to log in again.
router.post('/change-password', requireAuth, passwordIpLimiter, passwordUserLimiter, (req, res) => {
  const body = req.body || {};
  const current = typeof body.current_password === 'string' ? body.current_password : '';
  const next = typeof body.new_password === 'string' ? body.new_password : '';

  if (!current || !next) return res.status(400).json({ error: 'Fill in both password fields.' });
  if (next.length < LIMITS.passwordMin) {
    return res.status(400).json({ error: `New password needs to be at least ${LIMITS.passwordMin} characters.` });
  }
  if (passwordTooLong(next)) {
    return res.status(400).json({ error: `New password is too long (${PASSWORD_MAX_BYTES} bytes max).` });
  }
  if (next === current) {
    return res.status(400).json({ error: 'Choose a password different from your current one.' });
  }

  const row = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'Account not found.' });
  if (!bcrypt.compareSync(current, row.password_hash)) {
    return res.status(403).json({ error: 'Your current password is incorrect.' });
  }

  db.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?')
    .run(bcrypt.hashSync(next, 12), row.id);

  clearSessionCookie(res);
  res.json({ ok: true, loggedOut: true, message: 'Password changed. Please log in again.' });
});

module.exports = router;
