const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { LIMITS } = require('../config');
const { setSessionCookie, requireAdmin, requireModerator } = require('../middleware/auth');

// Mounted at /api/managers. Handles STAFF accounts (admin + council) and
// lets admins assign the per-section "president" role to student accounts.

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a bit.' }
});

const STAFF_CREATABLE = ['admin', 'council'];

function validUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9._-]{3,40}$/.test(u);
}

// One-time setup: creates the FIRST admin account using ADMIN_SETUP_KEY from
// your .env file. Refuses once any admin already exists.
router.post('/bootstrap', authLimiter, (req, res) => {
  const existingAdmin = db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").get();
  if (existingAdmin) {
    return res.status(403).json({ error: 'An admin account already exists. Ask an existing admin to add you.' });
  }

  let { setupKey, username, name, password } = req.body || {};
  if (!process.env.ADMIN_SETUP_KEY || setupKey !== process.env.ADMIN_SETUP_KEY) {
    return res.status(403).json({ error: 'Invalid setup key.' });
  }
  username = typeof username === 'string' ? username.trim() : '';
  name = typeof name === 'string' ? name.trim() : '';
  password = typeof password === 'string' ? password : '';

  if (!validUsername(username)) {
    return res.status(400).json({ error: 'Username must be 3-40 characters: letters, numbers, dots, dashes, underscores.' });
  }
  if (!name || name.length > LIMITS.nameMax) {
    return res.status(400).json({ error: 'Enter a display name.' });
  }
  if (password.length < LIMITS.passwordMin) {
    return res.status(400).json({ error: `Password needs to be at least ${LIMITS.passwordMin} characters.` });
  }
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    return res.status(409).json({ error: 'That username is taken.' });
  }

  const passwordHash = bcrypt.hashSync(password, 12);
  const info = db.prepare(`
    INSERT INTO users (username, name, password_hash, role)
    VALUES (?, ?, ?, 'admin')
  `).run(username, name, passwordHash);

  const user = { id: info.lastInsertRowid, name, grade: null, section: null, role: 'admin' };
  setSessionCookie(res, user);
  res.status(201).json({ user: { id: user.id, name, role: 'admin', canSeeAnon: true } });
});

// Staff login (admin or council) by username + password.
router.post('/login', authLimiter, (req, res) => {
  let { username, password } = req.body || {};
  username = typeof username === 'string' ? username.trim() : '';
  password = typeof password === 'string' ? password : '';

  const row = db.prepare("SELECT * FROM users WHERE username = ? AND role IN ('admin', 'council')").get(username);
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  setSessionCookie(res, row);
  res.json({ user: { id: row.id, name: row.name, role: row.role, canSeeAnon: row.role === 'admin' || row.can_see_anon === 1 } });
});

// Admin adds a staff account. Body: { username, name, password, role: 'admin' | 'council' }
router.post('/', requireAdmin, authLimiter, (req, res) => {
  let { username, name, password, role } = req.body || {};
  username = typeof username === 'string' ? username.trim() : '';
  name = typeof name === 'string' ? name.trim() : '';
  password = typeof password === 'string' ? password : '';
  role = role || 'council';

  if (!STAFF_CREATABLE.includes(role)) {
    return res.status(400).json({ error: "Role must be 'admin' or 'council'." });
  }
  if (!validUsername(username)) {
    return res.status(400).json({ error: 'Username must be 3-40 characters: letters, numbers, dots, dashes, underscores.' });
  }
  if (!name || name.length > LIMITS.nameMax) {
    return res.status(400).json({ error: 'Enter a display name.' });
  }
  if (password.length < LIMITS.passwordMin) {
    return res.status(400).json({ error: `Password needs to be at least ${LIMITS.passwordMin} characters.` });
  }
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    return res.status(409).json({ error: 'That username is taken.' });
  }

  const passwordHash = bcrypt.hashSync(password, 12);
  db.prepare('INSERT INTO users (username, name, password_hash, role) VALUES (?, ?, ?, ?)')
    .run(username, name, passwordHash, role);

  res.status(201).json({ ok: true });
});

// List staff accounts (admin + council can see who has access).
router.get('/', requireModerator, (req, res) => {
  const rows = db.prepare("SELECT id, username, name, role, can_see_anon, created_at FROM users WHERE role IN ('admin', 'council') ORDER BY created_at").all();
  res.json({ managers: rows });
});

// Admin only: allow or stop a COUNCIL member from seeing who wrote anonymous posts.
// (Admins always can; students and presidents never can.) Body: { allowed: true | false }
router.patch('/:username/anon-access', requireAdmin, (req, res) => {
  const { allowed } = req.body || {};
  if (typeof allowed !== 'boolean') return res.status(400).json({ error: 'allowed must be true or false.' });
  const target = db.prepare("SELECT id FROM users WHERE username = ? AND role = 'council'").get(req.params.username);
  if (!target) return res.status(404).json({ error: 'Council account not found.' });
  db.prepare('UPDATE users SET can_see_anon = ? WHERE id = ?').run(allowed ? 1 : 0, target.id);
  res.json({ ok: true, allowed });
});

// ---- President assignment (admin only) ----------------------------------

router.get('/students', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT id, name, grade, section, role FROM users
    WHERE role IN ('student', 'president')
    ORDER BY CAST(grade AS INTEGER), section, name
  `).all();
  res.json({ students: rows });
});

// Body: { role: 'president' | 'student' }. One president per section.
router.patch('/students/:id/role', requireAdmin, (req, res) => {
  const { role } = req.body || {};
  if (role !== 'president' && role !== 'student') {
    return res.status(400).json({ error: "Role must be 'president' or 'student'." });
  }
  const target = db.prepare("SELECT id, grade, section FROM users WHERE id = ? AND role IN ('student', 'president')")
    .get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Student account not found.' });

  if (role === 'president') {
    const other = db.prepare("SELECT id FROM users WHERE role = 'president' AND grade = ? AND section = ? AND id != ?")
      .get(target.grade, target.section, target.id);
    if (other) {
      return res.status(409).json({ error: 'That section already has a president. Demote them first.' });
    }
  }

  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, target.id);
  res.json({ ok: true });
});

module.exports = router;
