const jwt = require('jsonwebtoken');
const db = require('../db');

const COOKIE_NAME = 'vl_session';
const SECRET = process.env.JWT_SECRET;

if (!SECRET) {
  console.error('Missing JWT_SECRET in environment. Set it in your .env file before starting the server.');
  process.exit(1);
}

// Role tiers: admin > council > president > student
const STAFF_ROLES = ['admin', 'council'];              // see every section, moderate
const POSTER_ROLES = ['admin', 'council', 'president']; // may create main posts

const isStaff = user => !!user && STAFF_ROLES.includes(user.role);

function accountKey(name, grade, section) {
  return [name, grade, section].map(v => String(v).trim().toLowerCase()).join('|');
}

// The user's current token_version (0 for accounts that have never changed their password).
// Looked up here when the caller didn't pass it, so every place that issues a cookie
// (signup, login, profile edit, bootstrap) stays correct without knowing about versions.
function currentTokenVersion(user) {
  if (Number.isInteger(user.token_version)) return user.token_version;
  const row = db.prepare('SELECT token_version FROM users WHERE id = ?').get(user.id);
  return row ? row.token_version : 0;
}

function signSession(user) {
  return jwt.sign(
    { id: user.id, name: user.name, grade: user.grade, section: user.section, role: user.role, tv: currentTokenVersion(user) },
    SECRET,
    { expiresIn: '7d' }
  );
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/'
  };
}

function setSessionCookie(res, user) {
  res.cookie(COOKIE_NAME, signSession(user), cookieOptions());
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { ...cookieOptions(), maxAge: undefined });
}

// Verifies the cookie, then re-reads the user's CURRENT role/grade/section from
// the database, and rejects the token if its version no longer matches the account's
// token_version (i.e. the password was changed after the token was issued). That way a promotion, demotion, or deleted account takes effect
// on the very next request instead of waiting up to 7 days for the JWT to expire.
// req.user is always { id, name, role, grade, section }. Never rejects the request.
function attachUser(req, _res, next) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return next();
  try {
    const payload = jwt.verify(token, SECRET);
    const row = db.prepare('SELECT id, name, role, grade, section, token_version, can_see_anon FROM users WHERE id = ?').get(payload.id);
    // Tokens issued before this feature have no `tv`; they count as version 0.
    if (row && (payload.tv ?? 0) === row.token_version) {
      req.user = {
        id: row.id, name: row.name, role: row.role, grade: row.grade, section: row.section,
        // May see the real author of anonymous posts: admins always, council only when an admin allowed it.
        canSeeAnon: row.role === 'admin' || (row.role === 'council' && row.can_see_anon === 1)
      };
    }
  } catch (e) {
    // expired/invalid token — treat as logged out
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Log in to do that.' });
  next();
}

// requireRole('admin', 'council') -> 401 if logged out, 403 if the role isn't listed.
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Log in to do that.' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "You don't have permission to do that." });
    }
    next();
  };
}

const requireAdmin = requireRole('admin');
const requireModerator = requireRole(...STAFF_ROLES);   // delete/pin/status
const requirePoster = requireRole(...POSTER_ROLES);     // create main posts

module.exports = {
  COOKIE_NAME,
  STAFF_ROLES,
  POSTER_ROLES,
  isStaff,
  accountKey,
  setSessionCookie,
  clearSessionCookie,
  attachUser,
  requireAuth,
  requireRole,
  requireAdmin,
  requireModerator,
  requirePoster
};
