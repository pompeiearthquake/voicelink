const express = require('express');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { GRADE_SECTIONS, LIMITS } = require('../config');
const { isStaff, STAFF_ROLES, requireAuth, requireModerator, requirePoster } = require('../middleware/auth');
const { evaluateText } = require('../filter');

const router = express.Router();

const postLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Slow down a little — try again shortly.' }
});

const PINNED_KEY = 'pinned_post_id';

// Archive, archive view and permanent delete are all restricted to advisers/admins and
// student council members (requireModerator). Section presidents and students get 403.
const STATUSES = ['in_review', 'planned', 'resolved']; // In Review / Planned / Resolved

function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}
function setSetting(key, value) {
  db.prepare(`
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, value);
}

function validGradeSection(grade, section) {
  const sections = GRADE_SECTIONS[grade];
  return Array.isArray(sections) && sections.includes(section);
}

// admin/council can access every section; everyone else only their own.
function canAccessPost(user, post) {
  return isStaff(user) || (post.grade === user.grade && post.section === user.section);
}

// Who may SEE and WRITE comments (and react) on a post.
//
// This is deliberately a separate question from "who sees the post in the feed".
// Posts by admin/council and the pinned post are shown to everyone, but their comments
// keep the original rule: only that post's own section, plus admin/council. The feed
// query, the comment routes and the star/bookmark routes all use this same check, so
// widening the feed can never widen comment access.
function canViewComments(user, post) {
  return canAccessPost(user, post);
}

// Looks up a post (archived or not) for the archive routes.
function getPostForModeration(id) {
  return db.prepare('SELECT id, is_archived FROM posts WHERE id = ?').get(id);
}

// Loads a post for star/bookmark/comment (read or write), or sends 404 (not 403, so the
// existence of other sections' posts isn't revealed) and returns null.
function loadAccessiblePost(req, res) {
  const post = db.prepare('SELECT id, grade, section, is_archived FROM posts WHERE id = ?').get(req.params.id);
  // Archived posts are gone as far as the feed, comments, stars and saves are concerned.
  if (!post || post.is_archived || !canViewComments(req.user, post)) {
    res.status(404).json({ error: 'Post not found.' });
    return null;
  }
  return post;
}

function getComments(postId) {
  return db.prepare('SELECT id, name, text, created_at FROM comments WHERE post_id = ? ORDER BY created_at ASC, id ASC')
    .all(postId);
}

function serializePost(post, viewer, pinnedId) {
  const starCount = db.prepare('SELECT COUNT(*) AS n FROM stars WHERE post_id = ?').get(post.id).n;
  const starred = !!db.prepare('SELECT 1 FROM stars WHERE post_id = ? AND user_id = ?').get(post.id, viewer.id);
  const bookmarked = !!db.prepare('SELECT 1 FROM bookmarks WHERE post_id = ? AND user_id = ?').get(post.id, viewer.id);

  // A post can be in this viewer's feed (council post / pinned post) without the viewer
  // being allowed into its comment thread. In that case send no comments at all, not
  // even a count, and tell the client so it can show a note instead of the thread.
  const inCommentScope = canViewComments(viewer, post);
  const authorRole = STAFF_ROLES.includes(post.author_role) ? post.author_role : null;

  return {
    id: post.id,
    // Anonymous posts never carry the author's name to ANY viewer. Authorised staff (admin, or council an
    // admin has allowed) look it up deliberately via GET /:id/author, which is logged.
    name: post.anon ? null : post.author_name,
    anon: !!post.anon,
    grade: post.grade,
    section: post.section,
    text: post.text,
    date: post.created_at,
    status: post.status || null,
    pinned: pinnedId != null && post.id === pinnedId,
    authorRole,                       // 'admin' | 'council' for official posts, else null
    official: authorRole !== null,
    stars: starCount,
    starred,
    bookmarked,
    canInteract: inCommentScope,      // may comment / star / save
    commentsLocked: !inCommentScope,
    comments: inCommentScope ? getComments(post.id) : []
  };
}

const POST_SELECT = 'SELECT p.*, u.name AS author_name, u.role AS author_role FROM posts p JOIN users u ON u.id = p.user_id';

// Feed visibility:
//  - admin/council: every post, every section.
// Archived posts (is_archived = 1) never appear here, for any role — see GET /archived.
//  - everyone else: posts from their own grade + section, PLUS any post written by an
//    admin or council member, PLUS the currently pinned post, whatever section it's in.
// Regular student/president posts stay section-scoped. Comment visibility is NOT part
// of this query — see canViewComments(), applied per post in serializePost().
router.get('/', (req, res) => {
  const user = req.user;
  if (!user) return res.json({ posts: [], pinnedId: null });

  const pinnedRaw = getSetting(PINNED_KEY);
  const pinnedCandidate = pinnedRaw ? Number(pinnedRaw) : null;

  // Staff can look at one section's wall (?grade=8&section=Daniel) or at everything.
  const wantGrade = typeof req.query.grade === 'string' ? req.query.grade : '';
  const wantSection = typeof req.query.section === 'string' ? req.query.section : '';
  const sectionFilter = isStaff(user) && validGradeSection(wantGrade, wantSection);

  const rows = isStaff(user)
    ? (sectionFilter
        ? db.prepare(`${POST_SELECT} WHERE p.is_archived = 0 AND p.grade = ? AND p.section = ? ORDER BY p.created_at DESC, p.id DESC`).all(wantGrade, wantSection)
        : db.prepare(`${POST_SELECT} WHERE p.is_archived = 0 ORDER BY p.created_at DESC, p.id DESC`).all())
    : db.prepare(`
        ${POST_SELECT}
        WHERE p.is_archived = 0
          AND ((p.grade = ? AND p.section = ?)
               OR u.role IN ('admin', 'council')
               OR p.id = ?)
        ORDER BY p.created_at DESC, p.id DESC
      `).all(user.grade, user.section, pinnedCandidate);

  // Only report the pin if that post is in this user's feed.
  const pinnedId = rows.some(r => r.id === pinnedCandidate) ? pinnedCandidate : null;

  res.json({ posts: rows.map(r => serializePost(r, user, pinnedId)), pinnedId });
});

// admin/council/president may post; student gets 403 from requirePoster.
// For admin/council the grade + section they pick is the section whose students can
// comment on the post (the post itself is visible to everyone).
router.post('/', requirePoster, postLimiter, (req, res) => {
  let { text, anon, grade, section } = req.body || {};
  text = typeof text === 'string' ? text.trim() : '';
  if (!text) return res.status(400).json({ error: 'Write something before posting.' });
  if (text.length > LIMITS.postTextMax) {
    return res.status(400).json({ error: `Keep posts under ${LIMITS.postTextMax} characters.` });
  }
  if (evaluateText(text).blocked) {
    return res.status(400).json({ error: 'That post contains language that isn\'t allowed here. Please rewrite it.' });
  }

  let postGrade, postSection;
  if (isStaff(req.user)) {
    // Staff have no section of their own, so they choose which section to post to.
    postGrade = typeof grade === 'string' ? grade.trim() : '';
    postSection = typeof section === 'string' ? section.trim() : '';
    if (!validGradeSection(postGrade, postSection)) {
      return res.status(400).json({ error: 'Pick the grade and section whose students can comment.' });
    }
  } else {
    // President: always their own section, whatever the client sends.
    postGrade = req.user.grade;
    postSection = req.user.section;
  }

  const anonymous = req.user.role === 'president' && !!anon; // staff posts are always attributed

  const info = db.prepare(`
    INSERT INTO posts (user_id, anon, text, grade, section)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.user.id, anonymous ? 1 : 0, text, postGrade, postSection);

  const row = db.prepare(`${POST_SELECT} WHERE p.id = ?`).get(info.lastInsertRowid);
  res.status(201).json({ post: serializePost(row, req.user, null) });
});

// ---- Moderation: admin + council only ----------------------------------

// ---- Archiving (replaces direct deletion) --------------------------------
// There is no way to delete a post straight from the feed. Removing a post archives it
// (soft delete); it can then only be purged from inside the Archive view.

// PUT /api/posts/:id/archive — hide a post from the feed and move it to the archive.
// Advisers/admins and council members only. Presidents and students get 403 and have no
// removal action of any kind.
router.put('/:id/archive', requireModerator, (req, res) => {
  const post = getPostForModeration(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.is_archived) return res.json({ ok: true, alreadyArchived: true });

  db.prepare("UPDATE posts SET is_archived = 1, deleted_at = datetime('now') WHERE id = ?").run(post.id);
  if (getSetting(PINNED_KEY) === String(post.id)) setSetting(PINNED_KEY, '');
  res.json({ ok: true });
});

// GET /api/posts/archived — the archive, with the REAL author details.
// Advisers/admins and student council members ONLY: section presidents and students get 403.
// The real name behind an anonymous post is shown here, so this is deliberately closed to presidents.
router.get('/archived', requireModerator, (req, res) => {
  const base = `
    SELECT p.id, p.anon, p.text, p.grade, p.section, p.created_at, p.deleted_at,
           u.name AS author_name, u.username AS author_username, u.role AS author_role,
           (SELECT COUNT(*) FROM stars s WHERE s.post_id = p.id) AS stars,
           (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
    FROM posts p JOIN users u ON u.id = p.user_id
    WHERE p.is_archived = 1`;
  const order = ' ORDER BY p.deleted_at DESC, p.id DESC';

  const rows = db.prepare(base + order).all();

  res.set('Cache-Control', 'no-store'); // contains real identities
  res.json({
    posts: rows.map(r => ({
      id: r.id,
      // Real identity of an anonymous post only for viewers allowed to see it (admin, or authorised council).
      name: r.anon && !req.user.canSeeAnon ? null : r.author_name,
      username: r.anon && !req.user.canSeeAnon ? null : (r.author_username || null),
      authorRole: r.author_role,
      grade: r.grade,
      section: r.section,
      anon: !!r.anon,                    // was it originally posted anonymously?
      text: r.text,
      date: r.created_at,
      archivedAt: r.deleted_at,
      stars: r.stars,
      commentCount: r.comment_count
    }))
  });
});

// DELETE /api/posts/:id/permanent — purge an ARCHIVED post (and, via ON DELETE CASCADE,
// its comments, stars and saves) from SQLite. Refuses posts that haven't been archived.
// Advisers/admins and council members only (presidents and students get 403).
router.delete('/:id/permanent', requireModerator, (req, res) => {
  const post = getPostForModeration(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (!post.is_archived) {
    return res.status(409).json({ error: 'Only archived posts can be permanently deleted. Archive it first.' });
  }

  db.prepare('DELETE FROM posts WHERE id = ?').run(post.id);
  try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (e) { /* best effort: flush the write-ahead log */ }
  res.json({ ok: true });
});

router.delete('/:id/comments/:commentId', requireModerator, (req, res) => {
  const info = db.prepare('DELETE FROM comments WHERE id = ? AND post_id = ?')
    .run(req.params.commentId, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Comment not found.' });
  res.json({ ok: true, comments: getComments(Number(req.params.id)) });
});

router.post('/:id/pin', requireModerator, (req, res) => {
  const post = db.prepare('SELECT id FROM posts WHERE id = ? AND is_archived = 0').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  setSetting(PINNED_KEY, String(post.id));
  res.json({ ok: true });
});

router.post('/unpin', requireModerator, (req, res) => {
  setSetting(PINNED_KEY, '');
  res.json({ ok: true });
});

// Body: { status: 'in_review' | 'planned' | 'resolved' | null }  (null clears the badge)
router.post('/:id/status', requireModerator, (req, res) => {
  const { status } = req.body || {};
  const value = status === '' ? null : status;
  if (value !== null && !STATUSES.includes(value)) {
    return res.status(400).json({ error: 'Status must be in_review, planned, resolved, or null.' });
  }
  const info = db.prepare('UPDATE posts SET status = ? WHERE id = ? AND is_archived = 0').run(value, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Post not found.' });
  res.json({ ok: true, status: value });
});

// ---- Participation: any logged-in user, but only within sections they can see ----

router.post('/:id/star', requireAuth, (req, res) => {
  const post = loadAccessiblePost(req, res);
  if (!post) return;

  const existing = db.prepare('SELECT 1 FROM stars WHERE post_id = ? AND user_id = ?').get(post.id, req.user.id);
  if (existing) {
    db.prepare('DELETE FROM stars WHERE post_id = ? AND user_id = ?').run(post.id, req.user.id);
  } else {
    db.prepare('INSERT INTO stars (post_id, user_id) VALUES (?, ?)').run(post.id, req.user.id);
  }
  const starCount = db.prepare('SELECT COUNT(*) AS n FROM stars WHERE post_id = ?').get(post.id).n;
  res.json({ starred: !existing, stars: starCount });
});

router.post('/:id/bookmark', requireAuth, (req, res) => {
  const post = loadAccessiblePost(req, res);
  if (!post) return;

  const existing = db.prepare('SELECT 1 FROM bookmarks WHERE post_id = ? AND user_id = ?').get(post.id, req.user.id);
  if (existing) {
    db.prepare('DELETE FROM bookmarks WHERE post_id = ? AND user_id = ?').run(post.id, req.user.id);
  } else {
    db.prepare('INSERT INTO bookmarks (post_id, user_id) VALUES (?, ?)').run(post.id, req.user.id);
  }
  res.json({ bookmarked: !existing });
});

// GET /api/posts/:id/author — look up who wrote an ANONYMOUS post.
// Admins, and council members an admin has authorised. Everyone else gets 403. Each lookup is logged.
const revealLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many lookups. Try again later.' }
});
router.get('/:id/author', requireAuth, revealLimiter, (req, res) => {
  if (!req.user.canSeeAnon) return res.status(403).json({ error: "You don't have permission to do that." });
  const row = db.prepare(`
    SELECT p.id, p.anon, p.grade, p.section, u.name, u.username
    FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = ?
  `).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Post not found.' });
  if (!row.anon) return res.status(400).json({ error: 'That post is not anonymous.' });

  db.prepare('INSERT INTO anon_reveals (post_id, viewer_id) VALUES (?, ?)').run(row.id, req.user.id);
  res.set('Cache-Control', 'no-store');
  res.json({ author: { name: row.name, username: row.username || null, grade: row.grade, section: row.section } });
});

// Read a post's comments. Same authorization as writing one (canViewComments), and
// completely independent of whether the parent post appears in the viewer's feed.
router.get('/:id/comments', requireAuth, (req, res) => {
  const post = loadAccessiblePost(req, res);
  if (!post) return;
  res.json({ comments: getComments(post.id) });
});

router.post('/:id/comments', requireAuth, postLimiter, (req, res) => {
  const post = loadAccessiblePost(req, res);
  if (!post) return;

  let { text } = req.body || {};
  text = typeof text === 'string' ? text.trim() : '';
  if (!text) return res.status(400).json({ error: 'Write a comment first.' });
  if (text.length > LIMITS.commentTextMax) {
    return res.status(400).json({ error: `Keep comments under ${LIMITS.commentTextMax} characters.` });
  }
  if (evaluateText(text).blocked) {
    return res.status(400).json({ error: 'That comment contains language that isn\'t allowed here. Please rewrite it.' });
  }

  db.prepare('INSERT INTO comments (post_id, user_id, name, text) VALUES (?, ?, ?, ?)')
    .run(post.id, req.user.id, req.user.name, text);

  res.status(201).json({ comments: getComments(post.id) });
});

module.exports = router;
