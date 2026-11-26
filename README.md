# VoiceLink

A moderated opinion/suggestion wall for the student council, scoped by grade and
section. Node.js + Express + SQLite (`better-sqlite3`), with a single-page
front end in `public/index.html`.

## Roles

| Role | Sees | Can do |
|---|---|---|
| `admin` (adviser) | every section | post, comment, star, pin, set status, **archive**, view the archive, **permanently delete**, delete comments, add staff accounts, assign section presidents |
| `council` | every section | same as admin except adding staff accounts and assigning presidents |
| `president` | own section, plus council/admin posts and the pinned post | post to their own section (optionally anonymous), comment, star |
| `student` | own section, plus council/admin posts and the pinned post | comment, star, save (no main posts) |

- Posts by admin/council and the pinned post are visible to every logged-in
  student. Their **comments stay limited** to the post's own section (plus staff).
- Nobody can delete a post from the wall. Admin/council **archive** it (soft
  delete); only admin/council can open the **Archived posts** view (real author
  name, username, grade, section, and a Posted Anonymously / Public tag) and
  purge a post permanently from there. Presidents and students get HTTP 403.
- Changing your password signs you out on **every device** (`token_version`).

## Project layout

```
voicelink/
  package.json
  .env.example           copy to .env
  .gitignore
  data/                  SQLite database is created here (mount a volume in production)
  public/
    index.html           the whole front end (HTML + CSS + JS)
  src/
    server.js            app entry point
    config.js            grade/section list, limits, filter threshold
    db.js                schema + automatic migrations
    filter/              profanity filter (index.js, wordlist.js)
    middleware/auth.js   cookies, JWT + token_version check, role guards
    routes/
      auth.js            signup (requires agreedToTerms), login, session, PUT /profile, POST /change-password
      managers.js        staff accounts (admin/council), first-admin bootstrap, president assignment
      posts.js           feed, posting, archive/permanent delete, pin, status, comments, stars, saves
```

## Run locally

Node.js 18+.

```bash
npm install
cp .env.example .env
```

Edit `.env` and set real values for `JWT_SECRET` and `ADMIN_SETUP_KEY` (the file
shows how to generate one). Then:

```bash
npm start        # http://localhost:3000
```

## First admin account

Click **staff login** at the bottom of the page, then **First admin? Set up
account**. Enter a display name, username, password and your `ADMIN_SETUP_KEY`.
It works once; after an admin exists it always refuses. That admin can then:

- add more `admin` / `council` accounts (**Manage staff accounts**), and
- make a student a section president (**Assign section presidents**).

## Upgrading an existing database

Start the new version once and `db.js` migrates automatically: old `manager`
accounts become `admin`, and the `status`, `is_archived`, `deleted_at` and
`token_version` columns are added. **Back up `data/voicelink.db` first.**

## Editing grades and sections

`GRADE_SECTIONS` exists twice on purpose: in `public/index.html` (drives the
dropdowns) and in `src/config.js` (what the server actually validates). Change
both, then restart.

## Tuning the profanity filter

`src/filter/wordlist.js` holds the word roots (severity 1-3), a boundary-only
list for short roots, and an `ALLOWLIST` for false positives. `MIN_SEVERITY` in
`src/config.js` sets the cutoff.

## Deploying on Railway

1. Push the project to GitHub (commit `src/` and `public/`; `.gitignore` already excludes only `node_modules`, `.env` and the database files).
2. Railway -> New Project -> Deploy from GitHub repo. If the code is in a subfolder of the repo, set the service's **Root Directory** to it.
   Railway detects Node and runs `npm install` then `npm start`.
3. **Variables:** `JWT_SECRET` (long random string), `ADMIN_SETUP_KEY`, `NODE_ENV=production`. Railway sets `PORT` itself.
   `NODE_ENV=production` is what marks the login cookie Secure.
4. **Volume (keeps the database across redeploys):** add a volume to the service and mount it at `/app/data`
   (Railway puts your code in `/app`, and the app writes to `./data`). If you mount it elsewhere, set `DATA_DIR` to that path.
   Volumes are attached when the service starts, not during the build.
5. Settings -> Networking -> **Generate Domain** to get a public URL.
6. Open the site, click **staff login -> First admin? Set up account**, and use `ADMIN_SETUP_KEY`.

**Upgrading an existing deployment:** back up `voicelink.db` first (the volume's Backups tab, or `railway volume` in the CLI),
then deploy. On the first start the logs show `[db] migrated: ...` lines; later restarts show none.
Old managers become admins, and council members start with anonymous-author access OFF until an admin allows it
(left menu -> Anonymous-author access).

## Security notes

- Passwords are bcrypt hashes; login, signup, profile and password changes are rate-limited.
- Cookies are `HttpOnly` and `SameSite=Lax`, and `Secure` when `NODE_ENV=production`.
- All user text is HTML-escaped when rendered; the page also ships a Content-Security-Policy.
- Sign-up requires `agreedToTerms: true` on the server. Have a teacher or school
  administrator review the Terms & Privacy text in `public/index.html` before launch.
