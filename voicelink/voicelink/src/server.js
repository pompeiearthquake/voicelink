require('dotenv').config();

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const { attachUser } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const managerRoutes = require('./routes/managers');
const postRoutes = require('./routes/posts');

const app = express();

app.set('trust proxy', 1); // needed on Render/Railway so secure cookies work behind their proxy

// Helmet adds the standard security headers (HSTS, X-Content-Type-Options, X-Frame-Options,
// Referrer-Policy, ...). Its own Content-Security-Policy is switched off so Google Fonts and
// CDN assets aren't blocked; the page's <meta http-equiv="Content-Security-Policy"> in
// public/index.html is the CSP that applies. If you add another CDN (e.g. FontAwesome on
// cdnjs.cloudflare.com), allow it in that meta tag too.
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(attachUser);

app.use('/api/auth', authRoutes);
app.use('/api/managers', managerRoutes);
app.use('/api/posts', postRoutes);

app.use(express.static(path.join(__dirname, '..', 'public')));

// Centralized error handler — keeps stack traces out of API responses.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our end.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`VoiceLink server listening on port ${PORT}`);
});
