// Server-side copy of the same GRADE_SECTIONS map defined in the client's
// <script> (public/index.html). The server never trusts the client's copy —
// it revalidates every signup/post against this one — so if you add or
// rename a section, update BOTH places to keep them in sync.
const GRADE_SECTIONS = {
  '7': ['Genesis'],
  '8': ['Daniel', 'Leviticus'],
  '9': ['Jeremiah', 'Nehemiah'],
  '10': ['Psalms', 'Proverbs']
};

const LIMITS = {
  nameMax: 60,
  postTextMax: 2000,
  commentTextMax: 500,
  passwordMin: 6
};

// Profanity filter threshold: block anything whose severity meets or
// exceeds this number. 1 = block mild insults too (default). Raise to 2
// to let mild words like "bobo"/"damn" through and only block real
// swearing and slurs. See src/filter/wordlist.js for the tiers.
const MIN_SEVERITY = 1;

module.exports = { GRADE_SECTIONS, LIMITS, MIN_SEVERITY };
