// Word list for the profanity filter (src/filter/index.js).
//
// severity: 1 = mild insult (e.g. "bobo", "damn") — still blocked by default,
//           but lower this list's MIN_SEVERITY in src/config.js if the council
//           wants to allow mild words through.
//           2 = standard profanity/swearing.
//           3 = slurs and the harshest terms — always worth blocking.
//
// Roots only — do NOT add symbols, spacing, or letter-repeats here. The
// matcher (src/filter/index.js) already expands each root to catch
// leetspeak (f4ck), spacing (f u c k), symbols (f*ck), and stretching
// (fuuuck) automatically.
//
// This list is short on purpose: broad substring matching on very short
// or common word fragments (like "ass" alone) causes false positives on
// ordinary words ("class", "assignment", "assess"). Longer, more specific
// roots avoid that problem, and true short-word matches are still caught
// via WORD_BOUNDARY_ONLY below.

const ENGLISH = [
  { word: 'fuck', severity: 2 },
  { word: 'motherfucker', severity: 2 },
  { word: 'shit', severity: 2 },
  { word: 'bullshit', severity: 2 },
  { word: 'bitch', severity: 2 },
  { word: 'asshole', severity: 2 },
  { word: 'bastard', severity: 1 },
  { word: 'pussy', severity: 2 },
  { word: 'cunt', severity: 3 },
  { word: 'whore', severity: 2 },
  { word: 'slut', severity: 2 },
  { word: 'nigger', severity: 3 },
  { word: 'nigga', severity: 3 },
  { word: 'faggot', severity: 3 },
  { word: 'retard', severity: 2 },
  { word: 'dumbass', severity: 1 },
  { word: 'jackass', severity: 1 }
];

// Short roots that collide with common innocent words when matched as a
// loose substring — these are checked only against whole, boundary-safe
// tokens (see matchesBoundaryWord in index.js), not the fuzzy/smashed pass.
const ENGLISH_BOUNDARY_ONLY = [
  { word: 'ass', severity: 1 },
  { word: 'dick', severity: 1 },
  { word: 'hell', severity: 1 },
  { word: 'damn', severity: 1 },
  { word: 'crap', severity: 1 }
];

const FILIPINO = [
  { word: 'putangina', severity: 3 },
  { word: 'tangina', severity: 3 },
  { word: 'putanginamo', severity: 3 },
  { word: 'kingina', severity: 3 },
  { word: 'pakyu', severity: 2 },
  { word: 'gago', severity: 2 },
  { word: 'gaga', severity: 2 },
  { word: 'ulol', severity: 2 },
  { word: 'tarantado', severity: 2 },
  { word: 'tarantada', severity: 2 },
  { word: 'punyeta', severity: 1 },
  { word: 'leche', severity: 1 },
  { word: 'hayop', severity: 1 },
  { word: 'bwisit', severity: 1 },
  { word: 'buwisit', severity: 1 },
  { word: 'pakshet', severity: 2 },
  { word: 'peste', severity: 1 },
  { word: 'lintik', severity: 1 },
  { word: 'kupal', severity: 1 },
  { word: 'siraulo', severity: 1 },
  { word: 'engot', severity: 1 },
  { word: 'bobo', severity: 1 },
  { word: 'tanga', severity: 1 },
  { word: 'inutil', severity: 1 }
];

// Whole words that would otherwise trip a match (fuzzy or boundary) and
// cause false positives — stripped out of the text before checking.
// Add school-specific names/terms here if you get false positives.
const ALLOWLIST = [
  'assignment', 'assignments', 'assess', 'assessment', 'assessments',
  'assist', 'assistant', 'associate', 'association', 'assume', 'assumption',
  'class', 'classroom', 'classic', 'classmate', 'classmates',
  'pass', 'passed', 'passing', 'bypass', 'compass',
  'mass', 'massive', 'grass', 'brass', 'glass', 'embarrass', 'harassment',
  'password', 'passion'
];

module.exports = { ENGLISH, ENGLISH_BOUNDARY_ONLY, FILIPINO, ALLOWLIST };
