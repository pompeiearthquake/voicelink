const { ENGLISH, ENGLISH_BOUNDARY_ONLY, FILIPINO, ALLOWLIST } = require('./wordlist');
const { MIN_SEVERITY } = require('../config');

// A handful of lookalike characters people use to dodge filters —
// full-width letters, a few Cyrillic/Greek lookalikes, and common leet digits.
const CONFUSABLES = {
  '\u0430': 'a', '\u0410': 'a', // Cyrillic а/А
  '\u0435': 'e', '\u0415': 'e', // Cyrillic е/Е
  '\u043e': 'o', '\u041e': 'o', // Cyrillic о/О
  '\u0440': 'p', // Cyrillic р
  '\u0441': 'c', '\u0421': 'c', // Cyrillic с/С
  '\u0456': 'i', '\u0406': 'i', // Cyrillic і/І
  '\u03b1': 'a', '\u0391': 'a', // Greek alpha
  '\u03bf': 'o', '\u039f': 'o', // Greek omicron
  '\u0399': 'i', '\u03b9': 'i', // Greek iota
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  '@': 'a', '$': 's', '!': 'i', '+': 't', '|': 'l'
};

// Per-letter character classes used when building the fuzzy regex, so a
// substitution like "4" for "a" is caught even where CONFUSABLES above
// (a straight character swap) wouldn't apply because of how it's embedded.
const LETTER_CLASS = {
  a: 'a4@', b: 'b8', c: 'c', d: 'd', e: 'e3', f: 'f', g: 'g9',
  h: 'h', i: 'i1!|', j: 'j', k: 'k', l: 'l1|', m: 'm', n: 'n',
  o: 'o0', p: 'p', q: 'q', r: 'r', s: 's5$', t: 't7+', u: 'uv',
  v: 'vu', w: 'w', x: 'x', y: 'y', z: 'z2'
};

function stripDiacritics(str) {
  return str.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');
}

function applyConfusables(str) {
  return str.replace(/./gsu, ch => CONFUSABLES[ch] || ch);
}

function removeAllowlisted(str) {
  let out = str;
  for (const word of ALLOWLIST) {
    out = out.replace(new RegExp('\\b' + word + '\\b', 'gi'), ' ');
  }
  return out;
}

// Builds a regex that matches a root word even when letters are stretched
// ("fuuuck"), separated by symbols/spaces ("f.u c-k"), or leetspeak-swapped
// ("f4ck") — but keeps the gap between letters small so it can't fire
// across unrelated parts of a long message.
const regexCache = new Map();
function buildFuzzyRegex(root) {
  if (regexCache.has(root)) return regexCache.get(root);
  const pattern = root
    .split('')
    .map(ch => {
      const cls = LETTER_CLASS[ch] || ch;
      // Each letter position accepts the real letter/its lookalikes OR a
      // masking symbol (the "*" in "f*ck", "sh*t"), then a small gap of
      // separators before the next letter.
      return `(?:[${cls}]|[*#])+[\\s\\W_]{0,2}`;
    })
    .join('');
  const re = new RegExp(pattern, 'i');
  regexCache.set(root, re);
  return re;
}

function matchesBoundaryWord(normalizedTokens, root) {
  return normalizedTokens.includes(root);
}

function normalizeForMatching(text) {
  let s = text.toLowerCase();
  s = stripDiacritics(s);
  s = applyConfusables(s);
  s = removeAllowlisted(s);
  return s;
}

/**
 * Checks text against the word lists.
 * Returns { blocked, severity, hits } — hits is a count only (never the
 * matched words themselves), so callers can log/tune without the filter's
 * own responses becoming a way to test which words trip it.
 */
function evaluateText(text) {
  if (!text) return { blocked: false, severity: 0, hits: 0 };

  const normalized = normalizeForMatching(text);
  const smashed = normalized.replace(/[^a-z0-9]/g, ''); // for the fuzzy pass
  const tokens = normalized.split(/[^a-z0-9]+/).filter(Boolean).map(t => t.replace(/(.)\1{2,}/g, '$1$1'));

  let maxSeverity = 0;
  let hits = 0;

  for (const { word, severity } of [...ENGLISH, ...FILIPINO]) {
    if (buildFuzzyRegex(word).test(smashed) || buildFuzzyRegex(word).test(normalized)) {
      hits++;
      if (severity > maxSeverity) maxSeverity = severity;
    }
  }

  for (const { word, severity } of ENGLISH_BOUNDARY_ONLY) {
    if (matchesBoundaryWord(tokens, word)) {
      hits++;
      if (severity > maxSeverity) maxSeverity = severity;
    }
  }

  return { blocked: hits > 0 && maxSeverity >= MIN_SEVERITY, severity: maxSeverity, hits };
}

module.exports = { evaluateText };
