'use strict';

// Zero-dependency helpers for the security-review characterization suite.
//
// Everything here uses only Node built-ins (node:fs, node:path,
// node:child_process). Nothing from the Electron repo is imported, nothing is
// compiled, and no built Electron binary is required.
//
// The point of these helpers is to let the tests make *structural* claims
// about C++/TS source (brace matching, enclosing-block discovery, statement
// boundaries) rather than fragile line-number or grep claims.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** Absolute path for a repo-relative path. */
function repoPath (rel) {
  return path.join(REPO_ROOT, rel);
}

/** Read a repo-relative file as UTF-8. Throws a useful message if missing. */
function readRepoFile (rel) {
  const abs = repoPath(rel);
  if (!fs.existsSync(abs)) {
    throw new Error(`expected file to exist: ${abs}`);
  }
  return fs.readFileSync(abs, 'utf8');
}

function repoFileExists (rel) {
  return fs.existsSync(repoPath(rel));
}

/** 1-based line number of a character offset. */
function lineOf (text, index) {
  if (index < 0) throw new Error('lineOf: negative index');
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

/** The full text of the line containing `index`. */
function lineTextAt (text, index) {
  const start = text.lastIndexOf('\n', index - 1) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end);
}

/** indexOf that throws instead of silently returning -1. */
function mustIndexOf (text, needle, from = 0, label = '') {
  const idx = text.indexOf(needle, from);
  if (idx === -1) {
    throw new Error(
      `expected to find ${JSON.stringify(needle)}${label ? ` (${label})` : ''} ` +
      `at or after offset ${from}, but it is absent`);
  }
  return idx;
}

function countOccurrences (text, needle) {
  let n = 0;
  let i = text.indexOf(needle);
  while (i !== -1) {
    n++;
    i = text.indexOf(needle, i + needle.length);
  }
  return n;
}

// ---------------------------------------------------------------------------
// C-like source scanning (comment / string / char-literal aware)
// ---------------------------------------------------------------------------

const CHAR_LITERAL_RE = /^'(?:\\.|[^'\\])'/;

// Returns the offset just past whatever non-code construct starts at `i`,
// or -1 if `i` is ordinary code.
function skipNonCode (text, i) {
  const c = text[i];
  if (c === '/' && text[i + 1] === '/') {
    const nl = text.indexOf('\n', i);
    return nl === -1 ? text.length : nl;
  }
  if (c === '/' && text[i + 1] === '*') {
    const end = text.indexOf('*/', i + 2);
    return end === -1 ? text.length : end + 2;
  }
  if (c === '"') {
    let j = i + 1;
    while (j < text.length) {
      if (text[j] === '\\') { j += 2; continue; }
      if (text[j] === '"') return j + 1;
      j++;
    }
    return text.length;
  }
  if (c === "'") {
    const m = CHAR_LITERAL_RE.exec(text.slice(i, i + 8));
    if (m) return i + m[0].length;
    return -1; // a bare apostrophe in code (digit separator etc.) - treat as code
  }
  return -1;
}

/**
 * Given the offset of an opening bracket, return the offset of its match.
 * Skips comments, string literals and char literals.
 */
function matchBracket (text, openIdx) {
  const open = text[openIdx];
  const close = { '{': '}', '(': ')', '[': ']' }[open];
  if (!close) {
    throw new Error(`matchBracket: offset ${openIdx} is ${JSON.stringify(open)}, not an opening bracket`);
  }
  let depth = 0;
  let i = openIdx;
  while (i < text.length) {
    const skipped = skipNonCode(text, i);
    if (skipped !== -1) { i = skipped; continue; }
    const c = text[i];
    if (c === open) { depth++; i++; continue; }
    if (c === close) {
      depth--;
      if (depth === 0) return i;
      i++;
      continue;
    }
    i++;
  }
  throw new Error(`matchBracket: unbalanced ${open} starting at offset ${openIdx} (line ${lineOf(text, openIdx)})`);
}

/**
 * Locate a function *definition* by an anchor that appears in its signature.
 * Returns { anchor, bodyOpen, bodyClose, body } where `body` includes braces.
 *
 * Picks the occurrence of `anchor` whose next `{` comes before the next `;`,
 * i.e. a definition rather than a forward declaration.
 */
function findFunctionBody (text, anchor) {
  let from = 0;
  for (;;) {
    const at = text.indexOf(anchor, from);
    if (at === -1) break;
    const brace = text.indexOf('{', at);
    const semi = text.indexOf(';', at);
    if (brace !== -1 && (semi === -1 || brace < semi)) {
      const bodyClose = matchBracket(text, brace);
      return {
        anchor: at,
        bodyOpen: brace,
        bodyClose,
        body: text.slice(brace, bodyClose + 1)
      };
    }
    from = at + anchor.length;
  }
  throw new Error(`findFunctionBody: no definition found for anchor ${JSON.stringify(anchor)}`);
}

/**
 * Offsets of every `{` that is still open at `targetIdx`, scanning forward
 * from `from`. Outermost first. Lambda bodies that open *after* targetIdx are
 * naturally excluded.
 */
function enclosingBraces (text, from, targetIdx) {
  const stack = [];
  let i = from;
  while (i < targetIdx && i < text.length) {
    const skipped = skipNonCode(text, i);
    if (skipped !== -1) {
      if (skipped > targetIdx) break;
      i = skipped;
      continue;
    }
    const c = text[i];
    if (c === '{') stack.push(i);
    else if (c === '}') stack.pop();
    i++;
  }
  return stack;
}

/**
 * The source text of the statement/condition immediately preceding the `{` at
 * `openIdx`, scanning forward from `from` so that comments and strings are
 * handled correctly. Useful for reading an `if (...)` condition off its block.
 */
function conditionOfBlock (text, from, openIdx) {
  let last = from - 1;
  let i = from;
  while (i < openIdx) {
    const skipped = skipNonCode(text, i);
    if (skipped !== -1) {
      if (skipped > openIdx) break;
      i = skipped;
      continue;
    }
    const c = text[i];
    if (c === ';' || c === '{' || c === '}') last = i;
    i++;
  }
  return text.slice(last + 1, openIdx);
}

/**
 * Walk back over whitespace/newlines from `idx` and return the first
 * non-whitespace character before it (or '' at start of file).
 */
function previousCodeChar (text, idx) {
  let i = idx - 1;
  while (i >= 0 && /\s/.test(text[i])) i--;
  return i >= 0 ? text[i] : '';
}

// ---------------------------------------------------------------------------
// grep
// ---------------------------------------------------------------------------

// This suite quotes the very symbols it searches for, so its own sources would
// otherwise show up as "usages" of the dead code it is characterizing.
const SELF_DIR = 'spec/security-review/';

/**
 * Recursive grep over the repo, excluding build output, VCS dirs, and this
 * suite's own sources.
 * Returns [{ file, line, text }]. Empty array when there are no matches.
 */
function grepRepo (pattern, { regex = false, dir = '.', includeSelf = false } = {}) {
  const args = [
    '-rn',
    '--binary-files=without-match',
    '--exclude-dir=out',
    '--exclude-dir=.git',
    '--exclude-dir=node_modules',
    regex ? '-E' : '-F',
    '--',
    pattern,
    dir
  ];
  const res = spawnSync('grep', args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024
  });
  if (res.error) throw res.error;
  if (res.status === 1) return [];
  if (res.status !== 0) {
    throw new Error(`grep failed (status ${res.status}): ${res.stderr}`);
  }
  return res.stdout.split('\n').filter(Boolean).map((raw) => {
    const first = raw.indexOf(':');
    const second = raw.indexOf(':', first + 1);
    return {
      file: raw.slice(0, first).replace(/^\.\//, ''),
      line: Number(raw.slice(first + 1, second)),
      text: raw.slice(second + 1)
    };
  }).filter((hit) => includeSelf || !hit.file.startsWith(SELF_DIR));
}

module.exports = {
  REPO_ROOT,
  repoPath,
  readRepoFile,
  repoFileExists,
  lineOf,
  lineTextAt,
  mustIndexOf,
  countOccurrences,
  matchBracket,
  findFunctionBody,
  enclosingBraces,
  conditionOfBlock,
  previousCodeChar,
  grepRepo
};
