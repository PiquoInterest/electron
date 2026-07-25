'use strict';

// =============================================================================
// CHARACTERIZATION: cookies.get({ domain }) semantic inversion
// =============================================================================
//
// Companion to the `cookie-docs-code-mismatch` test in static-invariants.test.js.
// That one proves the *shape* of the defect statically. This one proves the
// *semantics* executably, with zero dependencies and no built Electron: both
// predicates are re-implemented in plain JS and run against each other.
//
// Same rules as the rest of this directory: a PASSING test means the defect is
// STILL PRESENT. When the C++ or the docs are fixed, delete these tests rather
// than repairing them.
//
// -----------------------------------------------------------------------------
// WHAT CHANGED
// -----------------------------------------------------------------------------
//
// Commit 74c4ae0b5 ("refactor: use `net::CanonicalCookie::IsDomainMatch()`",
// electron/electron#46748) deleted Electron's bespoke domain-filter predicate
// and delegated to Chromium's. The two are not equivalent - they evaluate the
// domain relation in OPPOSITE directions.
//
// BEFORE (deleted; verbatim from
//   `git show 74c4ae0b5^:shell/browser/api/electron_api_cookies.cc`):
//
//   bool MatchesDomain(std::string filter, const std::string& domain) {
//     // Add a leading '.' character to the filter domain if it doesn't exist.
//     if (net::cookie_util::DomainIsHostOnly(filter))
//       filter.insert(0, ".");
//
//     std::string sub_domain(domain);
//     // Strip any leading '.' character from the input cookie domain.
//     if (!net::cookie_util::DomainIsHostOnly(sub_domain))
//       sub_domain = sub_domain.substr(1);
//
//     // Now check whether the domain argument is a subdomain of the filter domain.
//     for (sub_domain.insert(0, "."); sub_domain.length() >= filter.length();) {
//       if (sub_domain == filter)
//         return true;
//       const size_t next_dot = sub_domain.find('.', 1);  // Skip over leading dot.
//       sub_domain.erase(0, next_dot);
//     }
//     return false;
//   }
//
// ...called as `MatchesDomain(*str /* the user filter */, cookie.Domain())`.
//
// AFTER (current tree, shell/browser/api/electron_api_cookies.cc):
//
//   if ((str = filter.FindString("domain")) && !cookie.IsDomainMatch(*str))
//     return false;
//
// `net::CanonicalCookie::IsDomainMatch(host)` forwards to
// `net::cookie_util::IsDomainMatch(cookie.Domain(), host)`, i.e. it answers
// "would this cookie be SENT to `host`?" - so the user's filter string is now
// being interpreted as a *request host*, not as a parent domain.
//
// Old question: "is the cookie's domain the filter, or a subdomain of it?"
// New question: "would this cookie be delivered to a request for the filter?"
//
// Those are inverses of one another, which is why the two disagree in BOTH
// directions below: one regression (cookies that used to be returned no longer
// are) and one over-match (cookies that were never returned now are).
// =============================================================================

const test = require('node:test');
const assert = require('node:assert');

const { readRepoFile, lineOf } = require('./helpers');

// -----------------------------------------------------------------------------
// Ports
// -----------------------------------------------------------------------------

// Port of net::cookie_util::DomainIsHostOnly:
//   bool DomainIsHostOnly(const std::string& domain_string) {
//     return (domain_string.empty() || domain_string[0] != '.');
//   }
function domainIsHostOnly (domainString) {
  return domainString.length === 0 || domainString[0] !== '.';
}

/**
 * Port of the DELETED Electron helper `MatchesDomain(filter, domain)` quoted
 * verbatim in the header comment above.
 *
 * Note on the C++/JS erase mapping: `std::string::erase(0, npos)` (which is
 * what happens when `find` returns npos) truncates to the empty string, so the
 * JS equivalent of `next_dot == npos` is assigning ''.
 */
function oldMatchesDomain (filterIn, domain) {
  let filter = filterIn;
  // if (net::cookie_util::DomainIsHostOnly(filter)) filter.insert(0, ".");
  if (domainIsHostOnly(filter)) filter = '.' + filter;

  // std::string sub_domain(domain);
  let subDomain = domain;
  // if (!DomainIsHostOnly(sub_domain)) sub_domain = sub_domain.substr(1);
  if (!domainIsHostOnly(subDomain)) subDomain = subDomain.substring(1);

  // for (sub_domain.insert(0, "."); sub_domain.length() >= filter.length();)
  subDomain = '.' + subDomain;
  while (subDomain.length >= filter.length) {
    if (subDomain === filter) return true;
    const nextDot = subDomain.indexOf('.', 1); // Skip over leading dot.
    subDomain = nextDot === -1 ? '' : subDomain.substring(nextDot);
  }
  return false;
}

/**
 * Port of net::cookie_util::IsDomainMatch(domain, host) - the predicate
 * CanonicalCookie::IsDomainMatch() delegates to:
 *
 *   if (host == domain) return true;
 *   if (domain.empty() || domain[0] != '.') return false;
 *   if (domain.compare(1, std::string::npos, host) == 0) return true;
 *   return (host.length() > domain.length() &&
 *           host.compare(host.length() - domain.length(),
 *                        domain.length(), domain) == 0);
 */
function newIsDomainMatch (cookieDomain, host) {
  if (host === cookieDomain) return true;
  if (cookieDomain.length === 0 || cookieDomain[0] !== '.') return false;
  if (cookieDomain.substring(1) === host) return true;
  return host.length > cookieDomain.length && host.endsWith(cookieDomain);
}

// Call-site wrappers, so the tests read in the API's own terms: "given this
// user filter, is this cookie returned by cookies.get()?"
//
//   old call site: MatchesDomain(*str, cookie.Domain())
//   new call site: cookie.IsDomainMatch(*str)
//                    == cookie_util::IsDomainMatch(cookie.Domain(), *str)
const oldReturnsCookie = (filter, cookieDomain) => oldMatchesDomain(filter, cookieDomain);
const newReturnsCookie = (filter, cookieDomain) => newIsDomainMatch(cookieDomain, filter);

// -----------------------------------------------------------------------------
// Sanity: the ports themselves behave as the C++ does
// -----------------------------------------------------------------------------

test('port sanity: DomainIsHostOnly matches the C++ definition', () => {
  assert.strictEqual(domainIsHostOnly('example.com'), true);
  assert.strictEqual(domainIsHostOnly('.example.com'), false);
  assert.strictEqual(domainIsHostOnly(''), true);
});

test('port sanity: each predicate is reflexive and rejects unrelated domains', () => {
  // Identical domains match under both, in both spellings.
  assert.strictEqual(oldReturnsCookie('example.com', 'example.com'), true);
  assert.strictEqual(newReturnsCookie('example.com', 'example.com'), true);

  // Completely unrelated domains match under neither.
  assert.strictEqual(oldReturnsCookie('example.com', 'evil.test'), false);
  assert.strictEqual(newReturnsCookie('example.com', 'evil.test'), false);

  // A suffix that is not a domain boundary must not match either
  // ("notexample.com" is not a subdomain of "example.com").
  assert.strictEqual(oldReturnsCookie('example.com', 'notexample.com'), false);
  assert.strictEqual(newReturnsCookie('example.com', 'notexample.com'), false);
});

// -----------------------------------------------------------------------------
// The differential
// -----------------------------------------------------------------------------

test('DEFECT STILL PRESENT: REGRESSION - host-only subdomain cookie no longer returned by a parent-domain filter', () => {
  // cookies.get({ domain: 'example.com' }) against a host-only cookie whose
  // domain is 'sub.example.com'.
  const filter = 'example.com';
  const cookieDomain = 'sub.example.com';

  // Documented + historical behaviour: the cookie IS a subdomain of the
  // filter, so it was returned.
  assert.strictEqual(oldReturnsCookie(filter, cookieDomain), true,
    'the deleted MatchesDomain returned host-only subdomain cookies');

  // Current behaviour: a host-only cookie for sub.example.com is never sent to
  // a request for example.com, so the delivery predicate says no.
  assert.strictEqual(newReturnsCookie(filter, cookieDomain), false,
    'CanonicalCookie::IsDomainMatch rejects it - the cookie silently disappears from cookies.get()');

  assert.notStrictEqual(oldReturnsCookie(filter, cookieDomain), newReturnsCookie(filter, cookieDomain),
    'the two predicates disagree: this is a silent behavioural regression');

  // This generalises to any depth of host-only subdomain.
  for (const domain of ['a.example.com', 'a.b.example.com', 'deep.a.b.example.com']) {
    assert.strictEqual(oldReturnsCookie('example.com', domain), true, `old should match ${domain}`);
    assert.strictEqual(newReturnsCookie('example.com', domain), false, `new should reject ${domain}`);
  }

  // A FIX (restoring subdomain-of-filter semantics in the C++) makes the two
  // predicates agree, so the notStrictEqual assertion above would fail.
});

test('DEFECT STILL PRESENT: NEW OVER-MATCH - domain cookie now returned by a filter naming a deeper host', () => {
  // cookies.get({ domain: 'a.b.example.com' }) against a domain cookie
  // '.example.com'.
  const filter = 'a.b.example.com';
  const cookieDomain = '.example.com';

  // Historical behaviour: '.example.com' is a PARENT of the filter, not a
  // subdomain of it, so it was NOT returned.
  assert.strictEqual(oldReturnsCookie(filter, cookieDomain), false,
    'the deleted MatchesDomain rejected parent-domain cookies');

  // Current behaviour: '.example.com' WOULD be sent to a request for
  // a.b.example.com, so the delivery predicate says yes. The filter now
  // surfaces cookies the caller did not ask about.
  assert.strictEqual(newReturnsCookie(filter, cookieDomain), true,
    'CanonicalCookie::IsDomainMatch accepts it - cookies.get() now over-returns');

  assert.notStrictEqual(oldReturnsCookie(filter, cookieDomain), newReturnsCookie(filter, cookieDomain),
    'the two predicates disagree: this is a new over-match');

  // Same inversion for any parent domain of the filter.
  for (const domain of ['.b.example.com', '.example.com', '.com']) {
    assert.strictEqual(oldReturnsCookie(filter, domain), false, `old should reject ${domain}`);
    assert.strictEqual(newReturnsCookie(filter, domain), true, `new should match ${domain}`);
  }
});

test('DEFECT STILL PRESENT: the disagreement is a direction inversion, not noise', () => {
  // A compact truth table over both predicates. `old` and `new` are the
  // expected results; every row is asserted, so this both documents and
  // enforces the exact shape of the inversion.
  const rows = [
    // filter,             cookie domain,        old,   new
    ['example.com', 'example.com', true, true], // agree: exact
    ['example.com', '.example.com', true, true], // agree: domain cookie for the filter itself
    ['example.com', 'evil.test', false, false], // agree: unrelated
    ['example.com', 'notexample.com', false, false], // agree: non-boundary suffix
    ['example.com', 'sub.example.com', true, false], // DISAGREE: regression
    ['example.com', '.sub.example.com', true, false], // DISAGREE: regression (domain cookie)
    ['a.b.example.com', '.example.com', false, true], // DISAGREE: over-match
    ['a.b.example.com', 'a.b.example.com', true, true], // agree: exact, deeper
    ['sub.example.com', 'example.com', false, false] // agree: parent host-only cookie
  ];

  const disagreements = [];
  for (const [filter, cookieDomain, expectedOld, expectedNew] of rows) {
    const gotOld = oldReturnsCookie(filter, cookieDomain);
    const gotNew = newReturnsCookie(filter, cookieDomain);
    assert.strictEqual(gotOld, expectedOld,
      `old predicate: filter=${filter} cookie=${cookieDomain}`);
    assert.strictEqual(gotNew, expectedNew,
      `new predicate: filter=${filter} cookie=${cookieDomain}`);
    if (gotOld !== gotNew) disagreements.push(`${filter} vs ${cookieDomain}`);
  }

  // The test discriminates: most rows agree. If the two predicates were
  // identical (or if the port were broken into always-true/always-false), this
  // would not hold.
  assert.strictEqual(disagreements.length, 3,
    `expected exactly three disagreeing rows, got: ${JSON.stringify(disagreements)}`);
  assert.ok(disagreements.length < rows.length,
    'sanity: the predicates agree on most inputs, so the disagreements are meaningful');
});

test('DEFECT STILL PRESENT: the documented contract matches the OLD predicate, not the shipped one', () => {
  // Tie the executable proof back to the tree: the docs describe
  // "cookies whose domains match or are subdomains of" the filter, which is
  // exactly oldMatchesDomain. The shipped code implements newIsDomainMatch.
  const docsFile = 'docs/api/cookies.md';
  const docs = readRepoFile(docsFile);
  const docsAt = docs.indexOf('subdomains of');
  assert.notStrictEqual(docsAt, -1,
    `${docsFile} should still document subdomain-of-filter semantics`);

  const cxxFile = 'shell/browser/api/electron_api_cookies.cc';
  const cxx = readRepoFile(cxxFile);
  const cxxAt = cxx.indexOf('cookie.IsDomainMatch(*str)');
  assert.notStrictEqual(cxxAt, -1,
    `${cxxFile} should still use the delivery predicate`);

  // The documented case (`docs/api/cookies.md:${line}`) is precisely the case
  // where the shipped predicate returns the wrong answer.
  const docsLine = lineOf(docs, docsAt);
  const cxxLine = lineOf(cxx, cxxAt);
  assert.ok(docsLine > 0 && cxxLine > 0);
  assert.strictEqual(
    oldReturnsCookie('example.com', 'sub.example.com'), true,
    `${docsFile}:${docsLine} promises this cookie is returned`);
  assert.strictEqual(
    newReturnsCookie('example.com', 'sub.example.com'), false,
    `${cxxFile}:${cxxLine} does not return it`);

  // A FIX to either side removes one of the two anchors above, failing this test.
});
