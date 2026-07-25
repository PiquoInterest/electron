'use strict';

// Entry point so that the documented command works verbatim:
//
//   node --test spec/security-review/
//
// Node 22's test runner treats a bare positional path as a file to execute
// rather than a directory to walk, and CommonJS resolution of a directory
// lands on its index.js. Requiring the suites here registers every test in a
// single runner process.
//
// The individual suites are also picked up on their own by a plain
// `node --test` (they match the default `**/*.test.js` pattern), and by
// `node --test 'spec/security-review/*.test.js'`. This file is deliberately
// NOT named *.test.js so those invocations never double-register anything.

require('./static-invariants.test.js');
require('./cookie-domain-match.test.js');
