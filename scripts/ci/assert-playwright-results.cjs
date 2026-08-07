'use strict';

const fs = require('node:fs');

const [reportPath] = process.argv.slice(2);
if (!reportPath) {
  console.error('CI_VERIFY_FAILURE: Playwright JSON report path is required');
  process.exit(1);
}

let report;
try {
  report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
} catch (error) {
  console.error(`CI_VERIFY_FAILURE: cannot read Playwright JSON report: ${error.message}`);
  process.exit(1);
}

const skipped = [];
const unrun = [];

function visitSuite(suite, parents = []) {
  const suiteParents = suite.title ? [...parents, suite.title] : parents;
  for (const spec of suite.specs || []) {
    const specParents = spec.title ? [...suiteParents, spec.title] : suiteParents;
    for (const test of spec.tests || []) {
      const title = [...specParents, test.title || '<unnamed test>'].join(' › ');
      const results = test.results || [];
      if (results.length === 0) {
        unrun.push(title);
        continue;
      }
      for (const result of results) {
        if (result.status === 'skipped') skipped.push(title);
        if (result.status === 'interrupted') unrun.push(title);
      }
    }
  }
  for (const child of suite.suites || []) visitSuite(child, suiteParents);
}

for (const suite of report.suites || []) visitSuite(suite);

const uniqueSkipped = [...new Set(skipped)];
const uniqueUnrun = [...new Set(unrun)];
console.log(`Playwright result audit: skipped=${uniqueSkipped.length} unrun=${uniqueUnrun.length}`);
if (uniqueSkipped.length || uniqueUnrun.length) {
  for (const title of uniqueSkipped) console.error(`CI_VERIFY_FAILURE: skipped test: ${title}`);
  for (const title of uniqueUnrun) console.error(`CI_VERIFY_FAILURE: unrun test: ${title}`);
  process.exit(1);
}
