'use strict';

const fs = require('node:fs');

const [reportPath, manifestPath, ...selectedFiles] = process.argv.slice(2);
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
const failed = [];
const reported = new Map();

function visitSuite(suite, parents = [], inheritedFile) {
  const suiteFile = suite.file || inheritedFile;
  const fileContainer = suite.title && suite.file && suite.title === suite.file;
  const suiteParents = suite.title && !fileContainer ? [...parents, suite.title] : parents;
  for (const spec of suite.specs || []) {
    const file = spec.file || suiteFile;
    const title = [...suiteParents, spec.title || '<unnamed test>'].join(' › ');
    const identity = `${file}\u0000${title}`;
    if (reported.has(identity)) failed.push(`duplicate report identity: ${file} › ${title}`);
    reported.set(identity, spec);
    if ((spec.tests || []).length !== 1) {
      failed.push(`${file} › ${title}: expected one Chromium test result, found ${(spec.tests || []).length}`);
    }
    for (const test of spec.tests || []) {
      const results = test.results || [];
      if (results.length === 0) {
        unrun.push(`${file} › ${title}`);
        continue;
      }
      for (const result of results) {
        if (result.status === 'skipped') skipped.push(`${file} › ${title}`);
        else if (result.status === 'interrupted') unrun.push(`${file} › ${title}`);
        else if (result.status !== 'passed') failed.push(`${file} › ${title}: ${result.status || 'unknown status'}`);
      }
      if (test.status !== 'expected') failed.push(`${file} › ${title}: ${test.status || 'unknown test status'}`);
    }
  }
  for (const child of suite.suites || []) visitSuite(child, suiteParents, suiteFile);
}

for (const suite of report.suites || []) visitSuite(suite);

const uniqueSkipped = [...new Set(skipped)];
const uniqueUnrun = [...new Set(unrun)];
const uniqueFailed = [...new Set(failed)];
let missing = [];
let unexpected = [];
let expectedCount;

if (manifestPath || selectedFiles.length) {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    console.error(`CI_VERIFY_FAILURE: cannot read product Playwright manifest: ${error.message}`);
    process.exit(1);
  }
  if (manifest?.version !== 1 || !Array.isArray(manifest.files) || !Array.isArray(manifest.tests)) {
    console.error('CI_VERIFY_FAILURE: product Playwright manifest has an unsupported shape');
    process.exit(1);
  }
  const selected = new Set(selectedFiles);
  if (selected.size === 0 || selected.size !== selectedFiles.length) {
    console.error('CI_VERIFY_FAILURE: product result audit requires distinct selected spec files');
    process.exit(1);
  }
  for (const file of selected) {
    if (!manifest.files.includes(file)) {
      console.error(`CI_VERIFY_FAILURE: selected product spec is not approved: ${file}`);
      process.exit(1);
    }
  }
  const expected = new Set(
    manifest.tests
      .filter((entry) => selected.has(entry.file))
      .map((entry) => `${entry.file}\u0000${entry.title}`),
  );
  expectedCount = expected.size;
  missing = [...expected].filter((identity) => !reported.has(identity));
  unexpected = [...reported.keys()].filter((identity) => !expected.has(identity));
  if (expectedCount === 0) uniqueFailed.push('selected product specs contain no approved tests');
  if ((report.stats?.expected || 0) !== expectedCount) {
    uniqueFailed.push(`report passed ${report.stats?.expected || 0}/${expectedCount} selected product tests`);
  }
  if ((report.stats?.skipped || 0) !== 0 || (report.stats?.unexpected || 0) !== 0 || (report.stats?.flaky || 0) !== 0) {
    uniqueFailed.push(
      `report stats were skipped=${report.stats?.skipped || 0} unexpected=${report.stats?.unexpected || 0} flaky=${report.stats?.flaky || 0}`,
    );
  }
}

console.log(
  `Playwright result audit: selected=${expectedCount ?? 'unbounded'} reported=${reported.size} `
    + `skipped=${uniqueSkipped.length} unrun=${uniqueUnrun.length} failed=${uniqueFailed.length}`,
);
if (uniqueSkipped.length || uniqueUnrun.length || uniqueFailed.length || missing.length || unexpected.length) {
  for (const title of uniqueSkipped) console.error(`CI_VERIFY_FAILURE: skipped test: ${title}`);
  for (const title of uniqueUnrun) console.error(`CI_VERIFY_FAILURE: unrun test: ${title}`);
  for (const title of uniqueFailed) console.error(`CI_VERIFY_FAILURE: failed test: ${title}`);
  for (const identity of missing) console.error(`CI_VERIFY_FAILURE: selected test missing from report: ${identity.replace('\u0000', ' › ')}`);
  for (const identity of unexpected) console.error(`CI_VERIFY_FAILURE: unselected test present in report: ${identity.replace('\u0000', ' › ')}`);
  process.exit(1);
}
