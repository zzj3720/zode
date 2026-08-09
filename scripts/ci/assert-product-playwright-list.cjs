'use strict';

const fs = require('node:fs');
const path = require('node:path');

const [listPath, specRoot, manifestPath] = process.argv.slice(2);
const EXPECTED_FILE_COUNT = 25;
const EXPECTED_TEST_COUNT = 58;
if (!listPath || !specRoot || !manifestPath) {
  console.error('CI_VERIFY_FAILURE: product Playwright list, spec root, and manifest are required');
  process.exit(1);
}

function walk(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(entryPath));
    else if (/\.spec\.(?:cjs|ts)$/.test(entry.name)) files.push(entryPath);
  }
  return files;
}

let listing;
try {
  listing = fs.readFileSync(listPath, 'utf8');
} catch (error) {
  console.error(`CI_VERIFY_FAILURE: cannot read product Playwright list: ${error.message}`);
  process.exit(1);
}

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

const root = path.resolve(specRoot, '..');
const actualFiles = new Set(
  walk(specRoot)
    .map((file) => path.relative(root, file).split(path.sep).join('/'))
    .sort(),
);
const expectedFiles = new Set(manifest.files);
const discoveredFiles = new Set();
const discoveredTests = new Set();
const testLine = /^\s+\[chromium\]\s+›\s+(specs\/[^:\s]+\.spec\.(?:cjs|ts)):\d+:\d+\s+›\s+(.*)$/gm;
const listedEntries = [...listing.matchAll(testLine)];
for (const match of listedEntries) {
  discoveredFiles.add(match[1]);
  discoveredTests.add(`${match[1]}\u0000${match[2].trim()}`);
}

const manifestTests = new Set(
  manifest.tests.map((entry) => `${entry.file}\u0000${entry.title}`),
);
const duplicateManifestTests = manifest.tests.length - manifestTests.size;
const missingCheckoutFiles = [...expectedFiles].filter((file) => !actualFiles.has(file));
const unexpectedCheckoutFiles = [...actualFiles].filter((file) => !expectedFiles.has(file));
const missingCollectedFiles = [...expectedFiles].filter((file) => !discoveredFiles.has(file));
const unexpectedCollectedFiles = [...discoveredFiles].filter((file) => !expectedFiles.has(file));
const missingTests = [...manifestTests].filter((test) => !discoveredTests.has(test));
const unexpectedTests = [...discoveredTests].filter((test) => !manifestTests.has(test));
const total = listing.match(/^Total:\s+(\d+)\s+tests\s+in\s+(\d+)\s+files/m);
const listedTestCount = total ? Number(total[1]) : undefined;
const listedFileCount = total ? Number(total[2]) : undefined;
console.log(
  `Product Playwright collection audit: expected_files=${expectedFiles.size} ` +
    `collected_files=${discoveredFiles.size} listed_tests=${listedTestCount ?? 'unknown'}`,
);
if (
  missingCheckoutFiles.length
  || unexpectedCheckoutFiles.length
  || missingCollectedFiles.length
  || unexpectedCollectedFiles.length
  || missingTests.length
  || unexpectedTests.length
  || duplicateManifestTests
  || !total
  || expectedFiles.size !== EXPECTED_FILE_COUNT
  || manifest.tests.length !== EXPECTED_TEST_COUNT
  || actualFiles.size !== EXPECTED_FILE_COUNT
  || discoveredFiles.size !== EXPECTED_FILE_COUNT
  || listedFileCount !== EXPECTED_FILE_COUNT
  || listedEntries.length !== EXPECTED_TEST_COUNT
  || listedTestCount !== EXPECTED_TEST_COUNT
) {
  for (const file of missingCheckoutFiles) console.error(`CI_VERIFY_FAILURE: manifest file is missing from checkout: ${file}`);
  for (const file of unexpectedCheckoutFiles) console.error(`CI_VERIFY_FAILURE: unmanifested product spec is in checkout: ${file}`);
  for (const file of missingCollectedFiles) console.error(`CI_VERIFY_FAILURE: approved product spec file was not collected: ${file}`);
  for (const file of unexpectedCollectedFiles) console.error(`CI_VERIFY_FAILURE: unapproved product spec was collected: ${file}`);
  for (const test of missingTests) console.error(`CI_VERIFY_FAILURE: approved product test was not collected: ${test.replace('\u0000', ' › ')}`);
  for (const test of unexpectedTests) console.error(`CI_VERIFY_FAILURE: unapproved product test was collected: ${test.replace('\u0000', ' › ')}`);
  if (duplicateManifestTests) console.error(`CI_VERIFY_FAILURE: product manifest has ${duplicateManifestTests} duplicate test identities`);
  if (!total) console.error('CI_VERIFY_FAILURE: Playwright list did not report a test total');
  if (expectedFiles.size !== EXPECTED_FILE_COUNT) {
    console.error(`CI_VERIFY_FAILURE: manifest product file count changed: ${expectedFiles.size}/${EXPECTED_FILE_COUNT}`);
  }
  if (manifest.tests.length !== EXPECTED_TEST_COUNT) {
    console.error(`CI_VERIFY_FAILURE: manifest product test count changed: ${manifest.tests.length}/${EXPECTED_TEST_COUNT}`);
  }
  if (actualFiles.size !== EXPECTED_FILE_COUNT) {
    console.error(`CI_VERIFY_FAILURE: checkout product file count changed: ${actualFiles.size}/${EXPECTED_FILE_COUNT}`);
  }
  if (listedFileCount !== EXPECTED_FILE_COUNT) {
    console.error(`CI_VERIFY_FAILURE: Playwright listed ${listedFileCount ?? 'unknown'} files; expected ${EXPECTED_FILE_COUNT}`);
  }
  if (listedTestCount !== EXPECTED_TEST_COUNT) {
    console.error(`CI_VERIFY_FAILURE: Playwright listed ${listedTestCount ?? 'unknown'} tests; expected ${EXPECTED_TEST_COUNT}`);
  }
  if (listedEntries.length !== EXPECTED_TEST_COUNT) {
    console.error(`CI_VERIFY_FAILURE: Playwright emitted ${listedEntries.length} test lines; expected ${EXPECTED_TEST_COUNT}`);
  }
  process.exit(1);
}
