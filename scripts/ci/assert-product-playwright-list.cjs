'use strict';

const fs = require('node:fs');
const path = require('node:path');

const [listPath, specRoot, manifestPath] = process.argv.slice(2);
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
let manifest;
try {
  listing = fs.readFileSync(listPath, 'utf8');
  manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
} catch (error) {
  console.error(`CI_VERIFY_FAILURE: cannot read product collection input: ${error.message}`);
  process.exit(1);
}
if (manifest?.version !== 1 || !Array.isArray(manifest.files) || !Array.isArray(manifest.tests)) {
  console.error('CI_VERIFY_FAILURE: product Playwright manifest has an unsupported shape');
  process.exit(1);
}

const root = path.resolve(specRoot, '..');
const actualFiles = new Set(
  walk(specRoot).map((file) => path.relative(root, file).split(path.sep).join('/')).sort(),
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

const manifestTests = new Set(manifest.tests.map((entry) => `${entry.file}\u0000${entry.title}`));
const missingCheckoutFiles = [...expectedFiles].filter((file) => !actualFiles.has(file));
const unexpectedCheckoutFiles = [...actualFiles].filter((file) => !expectedFiles.has(file));
const missingCollectedFiles = [...expectedFiles].filter((file) => !discoveredFiles.has(file));
const unexpectedCollectedFiles = [...discoveredFiles].filter((file) => !expectedFiles.has(file));
const missingTests = [...manifestTests].filter((test) => !discoveredTests.has(test));
const unexpectedTests = [...discoveredTests].filter((test) => !manifestTests.has(test));
const duplicateFiles = manifest.files.length - expectedFiles.size;
const duplicateTests = manifest.tests.length - manifestTests.size;
const total = listing.match(/^Total:\s+(\d+)\s+tests\s+in\s+(\d+)\s+files/m);
const listedTestCount = total ? Number(total[1]) : undefined;
const listedFileCount = total ? Number(total[2]) : undefined;

console.log(
  `Product Playwright collection audit: files=${discoveredFiles.size}/${expectedFiles.size} `
    + `tests=${listedTestCount ?? 'unknown'}/${manifestTests.size}`,
);
if (
  missingCheckoutFiles.length || unexpectedCheckoutFiles.length
  || missingCollectedFiles.length || unexpectedCollectedFiles.length
  || missingTests.length || unexpectedTests.length || duplicateFiles || duplicateTests
  || !total || listedFileCount !== expectedFiles.size || listedTestCount !== manifestTests.size
  || listedEntries.length !== manifestTests.size
) {
  for (const file of missingCheckoutFiles) console.error(`CI_VERIFY_FAILURE: manifest file is missing from checkout: ${file}`);
  for (const file of unexpectedCheckoutFiles) console.error(`CI_VERIFY_FAILURE: unmanifested product spec is in checkout: ${file}`);
  for (const file of missingCollectedFiles) console.error(`CI_VERIFY_FAILURE: approved product spec was not collected: ${file}`);
  for (const file of unexpectedCollectedFiles) console.error(`CI_VERIFY_FAILURE: unapproved product spec was collected: ${file}`);
  for (const test of missingTests) console.error(`CI_VERIFY_FAILURE: approved product test was not collected: ${test.replace('\u0000', ' › ')}`);
  for (const test of unexpectedTests) console.error(`CI_VERIFY_FAILURE: unapproved product test was collected: ${test.replace('\u0000', ' › ')}`);
  if (duplicateFiles) console.error(`CI_VERIFY_FAILURE: product manifest has ${duplicateFiles} duplicate files`);
  if (duplicateTests) console.error(`CI_VERIFY_FAILURE: product manifest has ${duplicateTests} duplicate test identities`);
  if (!total) console.error('CI_VERIFY_FAILURE: Playwright list did not report a test total');
  process.exit(1);
}
