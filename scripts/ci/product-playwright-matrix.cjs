'use strict';

const fs = require('node:fs');
const path = require('node:path');

const [manifestPath, specRoot] = process.argv.slice(2);
if (!manifestPath || !specRoot) {
  console.error('CI_PRODUCT_VERIFY_FAILURE: product manifest and spec root are required');
  process.exit(1);
}

let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
} catch (error) {
  console.error(`CI_PRODUCT_VERIFY_FAILURE: cannot read product manifest: ${error.message}`);
  process.exit(1);
}

if (manifest?.version !== 1 || !Array.isArray(manifest.files) || !Array.isArray(manifest.tests)) {
  console.error('CI_PRODUCT_VERIFY_FAILURE: product manifest has an unsupported shape');
  process.exit(1);
}

const files = manifest.files;
const uniqueFiles = new Set(files);
const sortedFiles = [...files].sort();
const testIdentities = new Set();
const testsPerFile = new Map(files.map((file) => [file, 0]));
let invalid = false;

if (uniqueFiles.size !== files.length) {
  console.error('CI_PRODUCT_VERIFY_FAILURE: product manifest contains duplicate files');
  invalid = true;
}
if (JSON.stringify(files) !== JSON.stringify(sortedFiles)) {
  console.error('CI_PRODUCT_VERIFY_FAILURE: product manifest files must stay sorted');
  invalid = true;
}

const resolvedSpecRoot = path.resolve(specRoot);
for (const file of files) {
  if (!/^specs\/[A-Za-z0-9._/-]+\.spec\.(?:cjs|ts)$/.test(file) || file.includes('..')) {
    console.error(`CI_PRODUCT_VERIFY_FAILURE: invalid product spec path: ${file}`);
    invalid = true;
    continue;
  }
  const candidate = path.resolve(resolvedSpecRoot, file.slice('specs/'.length));
  if (!candidate.startsWith(`${resolvedSpecRoot}${path.sep}`)) {
    console.error(`CI_PRODUCT_VERIFY_FAILURE: product spec escapes its root: ${file}`);
    invalid = true;
    continue;
  }
  try {
    const metadata = fs.lstatSync(candidate);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      console.error(`CI_PRODUCT_VERIFY_FAILURE: product spec is not a regular file: ${file}`);
      invalid = true;
    }
  } catch (error) {
    console.error(`CI_PRODUCT_VERIFY_FAILURE: product spec is unavailable: ${file}: ${error.message}`);
    invalid = true;
  }
}

for (const entry of manifest.tests) {
  if (!entry || typeof entry.file !== 'string' || typeof entry.title !== 'string' || !entry.title) {
    console.error('CI_PRODUCT_VERIFY_FAILURE: product manifest contains an invalid test identity');
    invalid = true;
    continue;
  }
  if (!uniqueFiles.has(entry.file)) {
    console.error(`CI_PRODUCT_VERIFY_FAILURE: product test references an unapproved file: ${entry.file}`);
    invalid = true;
    continue;
  }
  const identity = `${entry.file}\u0000${entry.title}`;
  if (testIdentities.has(identity)) {
    console.error(`CI_PRODUCT_VERIFY_FAILURE: duplicate product test identity: ${entry.file} › ${entry.title}`);
    invalid = true;
  }
  testIdentities.add(identity);
  testsPerFile.set(entry.file, testsPerFile.get(entry.file) + 1);
}

for (const [file, count] of testsPerFile) {
  if (count === 0) {
    console.error(`CI_PRODUCT_VERIFY_FAILURE: approved product spec has no tests: ${file}`);
    invalid = true;
  }
}

if (invalid || files.length === 0 || manifest.tests.length === 0) process.exit(1);

const include = files.map((file, index) => ({
  id: `${String(index + 1).padStart(2, '0')}-${path.basename(file).replace(/\.spec\.(?:cjs|ts)$/, '').replace(/[^A-Za-z0-9_-]+/g, '-')}`,
  file,
}));
process.stdout.write(`${JSON.stringify({ include })}\n`);
