'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

const ROOT = path.resolve(__dirname, '../../..');

function privateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  return directory;
}

function writePrivateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  fs.chmodSync(filePath, 0o600);
  return filePath;
}

function createObservationQuarantine(label) {
  const root = privateDirectory(path.join(ROOT, 'target', 'test-recordings', 'quarantine'));
  return privateDirectory(path.join(root, `harness-regression-${label}-${Date.now()}-${randomUUID()}`));
}

function readFirstOccurrenceSummary({ rawPath, cassettePath }) {
  const raw = JSON.parse(fs.readFileSync(rawPath, 'utf8'));
  const cassette = JSON.parse(fs.readFileSync(cassettePath, 'utf8'));
  const exchange = cassette.exchanges?.find((candidate) => candidate.recording_id === cassette.first_failure_recording_id)
    || cassette.exchanges?.[0];
  return {
    recording_id: raw.recording_id,
    raw: {
      boundary: raw.boundary,
      method: raw.method,
      path: raw.path,
      status: raw.response?.status,
      outcome: raw.response?.outcome,
    },
    cassette: {
      boundary: cassette.boundary,
      e2e_name: cassette.e2e_name,
      classification: cassette.classification,
      path: exchange?.path,
      status: exchange?.response?.status,
      outcome: exchange?.response?.outcome,
    },
  };
}

function retainFirstOccurrenceEvidence({ rawPath, cassettePath, label }) {
  const summary = readFirstOccurrenceSummary({ rawPath, cassettePath });
  const root = path.dirname(rawPath);
  const evidencePath = writePrivateJson(path.join(root, `${label}.evidence.json`), {
    schema: 'zode.web-e2e-harness-regression-evidence.v1',
    kind: 'first_occurrence',
    ...summary,
  });
  return { evidencePath, summary };
}

function makeDirectoryReadOnly(directory) {
  const originalMode = fs.statSync(directory).mode & 0o777;
  fs.chmodSync(directory, originalMode & ~0o222);
  return () => fs.chmodSync(directory, originalMode);
}

function retainRecordingGapEvidence({ label, wireAttempts, recordedAttempts, quarantineWritable }) {
  const unrecordedAttempts = Math.max(0, wireAttempts - recordedAttempts);
  const root = createObservationQuarantine(label);
  const evidencePath = writePrivateJson(path.join(root, 'first-occurrence.evidence.json'), {
    schema: 'zode.web-e2e-harness-regression-evidence.v1',
    kind: 'recording_gap',
    e2e_name: label,
    boundary: 'provider-recording-proxy',
    first_observed: {
      code: 'recording_gap',
      quarantine_writable: quarantineWritable,
    },
    wire_attempts: wireAttempts,
    recorded_attempts: recordedAttempts,
    unrecorded_attempts: unrecordedAttempts,
  });
  return { evidencePath, wireAttempts, recordedAttempts, unrecordedAttempts };
}

module.exports = {
  makeDirectoryReadOnly,
  retainFirstOccurrenceEvidence,
  retainRecordingGapEvidence,
};
