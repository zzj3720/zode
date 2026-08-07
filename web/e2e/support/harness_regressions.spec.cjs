'use strict';

const assert = require('node:assert/strict');

const { test } = require('@playwright/test');

const {
  ProductRouteMissing,
  createWebE2EHarness,
} = require('./harness.cjs');
const {
  makeDirectoryReadOnly,
  retainFirstOccurrenceEvidence,
  retainRecordingGapEvidence,
} = require('./harness_regressions_quarantine.cjs');

const ENDPOINT_AUTHORITY = 'web-e2e-controller';
const SUBJECT = 'web-e2e-subject';

async function endpointJson(harness, path, options = {}) {
  const headers = {
    authorization: `Bearer ${harness.controllerSecret}`,
    'zode-subject': SUBJECT,
    ...options.headers,
  };
  const response = await fetch(`${harness.endpoint.baseUrl}${path}`, {
    ...options,
    headers,
  });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { status: response.status, body, text };
}

async function installProviderReplica(harness) {
  const result = await endpointJson(harness, '/v1/auth-replicas/profile-e2e', {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'idempotency-key': 'harness-regression-install-provider-replica',
    },
    body: JSON.stringify({
      schema: 'zode.auth-replica.install.v1',
      authority_id: ENDPOINT_AUTHORITY,
      provider: 'fixture-provider',
      kind: 'api_key',
      revision: 1,
      credential_schema: 'openai-compatible.api-key.v1',
      secret: {
        encoding: 'application/zode-secret-envelope',
        payload: harness.providerSecret,
      },
    }),
  });
  assert.ok(result.status === 200 || result.status === 201, `provider replica install failed: ${result.status}`);
}

async function createProviderSession(harness) {
  const result = await endpointJson(harness, '/v1/sessions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'idempotency-key': 'harness-regression-create-provider-session',
    },
    body: JSON.stringify({
      model: {
        provider: 'fixture-provider',
        provider_execution: {
          schema: 'zode.provider-execution.v1',
          revision: 1,
          kind: 'openai_compatible',
          base_url: harness.providerProxy.baseUrl,
        },
        model: 'fixture-model',
        auth_authority_id: ENDPOINT_AUTHORITY,
        auth_profile_id: 'profile-e2e',
        auth_revision: 1,
      },
      tools: [],
    }),
  });
  assert.equal(result.status, 201, `provider session creation failed: ${result.status}`);
  assert.ok(result.body?.session_id, 'provider session response omitted session_id');
  return result.body.session_id;
}

async function appendProviderMessage(harness, sessionId) {
  const result = await endpointJson(harness, `/v1/sessions/${sessionId}/messages`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'idempotency-key': 'harness-regression-provider-message',
    },
    body: JSON.stringify({ content: 'recording gap regression' }),
  });
  assert.equal(result.status, 202, `provider message admission failed: ${result.status}`);
}

class RecordingGapRegression extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'RecordingGapRegression';
    this.classification = 'recording_gap';
    this.details = details;
  }
}

test.describe('Zode web E2E harness regressions', () => {
  test('e2e_first_failure_cassette_tracks_actual_ui_failure', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    let harness;
    try {
      harness = await createWebE2EHarness();

      const systemResponse = await page.goto(`${harness.managementUrl}/v1/system`, {
        waitUntil: 'domcontentloaded',
      });
      assert.equal(systemResponse?.status(), 200, 'the real management system route did not provide the prerequisite 200');
      await harness.access.waitForJwksRequest();

      const uiResponse = await page.goto(`${harness.managementUrl}/`, {
        waitUntil: 'domcontentloaded',
      });
      const uiStatus = uiResponse?.status() ?? 0;
      assert.equal(uiStatus, 404, 'the real management UI entry did not provide the intended first failure');

      const failure = new ProductRouteMissing({
        path: '/',
        status: uiStatus,
        surface: 'management UI',
      });
      const evidence = await harness.captureAndReplayFailure(
        failure,
        'e2e_first_failure_cassette_tracks_actual_ui_failure',
      );
      assert.ok(evidence.record?.rawPath, 'first management exchange was not retained in quarantine');
      assert.ok(evidence.cassettePath, 'first management exchange was not promoted to a safe cassette');

      const retained = retainFirstOccurrenceEvidence({
        rawPath: evidence.record.rawPath,
        cassettePath: evidence.cassettePath,
        label: testInfo.title,
      });
      assert.equal(
        retained.summary.raw.path,
        '/',
        `first-occurrence evidence retained at ${retained.evidencePath}`,
      );
      assert.equal(
        retained.summary.raw.status,
        404,
        `first-occurrence evidence retained at ${retained.evidencePath}`,
      );
      assert.equal(
        retained.summary.cassette.path,
        '/',
        `cassette evidence retained at ${retained.evidencePath}`,
      );
      assert.equal(
        retained.summary.cassette.status,
        404,
        `cassette evidence retained at ${retained.evidencePath}`,
      );
    } finally {
      await harness?.close();
    }
  });

  test('e2e_recording_flush_failure_is_fatal', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    let harness;
    let restoreQuarantine;
    try {
      harness = await createWebE2EHarness();

      const systemResponse = await page.goto(`${harness.managementUrl}/v1/system`, {
        waitUntil: 'domcontentloaded',
      });
      assert.equal(systemResponse?.status(), 200, 'the real browser management barrier did not open');
      await harness.access.waitForJwksRequest();

      await installProviderReplica(harness);
      const sessionId = await createProviderSession(harness);

      restoreQuarantine = makeDirectoryReadOnly(harness.journal.rootDir);
      await appendProviderMessage(harness, sessionId);
      await harness.fakeProvider.waitForRequest(1);
      // The fixture notifies at request admission, before Node flushes the
      // response and the proxy attempts its journal write. Yield only to the
      // already-queued I/O; this is not a timing-based product barrier.
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));

      const wireAttempts = harness.fakeProvider.requests.length;
      const recordedAttempts = harness.journal.records
        .filter((record) => record.boundary === 'provider-recording-proxy')
        .length;
      const observation = retainRecordingGapEvidence({
        label: testInfo.title,
        wireAttempts,
        recordedAttempts,
        quarantineWritable: false,
      });
      if (observation.unrecordedAttempts > 0) {
        throw new RecordingGapRegression(
          `recording_gap: ${observation.unrecordedAttempts} provider wire attempt(s) escaped an unwritable quarantine; evidence=${observation.evidencePath}`,
          observation,
        );
      }
      assert.equal(
        observation.unrecordedAttempts,
        0,
        `recording_gap evidence retained at ${observation.evidencePath}`,
      );
    } finally {
      restoreQuarantine?.();
      await harness?.close();
    }
  });
});
