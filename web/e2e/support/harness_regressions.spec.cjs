'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { test } = require('@playwright/test');

const {
  HarnessFailure,
  RecordingJournal,
  SecretLedger,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require('./harness.cjs');
const {
  makeDirectoryReadOnly,
  retainFirstOccurrenceEvidence,
  retainRecordingGapEvidence,
} = require('./harness_regressions_quarantine.cjs');

const ENDPOINT_AUTHORITY = 'web-e2e-controller';
const SUBJECT = 'web-e2e-subject';

async function managementJson(page, harness, path, options = {}) {
  const headers = {
    ...options.headers,
  };
  return page.evaluate(async ({ targetPath, requestOptions }) => {
    const response = await fetch(targetPath, {
      method: requestOptions.method,
      headers: requestOptions.headers,
      body: requestOptions.body,
    });
    const text = await response.text();
    let body;
    try { body = JSON.parse(text); } catch { body = undefined; }
    return { status: response.status, body, text };
  }, { targetPath: path, requestOptions: { ...options, headers } });
}

async function installProviderReplica(page, harness) {
  const result = await managementJson(page, harness, '/v1/auth-replicas/profile-e2e', {
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

async function createProviderSession(page, harness) {
  const result = await managementJson(page, harness, '/v1/sessions', {
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

async function appendProviderMessage(page, harness, sessionId) {
  const result = await managementJson(page, harness, `/v1/sessions/${sessionId}/messages`, {
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
  test('e2e_first_failure_cassette_tracks_real_browser_exchange', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    let harness;
    try {
      harness = await createWebE2EHarness({ uiMode: 'assets' });
      const captureSetId = harness.beginCaptureSet({
        e2eName: 'e2e_first_failure_cassette_tracks_real_browser_exchange',
        maxMembers: 16,
      });

      const systemResponse = await page.goto(`${harness.managementUrl}/v1/system`, {
        waitUntil: 'domcontentloaded',
      });
      assert.equal(systemResponse?.status(), 200, 'the real management system route did not provide the prerequisite 200');
      await harness.access.waitForJwksRequest();

      const uiResponse = await page.goto(`${harness.managementUrl}/`, {
        waitUntil: 'domcontentloaded',
      });
      const uiStatus = uiResponse?.status() ?? 0;
      assert.equal(uiStatus, 200, 'the real management UI entry did not provide the prerequisite 200');
      const renderedText = await page.locator('body').innerText();
      // This is a recorder-mechanism fixture fault after a real successful
      // browser exchange. It is deliberately not product-behavior evidence.
      const failure = new HarnessFailure(
        'HARNESS_FIRST_OCCURRENCE_FIXTURE_FAILURE',
        renderedText.trim()
          ? 'recorder fixture intentionally stopped after the real UI exchange'
          : 'recorder fixture observed an empty real UI document',
        { path: '/', status: uiStatus, surface: 'management UI', nonEvidence: true },
      );
      const evidence = await harness.captureAndReplayFailure(
        failure,
        'e2e_first_failure_cassette_tracks_real_browser_exchange',
      );
      assert.equal(evidence.captureSet?.captureSetId, captureSetId, 'first failure did not flush its bounded capture set');
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
        200,
        `first-occurrence evidence retained at ${retained.evidencePath}`,
      );
      assert.equal(
        retained.summary.cassette.path,
        '/',
        `cassette evidence retained at ${retained.evidencePath}`,
      );
      assert.equal(
        retained.summary.cassette.status,
        200,
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
    let closeError;
    try {
      harness = await createWebE2EHarness();

      const systemResponse = await page.goto(`${harness.managementUrl}/v1/system`, {
        waitUntil: 'domcontentloaded',
      });
      assert.equal(systemResponse?.status(), 200, 'the real browser management barrier did not open');
      await harness.access.waitForJwksRequest();

      await installProviderReplica(page, harness);
      const sessionId = await createProviderSession(page, harness);

      restoreQuarantine = makeDirectoryReadOnly(harness.journal.rootDir);
      await appendProviderMessage(page, harness, sessionId);
      const fatal = await harness.journal.waitForFatal();
      assert.equal(fatal.classification, 'RECORDING_FLUSH_FAILURE', 'recorder flush failure was not typed');
      const wireAttempts = harness.fakeProvider.requests.length;
      assert.equal(wireAttempts, 0, 'fail-closed recorder allowed an unrecorded provider wire attempt');
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
      try {
        await harness?.close();
      } catch (error) {
        closeError = error;
      }
    }
    assert.equal(closeError?.classification, 'RECORDING_FLUSH_FAILURE', 'recording flush failure did not propagate as fatal');
  });

  test('e2e_browser_capture_set_redacts_sensitive_query_slots_and_replays_exact_path', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-query-slot-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let upstream;
    let edge;
    let replayServer;
    try {
      upstream = await startHttpServer((request, response) => {
        if (request.method !== 'GET' || !request.url?.startsWith('/oauth/callback?')) {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        response.writeHead(200, {
          'cache-control': 'no-store',
          'content-type': 'text/html; charset=utf-8',
        });
        response.end('<!doctype html><title>callback edge</title>');
      });
      const captureSetId = journal.beginCaptureSet({
        e2eName: testInfo.title,
        maxMembers: 4,
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'query-slot-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: upstream.baseUrl,
      }));

      const code = 'code/one?x';
      const state = 'state two';
      const token = 'token/three';
      const requestPath = `/oauth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}&code=${encodeURIComponent(code)}&next=%2Fhome&token=${encodeURIComponent(token)}`;
      const response = await page.goto(`${edge.baseUrl}${requestPath}`, { waitUntil: 'domcontentloaded' });
      assert.equal(response?.status(), 200, 'the browser did not receive the real callback-edge response');
      assert.match(await page.title(), /callback edge/);

      const first = journal.first({ boundary: 'query-slot-edge', responseStatus: 200 });
      assert.ok(first?.rawPath, 'the first browser query exchange was not retained in quarantine');
      const promoted = await journal.promoteCaptureSet(captureSetId, {
        e2eName: testInfo.title,
        classification: 'HARNESS_FIRST_OCCURRENCE_QUERY_SLOT_FAILURE',
        firstObserved: 'real Chromium query callback exchange through the public HTTP edge',
        firstFailureRecordingId: first.recordingId,
        replay: async (envelope) => {
          replayServer = await journal.startReplayServer(envelope);
          try {
            const replayResponse = await page.goto(`${replayServer.baseUrl}${requestPath}`, {
              waitUntil: 'domcontentloaded',
            });
            assert.equal(replayResponse?.status(), 200, 'redacted query replay did not preserve the callback status');
            assert.match(await page.title(), /callback edge/);
            await replayServer.finish();
            replayServer = undefined;
            return { ok: true };
          } finally {
            if (replayServer) {
              try { await replayServer.finish(); } catch {}
              replayServer = undefined;
            }
          }
        },
      });
      const exchange = promoted.envelope.exchanges[0];
      assert.equal(ledger.restore(exchange.path), requestPath, 'query-slot replay did not restore the exact wire path');
      assert.equal(
        promoted.envelope.synthetic_secret_slots.filter((slot) => slot.includes('query_code')).length,
        2,
        'duplicate sensitive query values did not retain two synthetic slots in order',
      );
      assert.ok(
        promoted.envelope.synthetic_secret_slots.some((slot) => slot.includes('query_state'))
          && promoted.envelope.synthetic_secret_slots.some((slot) => slot.includes('query_token')),
        'sensitive query values were not represented by synthetic slots',
      );
      assert.equal(promoted.replay?.ok, true, 'query-slot promotion did not retain replay proof');
    } finally {
      try { await replayServer?.finish(); } catch {}
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
      // Keep the quarantine directory for first-occurrence inspection if this
      // test is red; it is test-owned and never printed into the report.
    }
  });

  test('e2e_browser_replay_serializes_identical_concurrent_exchanges', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-replay-concurrency-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let upstream;
    let edge;
    let replayServer;
    try {
      let responseNumber = 0;
      upstream = await startHttpServer((request, response) => {
        if (request.method !== 'GET' || !['/bootstrap', '/same-get'].includes(request.url)) {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        const body = request.url === '/bootstrap'
          ? Buffer.from('bootstrap', 'utf8')
          : Buffer.from(`exchange-${responseNumber++}`, 'utf8');
        response.writeHead(200, {
          'cache-control': 'no-store',
          'content-type': 'text/plain; charset=utf-8',
        });
        response.end(body);
      });
      const captureSetId = journal.beginCaptureSet({
        e2eName: testInfo.title,
        maxMembers: 3,
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'replay-concurrency-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: upstream.baseUrl,
      }));
      const bootstrap = await page.goto(`${edge.baseUrl}/bootstrap`, { waitUntil: 'domcontentloaded' });
      assert.equal(bootstrap?.status(), 200, 'the browser did not establish the real edge origin');
      const firstCapture = await page.evaluate(async (targetUrl) => {
        const responses = await Promise.all([
          fetch(targetUrl, { cache: 'no-store' }),
          fetch(targetUrl, { cache: 'no-store' }),
        ]);
        return Promise.all(responses.map(async (response) => ({
          status: response.status,
          body: await response.text(),
        })));
      }, '/same-get');
      assert.deepEqual(firstCapture.map((result) => result.status), [200, 200]);
      const first = journal.first({ boundary: 'replay-concurrency-edge', responseStatus: 200 });
      assert.ok(first?.rawPath, 'concurrent browser exchanges were not retained in quarantine');
      const prepared = journal.prepareCaptureSetPromotion(captureSetId, {
        e2eName: testInfo.title,
        classification: 'HARNESS_REPLAY_CONCURRENCY_FIXTURE_FAILURE',
        firstObserved: 'real Chromium sent two concurrent identical public GET exchanges',
        firstFailureRecordingId: first.recordingId,
      });
      assert.equal(prepared.captureSet.records.length, 3, 'capture did not retain the bootstrap and both concurrent exchanges');
      const expectedBodies = prepared.envelope.exchanges.slice(1).map((exchange) => (
        Buffer.from(exchange.response.chunks[0].data_base64, 'base64').toString('utf8')
      ));
      assert.equal(new Set(expectedBodies).size, 2, 'concurrent fixture responses did not distinguish cassette sequence members');

      // Preserve the real request/response bytes while using the captured
      // timing mode to hold both response handlers at the first chunk.  This
      // makes the concurrent reservation race constructible without sleeps.
      const { integrity_sha256: ignoredIntegrity, ...unsignedEnvelope } = prepared.envelope;
      const delayedUnsignedEnvelope = {
        ...unsignedEnvelope,
        exchanges: unsignedEnvelope.exchanges.map((exchange, index) => ({
          ...exchange,
          response: {
            ...exchange.response,
            chunks: exchange.response.chunks.map((chunk) => ({
              ...chunk,
              offset_us: index === 0 ? 0 : 200_000,
            })),
          },
        })),
      };
      const delayedCassette = {
        ...delayedUnsignedEnvelope,
        integrity_sha256: createHash('sha256').update(JSON.stringify(delayedUnsignedEnvelope)).digest('hex'),
      };
      replayServer = await journal.startReplayServer(delayedCassette, { timingMode: 'captured' });
      const replayBootstrap = await page.goto(`${replayServer.baseUrl}/bootstrap`, { waitUntil: 'domcontentloaded' });
      assert.equal(replayBootstrap?.status(), 200, 'the replay server did not establish the browser origin');
      const replayed = await page.evaluate(async (targetUrl) => {
        const responses = await Promise.all([
          fetch(targetUrl, { cache: 'no-store' }),
          fetch(targetUrl, { cache: 'no-store' }),
        ]);
        return Promise.all(responses.map(async (response) => ({
          status: response.status,
          body: await response.text(),
        })));
      }, '/same-get');
      assert.deepEqual(replayed.map((result) => result.status), [200, 200]);
      assert.deepEqual(
        replayed.map((result) => result.body),
        expectedBodies,
        'concurrent identical requests were not assigned distinct cassette exchanges in sequence order',
      );
      await replayServer.finish();
      replayServer = undefined;
    } finally {
      try { await replayServer?.finish(); } catch {}
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
      // Keep the first raw members in the test-owned quarantine on red.
    }
  });

  test('e2e_browser_capture_set_rejects_unknown_first_failure_recording_id', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-first-failure-id-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let upstream;
    let edge;
    try {
      upstream = await startHttpServer((request, response) => {
        if (request.method !== 'GET' || request.url !== '/first-failure-id') {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('first-failure-id');
      });
      const captureSetId = journal.beginCaptureSet({
        e2eName: testInfo.title,
        maxMembers: 1,
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'first-failure-id-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: upstream.baseUrl,
      }));
      const response = await page.goto(`${edge.baseUrl}/first-failure-id`, { waitUntil: 'domcontentloaded' });
      assert.equal(response?.status(), 200, 'the real browser edge did not open the first-failure fixture');
      const first = journal.first({ boundary: 'first-failure-id-edge', responseStatus: 200 });
      assert.ok(first?.rawPath, 'the first browser exchange was not retained before bogus promotion');
      const bogusRecordingId = '999999-00000000-0000-0000-0000-000000000000';
      await assert.rejects(
        () => journal.promoteCaptureSet(captureSetId, {
          e2eName: testInfo.title,
          classification: 'HARNESS_FIRST_FAILURE_ID_FIXTURE_FAILURE',
          firstObserved: 'real Chromium exchange with an intentionally unknown first-failure identity',
          firstFailureRecordingId: bogusRecordingId,
          replayProof: { ok: true },
        }),
        (error) => error?.classification === 'CAPTURE_SET_RELOAD_FAILURE',
        'promotion accepted a first_failure_recording_id that was not a durable capture-set member',
      );
      assert.equal(
        fs.readdirSync(path.join(quarantineRoot, 'promoted')).filter((entry) => entry.endsWith('.v1.json')).length,
        0,
        'unknown first-failure promotion wrote a cassette despite the atomic rejection',
      );
      assert.ok(fs.existsSync(first.rawPath), 'the retained first raw member was lost after rejection');
    } finally {
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });
});
