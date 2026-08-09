'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { test } = require('@playwright/test');

const {
  Barrier,
  HarnessFailure,
  RealProcess,
  RecordingJournal,
  SecretLedger,
  createWebE2EHarness,
  proxyHttp,
  startAccessFixture,
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

function requestLocalEdge(url, headers) {
  return new Promise((resolve, reject) => {
    const request = http.request(new URL(url), { method: 'GET', headers }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      response.once('end', () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
      response.once('error', reject);
    });
    request.once('error', (error) => resolve({ status: 0, headers: {}, body: Buffer.alloc(0), error }));
    request.end();
  });
}

function requestLocalEdgeWithBody(url, { method = 'POST', headers = {}, body = Buffer.alloc(0) } = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(new URL(url), {
      method,
      headers: { ...headers, 'content-length': String(body.length) },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      response.once('end', () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
      response.once('error', reject);
    });
    request.once('error', (error) => resolve({ status: 0, headers: {}, body: Buffer.alloc(0), error }));
    request.end(body);
  });
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
  test('e2e_shared_real_process_requires_capture_arm_before_spawn', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-process-arm-'));
    const markerPath = path.join(root, 'spawned.marker');
    const ledger = new SecretLedger();
    let childProcess;
    let failure;
    try {
      try {
        childProcess = await RealProcess.start({
          name: 'endpoint',
          binary: '/bin/sh',
          args: ['-c', `printf 'ZODE_READY http://127.0.0.1:45679\\n'; printf spawned > '${markerPath}'; sleep 30`],
          cwd: process.cwd(),
          env: {},
          readyPrefix: 'ZODE_READY ',
          ledger,
          logDir: path.join(root, 'logs'),
          e2eName: testInfo.title,
        });
      } catch (error) {
        failure = error;
      }
      if (childProcess) {
        try { await childProcess.stop(); } catch {}
      }
      assert.equal(failure?.classification, 'PROCESS_CAPTURE_NOT_ARMED', 'real process spawned without an armed capture');
      assert.equal(fs.existsSync(markerPath), false, 'the product child ran before capture was armed');
    } finally {
      try { await childProcess?.stop(); } catch {}
    }
  });

  test('e2e_shared_real_process_capture_is_durable_before_readiness_and_stop', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-process-capture-'));
    const ledger = new SecretLedger();
    let childProcess;
    try {
      childProcess = await RealProcess.start({
        name: 'endpoint',
        binary: '/bin/sh',
        args: ['-c', 'printf "ZODE_READY http://127.0.0.1:45680\\n"; sleep 30'],
        cwd: process.cwd(),
        env: {},
        readyPrefix: 'ZODE_READY ',
        ledger,
        logDir: path.join(root, 'logs'),
        startupCaptureRoot: path.join(root, 'capture'),
        startupConfigBytes: Buffer.from('test-only-config\n'),
        e2eName: testInfo.title,
      });

      const capture = childProcess.startupCapture;
      assert.ok(capture?.armed, 'the process did not expose an armed startup capture');
      assert.ok(fs.existsSync(capture.observationPath), 'readiness returned before durable process observation');
      const beforeStop = JSON.parse(fs.readFileSync(capture.observationPath, 'utf8'));
      assert.ok(['spawned', 'ready_probe', 'exit'].includes(beforeStop.phase), 'readiness observation phase was not durable');
      assert.equal(beforeStop.flush_status, 'ok', 'readiness observation was not durably flushed');
      assert.match(Buffer.from(beforeStop.stdout_hex, 'hex').toString('utf8'), /ZODE_READY http:\/\/127\.0\.0\.1:45680/u);

      await childProcess.stop();
      const afterStop = JSON.parse(fs.readFileSync(capture.observationPath, 'utf8'));
      assert.equal(afterStop.phase, 'stop', 'stop cleanup ran before durable process observation');
      assert.equal(afterStop.flush_status, 'ok', 'stop observation was not durably flushed');
      assert.equal(afterStop.stop.flush_status, 'ok', 'stop proof did not retain durable output flush status');
      assert.equal(afterStop.stop.timed_out, false, 'bounded stop unexpectedly timed out');
      assert.equal(afterStop.stop.leaked_pids.length, 0, 'bounded stop leaked a child process');
      assert.equal(afterStop.exit_status.known, true, 'stop observation lost the child exit status');
    } finally {
      try { await childProcess?.stop(); } catch {}
    }
  });

  test('e2e_shared_real_process_stops_interpreter_wrapper_with_durable_proof', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-process-wrapper-'));
    const wrapper = path.join(root, 'ready-wrapper.cjs');
    fs.writeFileSync(
      wrapper,
      '#!/usr/bin/env node\nconsole.log("ZODE_READY http://127.0.0.1:45682");\nsetInterval(() => {}, 30_000);\n',
      { mode: 0o700 },
    );
    fs.chmodSync(wrapper, 0o700);
    const ledger = new SecretLedger();
    let childProcess;
    try {
      childProcess = await RealProcess.start({
        name: 'server',
        binary: wrapper,
        args: [],
        cwd: process.cwd(),
        env: {},
        readyPrefix: 'ZODE_READY ',
        ledger,
        logDir: path.join(root, 'logs'),
        startupCaptureRoot: path.join(root, 'capture'),
        startupConfigBytes: Buffer.from('test-only-wrapper-config\n'),
        e2eName: testInfo.title,
      });
      await childProcess.stop();
      const observation = JSON.parse(fs.readFileSync(childProcess.startupCapture.observationPath, 'utf8'));
      assert.equal(observation.phase, 'stop');
      assert.equal(observation.stop.flush_status, 'ok');
      assert.equal(observation.stop.timed_out, false);
      assert.deepEqual(observation.stop.leaked_pids, []);
    } finally {
      try { await childProcess?.stop(); } catch {}
    }
  });

  test('e2e_shared_real_process_prefers_durable_ready_line_before_exit', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-process-ready-race-'));
    const ledger = new SecretLedger();
    const childProcess = await RealProcess.start({
      name: 'endpoint',
      binary: '/bin/sh',
      // Large preceding output keeps the sidecar write and child exit in the
      // same scheduling window while the readiness marker remains a line.
      args: ['-c', 'head -c 100000 /dev/zero; printf "\\nZODE_READY http://127.0.0.1:45681\\n"'],
      cwd: process.cwd(),
      env: {},
      readyPrefix: 'ZODE_READY ',
      ledger,
      logDir: path.join(root, 'logs'),
      startupCaptureRoot: path.join(root, 'capture'),
      startupConfigBytes: Buffer.from('test-only-config\n'),
      e2eName: testInfo.title,
    });
    try {
      assert.equal(childProcess.baseUrl, 'http://127.0.0.1:45681');
      await childProcess.exitPromise;
      const capture = childProcess.startupCapture;
      const exitObservation = JSON.parse(fs.readFileSync(capture.observationPath, 'utf8'));
      assert.equal(exitObservation.phase, 'exit', 'child exit was not durably quarantined before recovery');
      const recovered = capture.recoverProcessObservation({
        locatorPath: childProcess.locatorPath,
        locator: childProcess.locator,
        phase: 'recovered',
      });
      assert.equal(recovered.phase, 'recovered');
      assert.equal(recovered.flush_status, 'ok');
      assert.match(Buffer.from(recovered.stdout_hex, 'hex').toString('utf8'), /ZODE_READY http:\/\/127\.0\.0\.1:45681/u);
    } finally {
      // The shell exits naturally in this scenario; the locator and durable
      // observation remain available for recovery after an early harness exit.
      try { await childProcess.exitPromise; } catch {}
      try { await childProcess.stop(); } catch {}
    }
  });

  test('e2e_harness_rejects_unicode_control_or_unpaired_surrogate_authority_before_process_spawn', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-authority-validation-'));
    const markerPath = path.join(root, 'spawned.marker');
    const binaryPath = path.join(root, 'should-not-spawn.sh');
    fs.writeFileSync(binaryPath, '#!/bin/sh\nprintf spawned > "$ZODE_AUTHORITY_SPAWN_MARKER"\nexit 1\n', { mode: 0o700 });
    fs.chmodSync(binaryPath, 0o700);
    const previousEndpointBinary = process.env.ZODE_ENDPOINT_BIN;
    const previousServerBinary = process.env.ZODE_SERVER_BIN;
    const previousMarker = process.env.ZODE_AUTHORITY_SPAWN_MARKER;
    process.env.ZODE_ENDPOINT_BIN = binaryPath;
    process.env.ZODE_SERVER_BIN = binaryPath;
    process.env.ZODE_AUTHORITY_SPAWN_MARKER = markerPath;
    try {
      for (const authorityId of ['\u0085', '\ud800']) {
        await assert.rejects(
          createWebE2EHarness({ authorityId, e2eName: testInfo.title }),
          (error) => error?.classification === 'AUTHORITY_INVALID',
          `authority ${JSON.stringify(authorityId)} was not rejected before process startup`,
        );
      }
      assert.equal(fs.existsSync(markerPath), false, 'invalid authority caused a product child to spawn');
    } finally {
      if (previousEndpointBinary === undefined) delete process.env.ZODE_ENDPOINT_BIN;
      else process.env.ZODE_ENDPOINT_BIN = previousEndpointBinary;
      if (previousServerBinary === undefined) delete process.env.ZODE_SERVER_BIN;
      else process.env.ZODE_SERVER_BIN = previousServerBinary;
      if (previousMarker === undefined) delete process.env.ZODE_AUTHORITY_SPAWN_MARKER;
      else process.env.ZODE_AUTHORITY_SPAWN_MARKER = previousMarker;
    }
  });

  test('e2e_first_failure_cassette_tracks_real_browser_exchange', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    let harness;
    try {
      harness = await createWebE2EHarness({ uiMode: 'assets', includeServerOrigins: true });
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

  test('e2e_later_reproduction_relation_is_bound_to_real_browser_capture', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const relation = 'later_test_reproduction_of_gap';
    const classification = 'HARNESS_LATER_RELATION_FIXTURE_FAILURE';
    let harness;
    try {
      harness = await createWebE2EHarness({ uiMode: 'assets', includeServerOrigins: true });
      const captureSetId = harness.beginCaptureSet({
        e2eName: `${testInfo.title}__${relation}`,
        maxMembers: 16,
      });

      const uiResponse = await page.goto(`${harness.managementUrl}/`, {
        waitUntil: 'domcontentloaded',
      });
      const status = uiResponse?.status() ?? 0;
      assert.equal(status, 200, 'the real browser exchange did not reach the management UI');
      await page.waitForLoadState('networkidle');
      assert.ok((await page.locator('body').innerText()).trim(), 'the real browser UI document was empty');

      const evidence = await harness.captureAndReplayFailure(
        new HarnessFailure(
          classification,
          'recorder relation fixture stopped after the real browser exchange',
          {
            method: 'GET',
            path: '/',
            status,
            browserBehaviorReplayRequired: false,
            nonEvidence: true,
          },
        ),
        testInfo.title,
        { relation },
      );
      assert.equal(evidence.captureSet?.captureSetId, captureSetId, 'later reproduction did not seal its bounded capture set');
      assert.ok(evidence.record?.rawPath, 'later reproduction did not retain its real browser exchange');
      assert.ok(evidence.cassettePath, 'later reproduction did not create a replay-proven cassette');

      const retained = retainFirstOccurrenceEvidence({
        rawPath: evidence.record.rawPath,
        cassettePath: evidence.cassettePath,
        label: testInfo.title,
      });
      const cassette = JSON.parse(fs.readFileSync(evidence.cassettePath, 'utf8'));
      assert.equal(
        cassette.classification,
        `${classification}__${relation}`,
        `later-reproduction relation was not bound to the retained cassette; evidence=${retained.evidencePath}`,
      );
      assert.match(
        cassette.first_observed,
        new RegExp(`^relation=${relation}; `),
        `later-reproduction relation was not bound to first_observed; evidence=${retained.evidencePath}`,
      );
    } finally {
      await harness?.close();
    }
  });

  test('e2e_browser_only_failure_seals_context_without_false_http_promotion', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const relation = 'later_test_reproduction_of_gap';
    let harness;
    try {
      harness = await createWebE2EHarness({ uiMode: 'assets', includeServerOrigins: true });
      const captureSetId = harness.beginCaptureSet({
        e2eName: `${testInfo.title}__${relation}`,
        maxMembers: 16,
      });

      const uiResponse = await page.goto(`${harness.managementUrl}/`, {
        waitUntil: 'domcontentloaded',
      });
      assert.equal(uiResponse?.status(), 200, 'the real browser context did not reach the management UI');
      await page.waitForLoadState('networkidle');
      assert.ok((await page.locator('body').innerText()).trim(), 'the real browser UI document was empty');

      const evidence = await harness.captureAndReplayFailure(
        new HarnessFailure(
          'HARNESS_BROWSER_ONLY_FIXTURE_FAILURE',
          'browser-only fixture stopped without inventing an HTTP failure identity',
          { browserBehaviorReplayRequired: true, nonEvidence: true },
        ),
        testInfo.title,
        { relation },
      );
      assert.equal(evidence.record, undefined, 'browser-only failure was falsely bound to an earlier HTTP response');
      assert.equal(evidence.captureSet?.captureSetId, captureSetId, 'browser-only context did not seal its capture set');
      assert.ok(evidence.captureSet?.records.length > 0, 'browser-only failure sealed no real public context');
      assert.equal(evidence.browserBehaviorReplayRequired, true, 'browser-only failure was misrepresented as replay proven');
      assert.equal(evidence.cassettePath, undefined, 'HTTP replay falsely promoted a browser behavior cassette');

      const manifest = JSON.parse(fs.readFileSync(
        path.join(harness.journal.rootDir, `${captureSetId}.manifest.json`),
        'utf8',
      ));
      assert.equal(manifest.state, 'flushed', 'browser-only failure context was not durable before writer exit');
      assert.equal(manifest.e2e_name, `${testInfo.title}__${relation}`, 'sealed context lost its later-reproduction provenance');
      assert.equal(manifest.first_failure_recording_id, undefined, 'browser-only failure invented an HTTP first-failure identity');
      assert.deepEqual(fs.readdirSync(harness.journal.promotedDir), [], 'browser-only failure created an immutable cassette without browser replay');
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
          replayServer = await journal.startReplayEdge(envelope, { canonicalOrigin: upstream.baseUrl });
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

  test('e2e_http_capture_set_preserves_canonical_host_and_forwarded_headers_for_replay', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-host-surface-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    const managementOrigin = 'http://127.0.0.1:48123';
    const callbackOrigin = 'http://127.0.0.2:48123';
    const managementForwarded = 'for=203.0.113.10;host=spoof-management.invalid';
    const callbackForwarded = 'for=203.0.113.11;host=spoof-callback.invalid';
    const managementXForwardedHost = 'spoof-management.invalid';
    const callbackXForwardedHost = 'spoof-callback.invalid';
    let upstream;
    let managementEdge;
    let callbackEdge;
    let replayServer;
    try {
      upstream = await startHttpServer((request, response) => {
        if (request.method !== 'GET' || request.url !== '/host-surface') {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({
          host: request.headers.host,
          forwarded: request.headers.forwarded,
          x_forwarded_host: request.headers['x-forwarded-host'],
        }));
      });
      const captureSetId = journal.beginCaptureSet({
        e2eName: testInfo.title,
        maxMembers: 2,
      });
      managementEdge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'management-host-surface-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: managementOrigin,
      }));
      callbackEdge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'callback-host-surface-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: callbackOrigin,
      }));

      const managementCapture = await requestLocalEdge(`${managementEdge.baseUrl}/host-surface`, {
        host: 'management-edge.invalid',
        forwarded: managementForwarded,
        'x-forwarded-host': managementXForwardedHost,
        authorization: 'Bearer synthetic-edge-secret',
        cookie: 'session=synthetic-edge-cookie',
        'cf-access-jwt-assertion': 'synthetic-access-assertion',
      });
      const callbackCapture = await requestLocalEdge(`${callbackEdge.baseUrl}/host-surface`, {
        host: 'callback-edge.invalid',
        forwarded: callbackForwarded,
        'x-forwarded-host': callbackXForwardedHost,
        authorization: 'Bearer synthetic-edge-secret',
        cookie: 'session=synthetic-edge-cookie',
        'cf-access-jwt-assertion': 'synthetic-access-assertion',
      });
      assert.equal(managementCapture.status, 200, 'management local edge did not return the captured exchange');
      assert.equal(callbackCapture.status, 200, 'callback local edge did not return the captured exchange');

      const first = journal.first({ boundary: 'management-host-surface-edge', responseStatus: 200 });
      assert.ok(first?.rawPath, 'canonical Host capture was not retained in quarantine');
      const promoted = await journal.promoteCaptureSet(captureSetId, {
        e2eName: testInfo.title,
        classification: 'HARNESS_HOST_SURFACE_FIXTURE_FAILURE',
        firstObserved: 'real local management/callback edges carried distinct canonical Host and spoofed forwarding headers',
        firstFailureRecordingId: first.recordingId,
        replay: async (envelope) => {
          replayServer = await journal.startReplayServer(envelope);
          const wrong = await requestLocalEdge(`${replayServer.baseUrl}/host-surface`, {
            host: 'callback.invalid:48123',
            forwarded: 'for=198.51.100.99;host=wrong.invalid',
            'x-forwarded-host': 'wrong.invalid',
          });
          assert.equal(wrong.status, 500, 'replay accepted a wrong Host/forwarding authority');
          assert.equal(
            replayServer.failures[0]?.classification,
            'REPLAY_REQUEST_HEADER_MISMATCH',
            'wrong Host/forwarding headers did not produce a typed replay mismatch',
          );
          try {
            await replayServer.finish();
          } catch (error) {
            assert.equal(error.classification, 'REPLAY_REQUEST_HEADER_MISMATCH');
          }
          replayServer = undefined;

          replayServer = await journal.startReplayServer(envelope);
          const managementReplay = await requestLocalEdge(`${replayServer.baseUrl}/host-surface`, {
            host: new URL(managementOrigin).host,
            forwarded: managementForwarded,
            'x-forwarded-host': managementXForwardedHost,
          });
          const callbackReplay = await requestLocalEdge(`${replayServer.baseUrl}/host-surface`, {
            host: new URL(callbackOrigin).host,
            forwarded: callbackForwarded,
            'x-forwarded-host': callbackXForwardedHost,
          });
          assert.equal(managementReplay.status, 200, 'canonical management Host replay did not match');
          assert.equal(callbackReplay.status, 200, 'canonical callback Host replay did not match');
          await replayServer.finish();
          replayServer = undefined;
          return { ok: true };
        },
      });
      const exchanges = promoted.envelope.exchanges;
      assert.equal(exchanges.length, 2, 'both host surfaces were not retained in the capture set');
      assert.equal(exchanges[0].request_headers.host, new URL(managementOrigin).host);
      assert.equal(exchanges[0].request_headers.forwarded, managementForwarded);
      assert.equal(exchanges[0].request_headers['x-forwarded-host'], managementXForwardedHost);
      assert.equal(exchanges[0].request_headers.authorization, undefined);
      assert.equal(exchanges[0].request_headers.cookie, undefined);
      assert.equal(exchanges[0].request_headers['cf-access-jwt-assertion'], undefined);
      assert.equal(exchanges[1].request_headers.host, new URL(callbackOrigin).host);
      assert.equal(exchanges[1].request_headers.forwarded, callbackForwarded);
      assert.equal(exchanges[1].request_headers['x-forwarded-host'], callbackXForwardedHost);
      assert.equal(exchanges[1].request_headers.authorization, undefined);
      assert.equal(exchanges[1].request_headers.cookie, undefined);
      assert.equal(exchanges[1].request_headers['cf-access-jwt-assertion'], undefined);
      assert.equal(promoted.replay?.ok, true, 'Host surface promotion did not retain replay proof');
    } finally {
      try { await replayServer?.finish(); } catch {}
      try { await managementEdge?.close(); } catch {}
      try { await callbackEdge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });

  test('e2e_capture_set_recovery_promotes_existing_flushed_raw_after_recorder_restart', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-capture-recovery-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let upstream;
    let edge;
    try {
      upstream = await startHttpServer((request, response) => {
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.end('recovery-edge');
      });
      const captureSetId = journal.beginCaptureSet({ e2eName: testInfo.title, maxMembers: 1 });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'capture-recovery-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: upstream.baseUrl,
      }));
      const captured = await requestLocalEdge(`${edge.baseUrl}/recovery`, {});
      assert.equal(captured.status, 200, 'the real local edge did not produce the recovery source exchange');
      const firstFailureRecordingId = journal.first({ boundary: 'capture-recovery-edge', responseStatus: 200 }).recordingId;
      journal.flushCaptureSet(captureSetId, { firstFailureRecordingId });
      const destinationDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-capture-recovery-promoted-'));
      const promotedBeforeRecovery = fs.existsSync(path.join(quarantineRoot, 'promoted'));
      const restartedJournal = RecordingJournal.openFlushedCaptureRoot({ rootDir: quarantineRoot, ledger: new SecretLedger() });
      const reloaded = restartedJournal.reloadCaptureSet(captureSetId);
      assert.equal(reloaded.state, 'flushed', 'the recovery source was not durably sealed before recorder exit');
      assert.equal(fs.existsSync(path.join(quarantineRoot, 'promoted')), promotedBeforeRecovery, 'recovery loader polluted the forensic root before validation');
      await assert.rejects(
        () => restartedJournal.promoteFlushedCaptureSet(captureSetId, {
          destinationDirectory,
          replayProof: { ok: true },
        }),
        (error) => error.classification === 'REPLAY_PROOF_REQUIRED',
      );
      assert.equal(fs.readdirSync(destinationDirectory).length, 0, 'unbound recovery proof created a cassette');
      await assert.rejects(
        () => restartedJournal.promoteFlushedCaptureSet(captureSetId, {
          destinationDirectory,
          replay: async (envelope) => envelope.exchanges.map((exchange) => ({
            status: exchange.response.status,
            path: exchange.path,
            outcome: exchange.response.outcome,
            chunks: exchange.response.chunks.length,
          })),
        }),
        (error) => error.classification === 'REPLAY_PROOF_INVALID',
      );
      assert.equal(fs.readdirSync(destinationDirectory).length, 0, 'fabricated replay results created a cassette');
      await assert.rejects(
        () => restartedJournal.promoteFlushedCaptureSet(captureSetId, {
          destinationDirectory,
          replay: async (envelope) => {
            const results = await restartedJournal.replay(envelope, { baseUrl: upstream.baseUrl });
            envelope.exchanges[0].request_body.raw_base64 = Buffer.from('forged').toString('base64');
            return results;
          },
        }),
        (error) => error.classification === 'REPLAY_PROOF_INVALID',
      );
      assert.equal(fs.readdirSync(destinationDirectory).length, 0, 'mutated replay envelope created a cassette');
      const symlinkDestination = path.join(quarantineRoot, 'recovery-destination-link');
      fs.symlinkSync(quarantineRoot, symlinkDestination, 'dir');
      const forensicCassettesBeforeSymlinkAttempt = fs.readdirSync(quarantineRoot)
        .filter((entry) => entry.endsWith('.v1.json'))
        .sort();
      await assert.rejects(
        () => restartedJournal.promoteFlushedCaptureSet(captureSetId, {
          destinationDirectory: symlinkDestination,
          replay: async (envelope) => restartedJournal.replay(envelope, { baseUrl: upstream.baseUrl }),
        }),
        (error) => error.classification === 'RECOVERY_DESTINATION_INVALID',
      );
      assert.deepEqual(
        fs.readdirSync(quarantineRoot).filter((entry) => entry.endsWith('.v1.json')).sort(),
        forensicCassettesBeforeSymlinkAttempt,
        'symlink destination promotion polluted the forensic root',
      );
      const promoted = await restartedJournal.promoteFlushedCaptureSet(captureSetId, {
        classification: 'HARNESS_CAPTURE_RECOVERY_FIXTURE_FAILURE',
        firstObserved: 'recorder exited after flush before immutable promotion',
        firstFailureRecordingId,
        destinationDirectory,
        replay: async (envelope) => restartedJournal.replay(envelope, {
          baseUrl: upstream.baseUrl,
        }),
      });
      assert.equal(promoted.replay?.ok, true, 'recovered promotion did not retain the replay proof');
      assert.equal(fs.statSync(promoted.cassettePath).mode & 0o777, 0o444, 'recovered cassette was not immutable');
      assert.ok(fs.existsSync(reloaded.records[0].rawPath), 'recovery promotion rewrote or removed the first raw member');
      assert.equal(promoted.replay.source_digest, reloaded.sourceDigest, 'replay proof was not bound to the flushed source digest');
    } finally {
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });

  test('e2e_recording_promotion_never_deletes_existing_immutable_cassette', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-promotion-existing-'));
    const destinationDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-promotion-existing-destination-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let upstream;
    let edge;
    try {
      upstream = await startHttpServer((request, response) => {
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.end('existing-cassette');
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'promotion-existing-edge',
        journal,
        ledger,
        canonicalOrigin: upstream.baseUrl,
      }));
      const result = await requestLocalEdge(`${edge.baseUrl}/existing`, {});
      assert.equal(result.status, 200);
      const record = journal.first({ boundary: 'promotion-existing-edge', responseStatus: 200 });
      assert.ok(record?.recordingId, 'the real local exchange was not captured');
      const existingPath = path.join(destinationDirectory, `${record.recordingId}.v1.json`);
      const existingBytes = Buffer.from(JSON.stringify({ immutable: true, owner: testInfo.title }) + '\n');
      fs.writeFileSync(existingPath, existingBytes, { mode: 0o600, flag: 'wx' });
      fs.chmodSync(existingPath, 0o444);
      const before = fs.statSync(existingPath);
      await assert.rejects(
        () => journal.promote(record, {
          destinationDirectory,
          replayProof: { ok: true },
        }),
        (error) => Boolean(error),
      );
      const after = fs.statSync(existingPath);
      assert.deepEqual(fs.readFileSync(existingPath), existingBytes, 'duplicate promotion changed the immutable cassette bytes');
      assert.equal(after.mode & 0o777, 0o444, 'duplicate promotion changed immutable cassette permissions');
      assert.equal(after.ino, before.ino, 'duplicate promotion replaced the immutable cassette inode');
    } finally {
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });

  test('e2e_http_ingress_is_durably_captured_before_body_bound_failure', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-ingress-bound-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let upstream;
    let edge;
    try {
      let upstreamRequests = 0;
      upstream = await startHttpServer((request, response) => {
        upstreamRequests += 1;
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.end('unexpected upstream request');
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'ingress-bound-edge',
        journal,
        ledger,
        canonicalOrigin: upstream.baseUrl,
      }));
      const body = Buffer.alloc(4 * 1024 * 1024 + 1, 0x78);
      const result = await requestLocalEdgeWithBody(`${edge.baseUrl}/oversized-ingress`, { body });
      assert.equal(upstreamRequests, 0, 'body-bound failure escaped to the upstream edge');
      assert.ok(
        journal.records.some((record) => record.boundary === 'ingress-bound-edge'),
        `request ingress was not durably captured before body parsing failed (status=${result.status})`,
      );
    } finally {
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });

  test('e2e_jwks_ingress_is_durably_captured_before_path_assertion', async ({}, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-jwks-ingress-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let jwks;
    try {
      jwks = await startAccessFixture({
        ledger,
        journal,
        managementOrigin: 'http://127.0.0.1',
        callbackOrigin: 'http://127.0.0.2',
      });
      const result = await requestLocalEdge(`${jwks.jwksServer.baseUrl}/unexpected`, {});
      assert.equal(result.status, 404, 'JWKS path guard did not return its typed local 404');
      assert.ok(
        journal.records.some((record) => record.boundary === 'access-jwks-fixture'),
        'JWKS exchange was not durably captured before method/path assertion',
      );
    } finally {
      try { await jwks?.jwksServer?.close(); } catch {}
    }
  });

  test('e2e_http_streaming_proxy_forwards_durable_chunk_before_terminal_and_records_client_disconnect', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-streaming-proxy-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    const upstreamStarted = new Barrier('streaming upstream started');
    const releaseUpstream = new Barrier('release streaming upstream');
    let upstream;
    let edge;
    let firstChunkPromise;
    try {
      upstream = await startHttpServer(async (request, response) => {
        if (request.url === '/bootstrap') {
          response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
          response.end('<title>streaming proxy regression</title>');
          return;
        }
        assert.equal(request.url, '/stream');
        response.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
        });
        response.flushHeaders();
        response.write(': durable-first-chunk\n\n');
        upstreamStarted.notify();
        await releaseUpstream.wait();
        if (!response.destroyed) response.end('data: terminal\n\n');
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'streaming-proxy-edge',
        journal,
        ledger,
        canonicalOrigin: upstream.baseUrl,
      }));
      await page.goto(`${edge.baseUrl}/bootstrap`, { waitUntil: 'domcontentloaded' });
      firstChunkPromise = page.evaluate(async () => {
        const controller = new AbortController();
        window.__zodeStreamingProxyAbort = () => controller.abort();
        try {
          const response = await fetch('/stream', {
            headers: { accept: 'text/event-stream' },
            signal: controller.signal,
          });
          const first = response.body ? await response.body.getReader().read() : undefined;
          controller.abort();
          return {
            status: response.status,
            contentType: response.headers.get('content-type') || '',
            text: first?.value ? new TextDecoder().decode(first.value) : '',
          };
        } finally {
          delete window.__zodeStreamingProxyAbort;
        }
      });
      await upstreamStarted.wait();
      let timer;
      const observed = await Promise.race([
        firstChunkPromise,
        new Promise((resolve) => {
          timer = setTimeout(() => resolve({ timedOut: true }), 2_000);
        }),
      ]).finally(() => clearTimeout(timer));
      assert.equal(observed.timedOut, undefined, 'the durable upstream SSE chunk was buffered until terminal');
      assert.equal(observed.status, 200);
      assert.match(observed.contentType, /^text\/event-stream(?:;|$)/i);
      assert.equal(observed.text, ': durable-first-chunk\n\n');
      await journal.waitForIdle();
      const record = journal.first({
        boundary: 'streaming-proxy-edge',
        method: 'GET',
        requestPath: '/stream',
        responseStatus: 200,
      });
      assert.ok(record, 'streaming client disconnect was not durably captured');
      assert.equal(record.response.outcome, 'client_disconnected');
      assert.equal(
        Buffer.from(record.response.chunks[0].data_base64, 'base64').toString(),
        ': durable-first-chunk\n\n',
      );
      assert.equal(fs.statSync(record.rawPath).mode & 0o777, 0o600);
    } finally {
      await page.evaluate(() => window.__zodeStreamingProxyAbort?.()).catch(() => undefined);
      releaseUpstream.notify();
      await firstChunkPromise?.catch(() => undefined);
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });

  test('e2e_browser_replay_edge_restores_canonical_host_and_forwarded_headers', async ({ browser }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-browser-host-surface-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let canonicalOrigin;
    const forwarded = 'for=203.0.113.12;host=spoof-browser.invalid';
    const xForwardedHost = 'spoof-browser.invalid';
    let upstream;
    let edge;
    let replayEdge;
    let replayContext;
    try {
      upstream = await startHttpServer((request, response) => {
        if (request.method !== 'GET' || request.url !== '/browser-host-surface') {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end('<title>browser host surface</title>');
      });
      canonicalOrigin = upstream.baseUrl;
      const captureSetId = journal.beginCaptureSet({
        e2eName: testInfo.title,
        maxMembers: 1,
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'browser-host-surface-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin,
      }));
      const captureContext = await browser.newContext({ extraHTTPHeaders: {
        forwarded,
        'x-forwarded-host': xForwardedHost,
      } });
      const capturePage = await captureContext.newPage();
      const captured = await capturePage.goto(`${edge.baseUrl}/browser-host-surface`, { waitUntil: 'domcontentloaded' });
      assert.equal(captured?.status(), 200, 'the browser did not capture the local Host/forwarding edge exchange');
      await captureContext.close();

      const first = journal.first({ boundary: 'browser-host-surface-edge', responseStatus: 200 });
      assert.ok(first?.rawPath, 'the browser Host/forwarding exchange was not durably captured');
      const promoted = await journal.promoteCaptureSet(captureSetId, {
        e2eName: testInfo.title,
        classification: 'HARNESS_BROWSER_HOST_SURFACE_FIXTURE_FAILURE',
        firstObserved: 'real Chromium browser edge exchange required canonical Host and forwarding restoration',
        firstFailureRecordingId: first.recordingId,
        replay: async (envelope) => {
          replayEdge = await journal.startReplayEdge(envelope, { canonicalOrigin: upstream.baseUrl });
          const wrongContext = await browser.newContext({ extraHTTPHeaders: {
            forwarded: 'for=198.51.100.24;host=wrong-browser.invalid',
            'x-forwarded-host': 'wrong-browser.invalid',
          } });
          const wrongPage = await wrongContext.newPage();
          const wrongReplay = await wrongPage.goto(`${replayEdge.baseUrl}/browser-host-surface`, { waitUntil: 'domcontentloaded' });
          assert.equal(wrongReplay?.status(), 500, 'browser replay silently overwrote an explicitly spoofed forwarding header');
          try {
            await replayEdge.finish();
          } catch (error) {
            assert.equal(error.classification, 'REPLAY_REQUEST_HEADER_MISMATCH');
          }
          assert.equal(
            replayEdge.server.failures[0]?.classification,
            'REPLAY_REQUEST_HEADER_MISMATCH',
            'explicit browser forwarding spoof did not produce a typed replay mismatch',
          );
          await wrongContext.close();
          replayEdge = undefined;

          replayEdge = await journal.startReplayEdge(envelope, { canonicalOrigin: upstream.baseUrl });
          replayContext = await browser.newContext();
          const replayPage = await replayContext.newPage();
          const replayed = await replayPage.goto(`${replayEdge.baseUrl}/browser-host-surface`, { waitUntil: 'domcontentloaded' });
          assert.equal(replayed?.status(), 200, 'browser replay edge did not restore the captured forwarding headers');
          await replayContext.close();
          replayContext = undefined;
          await replayEdge.finish();
          replayEdge = undefined;
          assert.equal(journal.records.length, 1, 'browser replay appended a member to the sealed capture set');
          return { ok: true };
        },
      });
      assert.equal(promoted.replay?.ok, true, 'browser Host/forwarding replay proof was not retained');
    } finally {
      try { await replayContext?.close(); } catch {}
      try { await replayEdge?.finish(); } catch {}
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });

  test('e2e_browser_replay_edge_preserves_exchange_order_when_body_is_held', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-replay-held-body-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let upstream;
    let edge;
    let replayEdge;
    let notifyPostArrived;
    const postArrived = new Promise((resolve) => { notifyPostArrived = resolve; });
    try {
      upstream = await startHttpServer(async (request, response) => {
        if (request.method === 'GET' && request.url === '/bootstrap') {
          response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
          response.end('bootstrap');
          return;
        }
        if (request.method === 'POST' && request.url === '/slow') {
          const body = [];
          for await (const chunk of request) body.push(Buffer.from(chunk));
          assert.equal(Buffer.concat(body).toString('utf8'), 'held', 'capture fixture received an unexpected held body');
          response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
          response.end('slow');
          return;
        }
        if (request.method === 'GET' && request.url === '/fast') {
          response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
          response.end('fast');
          return;
        }
        response.writeHead(404, { 'content-type': 'text/plain' });
        response.end('not found');
      });
      const captureSetId = journal.beginCaptureSet({
        e2eName: testInfo.title,
        maxMembers: 3,
      });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'replay-held-body-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: upstream.baseUrl,
      }));
      const bootstrap = await page.goto(`${edge.baseUrl}/bootstrap`, { waitUntil: 'domcontentloaded' });
      assert.equal(bootstrap?.status(), 200, 'the browser did not establish the held-body capture edge');
      const captured = await page.evaluate(async () => {
        const slow = await fetch('/slow', {
          method: 'POST',
          headers: { 'content-type': 'text/plain' },
          body: 'held',
        });
        const fast = await fetch('/fast');
        return {
          slow: { status: slow.status, body: await slow.text() },
          fast: { status: fast.status, body: await fast.text() },
        };
      });
      assert.equal(captured.slow.status, 200);
      assert.equal(captured.fast.status, 200);
      const first = journal.first({ boundary: 'replay-held-body-edge', responseStatus: 200 });
      assert.ok(first?.rawPath, 'the held-body browser exchanges were not retained in quarantine');
      const prepared = journal.prepareCaptureSetPromotion(captureSetId, {
        e2eName: testInfo.title,
        classification: 'HARNESS_REPLAY_HELD_BODY_ORDER_FIXTURE_FAILURE',
        firstObserved: 'a real public POST body was held at the replay edge while Chromium issued the next public GET',
        firstFailureRecordingId: first.recordingId,
      });
      assert.equal(prepared.captureSet.records.length, 3, 'bootstrap, held POST, and fast GET were not all retained');

      replayEdge = await journal.startReplayEdge(prepared.envelope, {
        canonicalOrigin: upstream.baseUrl,
        onDispatch: ({ request }) => {
          if (request.method === 'POST' && request.url === '/slow') notifyPostArrived();
        },
      });
      const replayBootstrap = await page.goto(`${replayEdge.baseUrl}/bootstrap`, { waitUntil: 'domcontentloaded' });
      assert.equal(replayBootstrap?.status(), 200, 'the replay edge did not establish the browser origin');
      const postExchange = prepared.envelope.exchanges.find((exchange) => exchange.method === 'POST' && exchange.path === '/slow');
      assert.ok(postExchange, 'held POST exchange was not present in the promoted envelope');
      const postHeaders = Object.fromEntries(
        Object.entries(postExchange.request_headers || {}).map(([name, value]) => [name, ledger.restore(value)]),
      );
      let heldPostRequest;
      const heldPostResponse = new Promise((resolve, reject) => {
        heldPostRequest = http.request(new URL('/slow', replayEdge.baseUrl), {
          method: 'POST',
          headers: { ...postHeaders, expect: '100-continue', 'content-length': '4' },
        }, (response) => {
          const chunks = [];
          response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          response.once('error', reject);
          response.once('end', () => resolve({
            status: response.statusCode || 0,
            body: Buffer.concat(chunks).toString('utf8'),
          }));
        });
        heldPostRequest.once('error', reject);
        heldPostRequest.flushHeaders();
      });
      // A real public POST has entered the replay edge and its request body is
      // intentionally left unterminated.  Chromium drives the next public
      // GET through the same edge while this request is held.
      await postArrived;
      const fastRequest = page.waitForRequest((request) => request.url() === `${replayEdge.baseUrl}/fast`);
      const fastResponse = page.evaluate(async () => {
        const response = await fetch('/fast');
        return { status: response.status, body: await response.text() };
      });
      await fastRequest;
      // The browser has dispatched GET /fast while POST /slow is still held.
      // Release the POST only after that public request barrier, so the edge
      // must retain exchange-1 until its body/dispatch fully completes.
      heldPostRequest.end('held');
      const replayed = {
        slow: await heldPostResponse,
        fast: await fastResponse,
      };
      assert.deepEqual(replayed, {
        slow: { status: 200, body: 'slow' },
        fast: { status: 200, body: 'fast' },
      }, `held POST and subsequent GET did not replay in cassette order: ${JSON.stringify(replayEdge.failures.map((failure) => ({ classification: failure.classification, message: failure.message, details: failure.details })))}`);
      await replayEdge.finish();
      replayEdge = undefined;
    } finally {
      try { await replayEdge?.finish(); } catch {}
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
      // Keep the first raw members in the test-owned quarantine on red.
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
      replayServer = await journal.startReplayEdge(delayedCassette, {
        timingMode: 'captured',
        canonicalOrigin: upstream.baseUrl,
      });
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

  test('e2e_browser_replay_accepts_same_bytes_after_transport_chunk_coalescing', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-replay-chunk-coalescing-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    const body = Buffer.from('chunk-one-chunk-two', 'utf8');
    const firstChunkSent = new Barrier('chunk coalescing first chunk');
    const releaseSecondChunk = new Barrier('chunk coalescing second chunk');
    let upstream;
    let edge;
    let coalesced;
    try {
      upstream = await startHttpServer(async (request, response) => {
        if (request.method !== 'GET' || request.url !== '/chunk-coalescing') {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        response.write(body.subarray(0, 10));
        firstChunkSent.notify();
        await releaseSecondChunk.wait();
        response.end(body.subarray(10));
      });
      const captureSetId = journal.beginCaptureSet({ e2eName: testInfo.title, maxMembers: 1 });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: upstream.baseUrl,
        request,
        response,
        boundary: 'replay-chunk-coalescing-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: upstream.baseUrl,
      }));

      const navigation = page.goto(`${edge.baseUrl}/chunk-coalescing`, { waitUntil: 'load' });
      await firstChunkSent.wait();
      releaseSecondChunk.notify();
      const captured = await navigation;
      assert.equal(captured?.status(), 200, 'the real browser did not capture the chunked local edge response');
      const first = journal.first({ boundary: 'replay-chunk-coalescing-edge', responseStatus: 200 });
      assert.ok(first?.rawPath, 'the chunked browser exchange was not retained in quarantine');
      const capturedBody = Buffer.concat(first.response.chunks.map((chunk) => Buffer.from(chunk.data_base64, 'base64')));
      assert.deepEqual(capturedBody, body, 'the first browser exchange did not retain the complete response bytes');
      assert.ok(first.response.chunks.length >= 2, 'the fixture did not create a distinct captured chunk boundary');

      coalesced = await startHttpServer((request, response) => {
        if (request.method !== 'GET' || request.url !== '/chunk-coalescing') {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        // This is the same public response bytes delivered by a target that
        // coalesces the two transport reads into one Node response chunk.
        response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        response.end(body);
      });
      const promoted = await journal.promoteCaptureSet(captureSetId, {
        e2eName: testInfo.title,
        classification: 'HARNESS_TRANSPORT_CHUNK_RESEGMENTATION',
        firstObserved: 'real browser response bytes were split by one HTTP hop and coalesced by the replay target',
        firstFailureRecordingId: first.recordingId,
        replay: async (envelope) => ({
          ok: true,
          results: await journal.replay(envelope, { baseUrl: coalesced.baseUrl }),
        }),
      });
      assert.ok(promoted.cassettePath, 'same-entry replay did not promote the coalesced-byte cassette');
      assert.equal(
        promoted.replay?.results?.[0]?.chunks,
        first.response.chunks.length,
        'replay proof did not retain the captured logical chunk count',
      );
    } finally {
      try { await coalesced?.close(); } catch {}
      try { await edge?.close(); } catch {}
      try { await upstream?.close(); } catch {}
    }
  });

  test('e2e_browser_replay_rejects_same_bytes_with_terminal_outcome_mismatch', async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const quarantineRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-replay-terminal-outcome-'));
    const destinationDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-replay-terminal-destination-'));
    const ledger = new SecretLedger();
    const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
    let unavailable;
    let edge;
    let replayTarget;
    try {
      unavailable = await startHttpServer(() => {});
      const unavailableBaseUrl = unavailable.baseUrl;
      await unavailable.close();
      unavailable = undefined;

      const captureSetId = journal.beginCaptureSet({ e2eName: testInfo.title, maxMembers: 1 });
      edge = await startHttpServer((request, response) => proxyHttp({
        targetBaseUrl: unavailableBaseUrl,
        request,
        response,
        boundary: 'replay-terminal-outcome-edge',
        journal,
        ledger,
        captureSetId,
        canonicalOrigin: unavailableBaseUrl,
      }));
      const captured = await page.goto(`${edge.baseUrl}/terminal-outcome`, { waitUntil: 'load' });
      assert.equal(captured?.status(), 502, 'the real browser did not observe the captured upstream failure response');

      const first = journal.first({ boundary: 'replay-terminal-outcome-edge', responseStatus: 502 });
      assert.ok(first?.rawPath, 'the terminal-outcome first occurrence was not durably retained');
      assert.equal(first.response.outcome, 'transport_error', 'the fixture did not capture a transport terminal outcome');
      const capturedBody = Buffer.concat(first.response.chunks.map((chunk) => Buffer.from(chunk.data_base64, 'base64')));
      assert.ok(capturedBody.length > 0, 'the captured failure response had no body bytes');

      replayTarget = await startHttpServer((request, response) => {
        if (request.method !== 'GET' || request.url !== '/terminal-outcome') {
          response.writeHead(404, { 'content-type': 'text/plain' });
          response.end('not found');
          return;
        }
        // Keep status and bytes identical, but terminate by disconnecting the
        // response.  Same-entry replay must reject this outcome difference.
        response.writeHead(502, { 'content-type': 'application/json' });
        response.write(capturedBody);
        setImmediate(() => response.socket?.destroy());
      });

      await assert.rejects(
        journal.promoteCaptureSet(captureSetId, {
          e2eName: testInfo.title,
          classification: 'HARNESS_TERMINAL_OUTCOME_MISMATCH',
          firstObserved: 'real browser observed the same bytes before a replay target changed terminal outcome',
          firstFailureRecordingId: first.recordingId,
          destinationDirectory,
          replay: async (envelope) => ({
            ok: true,
            results: await journal.replay(envelope, { baseUrl: replayTarget.baseUrl }),
          }),
        }),
        (error) => error?.classification === 'REPLAY_TERMINATION_MISMATCH',
        'same status/body with a different terminal outcome was accepted',
      );
      assert.deepEqual(fs.readdirSync(destinationDirectory), [], 'terminal-outcome mismatch wrote a cassette');
    } finally {
      try { await replayTarget?.close(); } catch {}
      try { await edge?.close(); } catch {}
      try { await unavailable?.close(); } catch {}
    }
  });
});
