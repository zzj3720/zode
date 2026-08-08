#!/usr/bin/env node
'use strict';

/*
 * Public browser/process red for persistent provider ownership.  A user-owned
 * descriptor is created at the reserved test identity before the smoke
 * subprocess; the smoke must refuse it before any PUT can mutate it.
 */
const { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const repository = path.resolve(__dirname, '..', '..');
const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
const entry = path.join(repository, 'release', 'local-channel.cjs');
const smoke = path.join(repository, 'tests', 'release_e2e', 'installed_channel_browser_smoke_e2e.cjs');
const { chromium } = require(path.join(
  repository, 'web', 'e2e', 'node_modules', '@playwright', 'test',
));
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-provider-ownership-'));
const channelRoot = path.join(workspace, 'channel');
const reservedProviderId = 'zode-installed-live-test';
const quarantine = path.join(
  repository,
  'target',
  'test-recordings',
  'quarantine',
  `installed-channel-provider-ownership-${Date.now()}`,
);

function fail(message, details = {}) {
  const error = new Error(message);
  error.details = details;
  throw error;
}

function run(args, env = {}) {
  const result = spawnSync(process.execPath, [entry, ...args], {
    cwd: repository,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  let payload = null;
  for (const line of String(result.stdout || '').trim().split(/\r?\n/).reverse()) {
    try { payload = JSON.parse(line); break; } catch { /* structured output is last */ }
  }
  return { status: result.status ?? 1, stdout: result.stdout || '', stderr: result.stderr || '', payload };
}

function runSmoke(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [smoke], {
      cwd: repository,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('close', (status, signal) => resolve({
      status: status ?? 1,
      signal,
      stdout: Buffer.concat(stdout).toString('utf8').slice(0, 16_384),
      stderr: Buffer.concat(stderr).toString('utf8').slice(0, 16_384),
    }));
  });
}

function readRequest(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
}

function close(server) {
  return new Promise((resolve) => server?.close(() => resolve()));
}

function preserveFailure(error, details) {
  try {
    const fs = require('node:fs');
    fs.mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    chmodSync(quarantine, 0o700);
    const target = path.join(quarantine, 'installed-channel-provider-ownership-first-failure.json');
    if (!existsSync(target)) {
      writeFileSync(target, `${JSON.stringify({
        schema: 'zode.installed-channel-provider-ownership-failure.v1',
        relation: 'first_post_rule_test_occurrence',
        error: String(error?.message || error),
        details,
      }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    }
  } catch { /* the public failure remains the authoritative red */ }
}

async function main() {
  if (!artifact) {
    process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'missing_artifact' }) + '\n');
    process.exitCode = 78;
    return;
  }
  let userProvider;
  let recorderProvider;
  let recorderRequests = 0;
  let browser;
  let started = false;
  let phase = 'init';
  let userProviderOrigin;
  let userDefaultProfileId;
  try {
    userProvider = http.createServer(async (request, response) => {
      await readRequest(request);
      response.writeHead(200, { 'content-type': 'text/event-stream' });
      response.end('data: [DONE]\n\n');
    });
    userProviderOrigin = await listen(userProvider);
    recorderProvider = http.createServer(async (request, response) => {
      recorderRequests += 1;
      await readRequest(request);
      response.writeHead(200, { 'content-type': 'text/event-stream' });
      response.write('data: {"choices":[{"delta":{"content":"ZODE_E2_LIVE_OK"},"finish_reason":null}]}\n\n');
      response.write('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n');
      response.end('data: [DONE]\n\n');
    });
    const recorderOrigin = await listen(recorderProvider);
    const initialEnv = { ZODE_RELEASE_PROVIDER_ORIGINS: userProviderOrigin };

    phase = 'initial_install';
    const installed = run(['install', '--artifact', path.resolve(artifact), '--channel-root', channelRoot], initialEnv);
    if (installed.status !== 0 || installed.payload?.ok !== true) fail('ownership fixture install failed', installed);
    const startedResult = run(['start', '--channel-root', channelRoot], initialEnv);
    if (startedResult.status !== 0 || startedResult.payload?.ok !== true) fail('ownership fixture start failed', startedResult);
    started = true;
    const url = startedResult.payload.url;

    phase = 'create_user_descriptor';
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Providers', exact: true }).click();
    await page.getByRole('button', { name: 'Configure provider' }).click();
    await page.getByLabel('Provider ID').fill(reservedProviderId);
    await page.getByLabel('Base URL').fill(userProviderOrigin);
    await page.getByLabel('Models').fill('user-owned-model');
    await page.getByRole('button', { name: 'Save provider' }).click();
    await page.getByText(`${reservedProviderId} is ready for an auth profile.`, { exact: true }).waitFor();
    const userCard = page.locator('article.resource-card').filter({
      has: page.getByRole('heading', { name: reservedProviderId, exact: true }),
    });
    await userCard.getByText(userProviderOrigin, { exact: true }).waitFor();
    await userCard.getByRole('button', { name: 'Add API key profile' }).click();
    await userCard.getByLabel('Profile label').fill('User-owned default profile');
    await userCard.getByLabel('API key').fill('user-owned-fixture-key');
    await userCard.getByLabel('Share with this machine').check();
    await userCard.getByRole('button', { name: 'Create profile' }).click();
    await page.getByText('Profile installed on the selected Endpoint.', { exact: true }).waitFor();
    userDefaultProfileId = await page.evaluate(async (provider) => {
      const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, { headers: { accept: 'application/json' } });
      const payload = await response.json();
      return (payload.items || []).find((item) => item.is_default)?.profile_id || null;
    }, reservedProviderId);
    if (!userDefaultProfileId) fail('ownership fixture did not create a durable default profile');

    const stopped = run(['stop', '--channel-root', channelRoot], initialEnv);
    if (stopped.status !== 0 || stopped.payload?.ok !== true) fail('ownership fixture pre-stop failed', stopped);
    started = false;

    phase = 'run_persistent_smoke';
    const smokeResult = await runSmoke({
      ZODE_RELEASE_CHANNEL_ARTIFACT: path.resolve(artifact),
      ZODE_RELEASE_LOCAL_CHANNEL_ROOT: channelRoot,
      ZODE_RELEASE_LIVE_PROVIDER_BASE_URL: `${recorderOrigin}/zen/go/v1`,
      ZODE_RELEASE_LIVE_PROVIDER_API_KEY: 'ownership-test-key',
    });
    if (smokeResult.status === 0) fail('persistent smoke did not refuse a user-owned reserved provider identity', {
      ...smokeResult,
      recorder_requests: recorderRequests,
    });

    phase = 'verify_user_descriptor';
    const resumed = run(['start', '--channel-root', channelRoot], initialEnv);
    if (resumed.status !== 0 || resumed.payload?.ok !== true) fail('ownership fixture restart failed', resumed);
    started = true;
    await page.goto(resumed.payload.url, { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Providers', exact: true }).click();
    const resumedCard = page.locator('article.resource-card').filter({
      has: page.getByRole('heading', { name: reservedProviderId, exact: true }),
    });
    const actualText = await resumedCard.innerText();
    const observedDefaultProfileId = await page.evaluate(async (provider) => {
      const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, { headers: { accept: 'application/json' } });
      const payload = await response.json();
      return (payload.items || []).find((item) => item.is_default)?.profile_id || null;
    }, reservedProviderId);
    const ownershipFailures = [];
    if (!actualText.includes(userProviderOrigin)) ownershipFailures.push('descriptor');
    if (observedDefaultProfileId !== userDefaultProfileId) ownershipFailures.push('default_profile');
    if (ownershipFailures.length > 0) {
      fail('persistent smoke rewrote a user-owned provider descriptor', {
        ownership_failures: ownershipFailures,
        expected_base_url: userProviderOrigin,
        observed_card: actualText,
        expected_default_profile_id: userDefaultProfileId,
        observed_default_profile_id: observedDefaultProfileId,
        smoke_stdout: smokeResult.stdout.slice(-4_096),
        smoke_stderr: smokeResult.stderr.slice(-4_096),
      });
    }
    process.stdout.write(JSON.stringify({
      status: 'PASS',
      operation: 'installed_channel_provider_ownership',
      user_provider: reservedProviderId,
      user_base_url: userProviderOrigin,
      smoke_status: smokeResult.status,
    }) + '\n');
  } catch (error) {
    preserveFailure(error, { phase, channel_root: channelRoot, user_provider_origin: userProviderOrigin });
    process.stderr.write(`${JSON.stringify({
      status: 'RED',
      operation: 'installed_channel_provider_ownership',
      error: String(error?.message || error),
      details: error?.details || {},
    })}\n`);
    process.exitCode = 1;
  } finally {
    await browser?.close().catch(() => {});
    if (started) {
      try { run(['stop', '--channel-root', channelRoot]); } catch { /* preserve evidence */ }
    }
    await close(userProvider);
    await close(recorderProvider);
    try { rmSync(workspace, { recursive: true, force: true }); } catch { /* evidence remains */ }
  }
}

main().catch((error) => {
  preserveFailure(error, {});
  process.stderr.write(`${JSON.stringify({ status: 'HARNESS_ERROR', error: String(error) })}\n`);
  process.exitCode = 2;
});
