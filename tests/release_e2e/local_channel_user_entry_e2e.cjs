#!/usr/bin/env node
'use strict';

/*
 * Real-process/browser acceptance for the persistent local-channel entry.
 * This intentionally uses a temporary channel root so the test never mutates
 * a user's home installation.  The product still runs from the immutable
 * installed artifact; only the provider boundary is a deterministic local
 * fixture for this channel-entry contract.
 */
const { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { chromium } = require(path.join(
  __dirname,
  '..',
  '..',
  'web',
  'e2e',
  'node_modules',
  '@playwright',
  'test',
));

const repository = path.resolve(__dirname, '..', '..');
const entry = path.join(repository, 'release', 'local-channel.cjs');
const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-local-channel-user-entry-'));
const channelRoot = path.join(workspace, 'channel');
const quarantine = path.join(repository, 'target', 'test-recordings', 'quarantine', `local-channel-user-entry-${Date.now()}`);

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
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  let payload = null;
  for (const line of String(result.stdout || '').trim().split(/\r?\n/).reverse()) {
    try { payload = JSON.parse(line); break; } catch { /* structured output is last */ }
  }
  return { status: result.status ?? 1, stdout: result.stdout || '', stderr: result.stderr || '', payload };
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

function cleanupWorkspace() {
  if (!existsSync(workspace)) return;
  try {
    const fs = require('node:fs');
    function makeWritable(value) {
      const stat = fs.lstatSync(value);
      if (stat.isDirectory()) {
        for (const name of fs.readdirSync(value)) makeWritable(path.join(value, name));
        fs.chmodSync(value, 0o700);
      } else if (stat.isFile()) {
        fs.chmodSync(value, 0o600);
      }
    }
    makeWritable(workspace);
    rmSync(workspace, { recursive: true, force: true });
  } catch { /* first-failure evidence remains in the ignored quarantine */ }
}

function preserveFailure(error, details = {}) {
  try {
    require('node:fs').mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    chmodSync(quarantine, 0o700);
    const target = path.join(quarantine, 'local-channel-user-entry-first-failure.json');
    if (!existsSync(target)) {
      writeFileSync(target, `${JSON.stringify({
        schema: 'zode.local-channel-user-entry-failure.v1',
        relation: 'first_post_rule_test_occurrence',
        error: String(error?.message || error),
        details,
      }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    }
  } catch { /* preserve the public failure even if quarantine is unavailable */ }
}

async function main() {
  if (!artifact) {
    process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'missing_artifact' }) + '\n');
    process.exitCode = 78;
    return;
  }

  let provider;
  const providerRequests = [];
  let browser;
  let started = false;
  let phase = 'init';
  try {
    provider = http.createServer(async (request, response) => {
      await readRequest(request);
      providerRequests.push({ method: request.method, path: request.url });
      response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      response.write('data: {"choices":[{"delta":{"content":"ZODE_USER_ENTRY_OK"},"finish_reason":null}]}\n\n');
      response.write('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n');
      response.end('data: [DONE]\n\n');
    });
    const providerOrigin = await listen(provider);
    const env = { ZODE_RELEASE_PROVIDER_ORIGINS: providerOrigin };

    const installed = run(['install', '--artifact', path.resolve(artifact), '--channel-root', channelRoot], env);
    if (installed.status !== 0 || installed.payload?.ok !== true) fail('persistent channel install failed', installed);

    const startedResult = run(['start', '--channel-root', channelRoot], env);
    if (startedResult.status !== 0 || startedResult.payload?.ok !== true || typeof startedResult.payload?.url !== 'string') {
      fail('persistent channel start did not return a user URL', startedResult);
    }
    started = true;
    const url = startedResult.payload.url;
    phase = 'initial_browser';
    const page = await (browser = await chromium.launch({ headless: true })).newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Sessions', exact: true }).waitFor();
    await page.getByText('All-in-one ready', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Providers' }).click();
    await page.getByRole('button', { name: 'Configure provider' }).click();
    await page.getByLabel('Provider ID').fill('installed-user-entry-provider');
    await page.getByLabel('Base URL').fill(providerOrigin);
    await page.getByLabel('Models').fill('installed-user-entry-model');
    await page.getByRole('button', { name: 'Save provider' }).click();
    await page.getByText('installed-user-entry-provider is ready for an auth profile.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Add API key profile' }).click();
    await page.getByLabel('Profile label').fill('Installed user entry profile');
    await page.getByLabel('API key').fill('user-entry-fixture-key');
    await page.getByLabel('Share with this machine').check();
    await page.getByRole('button', { name: 'Create profile' }).click();
    await page.getByText('Profile installed on the selected Endpoint.', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Sessions' }).click();
    await page.getByRole('button', { name: 'New session' }).click();
    await page.getByLabel('Provider').selectOption('installed-user-entry-provider');
    await page.getByLabel('Model').selectOption('installed-user-entry-model');
    await page.getByLabel('Auth profile').selectOption({ label: 'Installed user entry profile' });
    await page.getByRole('button', { name: 'Start session' }).click();
    await page.getByPlaceholder('Message Zode').fill('Reply with exactly ZODE_USER_ENTRY_OK.');
    await page.getByRole('button', { name: 'Send' }).click();
    await page.getByText('ZODE_USER_ENTRY_OK', { exact: true }).waitFor({ timeout: 20_000 });
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.getByText('ZODE_USER_ENTRY_OK', { exact: true }).waitFor({ timeout: 20_000 });

    phase = 'first_stop';
    const stopped = run(['stop', '--channel-root', channelRoot], env);
    if (stopped.status !== 0 || stopped.payload?.ok !== true) fail('persistent channel stop failed', stopped);
    phase = 'restart';
    const restarted = run(['start', '--channel-root', channelRoot], env);
    if (restarted.status !== 0 || restarted.payload?.ok !== true || restarted.payload.url !== url) {
      fail('persistent channel restart did not preserve the user URL', restarted);
    }
    phase = 'reopened_browser';
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Sessions', exact: true }).waitFor();
    const durableSession = page.locator('a.session-row').first();
    await durableSession.waitFor();
    await durableSession.click();
    await page.getByText('ZODE_USER_ENTRY_OK', { exact: true }).waitFor({ timeout: 20_000 });
    const finalStop = run(['stop', '--channel-root', channelRoot], env);
    if (finalStop.status !== 0 || finalStop.payload?.ok !== true) fail('persistent channel final stop failed', finalStop);

    process.stdout.write(JSON.stringify({
      status: 'PASS',
      url,
      artifact_revision: path.basename(path.resolve(artifact)),
      durable_final_visible_after_restart: true,
    }) + '\n');
  } catch (error) {
    let browserUrl = null;
    try { browserUrl = browser?.contexts()?.[0]?.pages()?.[0]?.url() || null; } catch { /* best effort */ }
    preserveFailure(error, {
      channel_root: channelRoot,
      artifact: artifact ? path.resolve(artifact) : null,
      phase,
      provider_requests: providerRequests,
      browser_url: browserUrl,
    });
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error), details: error.details || {} }) + '\n');
    process.exitCode = 1;
  } finally {
    await browser?.close().catch(() => {});
    if (started) {
      try { run(['stop', '--channel-root', channelRoot]); } catch { /* preserve process evidence for diagnosis */ }
    }
    await close(provider);
    cleanupWorkspace();
  }
}

main().catch((error) => {
  process.stderr.write(JSON.stringify({ status: 'HARNESS_ERROR', error: String(error.message || error) }) + '\n');
  process.exitCode = 2;
});
