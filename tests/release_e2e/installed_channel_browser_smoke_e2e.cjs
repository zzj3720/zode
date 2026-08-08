#!/usr/bin/env node
'use strict';

/*
 * Installed-channel browser smoke.  The only product processes in this test
 * are the immutable artifact's zode-server/zode children.  The JWKS edge and
 * fake provider are test-owned boundary fixtures; the browser uses the same
 * Access-protected origin for every management request.
 */
const {
  generateKeyPairSync,
  sign,
  randomUUID,
} = require('node:crypto');
const {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const repositoryRoot = path.resolve(__dirname, '..', '..');
const { chromium } = require(path.join(repositoryRoot, 'web', 'e2e', 'node_modules', '@playwright', 'test'));
const channelEntry = path.join(repositoryRoot, 'release', 'channel.cjs');
const runId = `${Date.now()}-${randomUUID()}`;
const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
const quarantine = path.join(repositoryRoot, 'target', 'test-recordings', 'quarantine', runId);

function fail(message, details = {}) {
  const error = new Error(message);
  error.details = details;
  throw error;
}

function jsonLine(stdout) {
  for (const line of String(stdout || '').trim().split(/\r?\n/).reverse()) {
    try { return JSON.parse(line); } catch { /* readiness lines precede the result */ }
  }
  return null;
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
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function close(server) {
  return new Promise((resolve) => server?.close(() => resolve()));
}

function base64Url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function jwt(privateKey, issuer, audience, kid) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url({ alg: 'RS256', kid, typ: 'JWT' });
  const claims = base64Url({
    iss: issuer,
    aud: [audience],
    sub: 'installed-channel-browser-user',
    iat: now,
    nbf: now - 1,
    exp: now + 600,
    type: 'app',
  });
  const signature = sign('RSA-SHA256', Buffer.from(`${header}.${claims}`), privateKey).toString('base64url');
  return `${header}.${claims}.${signature}`;
}

function command(executable, args, env) {
  return new Promise((resolve) => {
    const child = spawn(executable, args, {
      cwd: repositoryRoot,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('close', (status, signal) => {
      const out = Buffer.concat(stdout).toString('utf8');
      const err = Buffer.concat(stderr).toString('utf8');
      resolve({ status: status ?? 1, signal, stdout: out, stderr: err, payload: jsonLine(out) });
    });
  });
}

function preserveFailure(error, context) {
  mkdirSync(quarantine, { recursive: true, mode: 0o700 });
  chmodSync(quarantine, 0o700);
  const target = path.join(quarantine, 'installed-channel-browser-first-failure.json');
  if (existsSync(target)) return;
  writeFileSync(target, `${JSON.stringify({
    schema: 'zode.installed-channel-browser-failure.v1',
    recording_id: runId,
    relation: 'first_post_rule_test_occurrence',
    context,
    error: String(error?.message || error),
    details: error?.details || {},
  }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
}

async function startFixtures() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const kid = `installed-channel-${randomUUID()}`;
  const audience = 'zode-installed-channel-browser';
  const providerKey = `installed-provider-${randomUUID()}`;
  const controllerSecret = `installed-controller-${randomUUID()}`;
  const requests = [];
  const provider = http.createServer(async (request, response) => {
    const body = await readRequest(request);
    requests.push({ method: request.method, path: request.url, body });
    response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
    response.write('data: {"choices":[{"delta":{"content":"ZODE_INSTALLED_BROWSER_OK"},"finish_reason":null}]}\n\n');
    response.write('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n');
    response.end('data: [DONE]\n\n');
  });
  const providerOrigin = await listen(provider);
  const jwks = http.createServer((request, response) => {
    if (request.method !== 'GET' || request.url !== '/jwks') {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify({ keys: [{ ...jwk, kid, use: 'sig', alg: 'RS256' }] }));
  });
  const issuer = await listen(jwks);
  const assertion = jwt(privateKey, issuer, audience, kid);
  let targetOrigin = null;
  const edge = http.createServer(async (request, response) => {
    if (!targetOrigin) {
      response.writeHead(503, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'target_not_ready' }));
      return;
    }
    const target = new URL(targetOrigin);
    const headers = { ...request.headers };
    delete headers.connection;
    delete headers['cf-access-jwt-assertion'];
    headers.host = target.host;
    headers['cf-access-jwt-assertion'] = assertion;
    const upstream = http.request({
      hostname: target.hostname,
      port: target.port,
      method: request.method,
      path: request.url,
      headers,
    }, (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on('error', (error) => {
      if (!response.headersSent) response.writeHead(502, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: String(error) }));
    });
    request.pipe(upstream);
  });
  const edgeOrigin = await listen(edge);
  return {
    providerOrigin,
    provider,
    providerKey,
    requests,
    issuer,
    jwks,
    audience,
    assertion,
    controllerSecret,
    edgeOrigin,
    edge,
    setTarget(value) { targetOrigin = value; },
    async close() {
      await close(edge);
      await close(jwks);
      await close(provider);
    },
  };
}

async function main() {
  if (!artifact) {
    process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'missing_artifact' }) + '\n');
    process.exitCode = 78;
    return;
  }
  const root = mkdtempSync(path.join(os.tmpdir(), 'zode-installed-browser-smoke-'));
  const fixtures = await startFixtures();
  let started = false;
  let browser;
  let failure;
  const env = {
    ...process.env,
    ZODE_RELEASE_ACCESS_ASSERTION: fixtures.assertion,
    ZODE_RELEASE_ACCESS_ISSUER: fixtures.issuer,
    ZODE_RELEASE_ACCESS_JWKS_URL: `${fixtures.issuer}/jwks`,
    ZODE_RELEASE_ACCESS_AUDIENCE: fixtures.audience,
    ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER: fixtures.controllerSecret,
  };
  try {
    const installed = await command(process.execPath, [channelEntry, 'install', '--artifact', path.resolve(artifact), '--release-root', root], env);
    if (installed.status !== 0 || installed.payload?.ok !== true) fail('installed artifact install failed', installed);
    const startedResult = await command(process.execPath, [channelEntry, 'start', '--artifact', path.resolve(artifact), '--release-root', root], env);
    if (startedResult.status !== 0 || startedResult.payload?.ok !== true) fail('installed artifact start failed', startedResult);
    started = true;
    const serverUrl = startedResult.payload?.health?.probes?.server_url;
    if (typeof serverUrl !== 'string') fail('installed start did not expose live server probe', startedResult);
    fixtures.setTarget(new URL(serverUrl).origin);
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    const browserRequests = [];
    page.on('request', (request) => browserRequests.push({ method: request.method(), url: request.url() }));
    await page.goto(`${fixtures.edgeOrigin}/`, { waitUntil: 'domcontentloaded' });
    await page.getByText('Sessions', { exact: true }).waitFor();
    await page.getByText('All-in-one ready', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Providers' }).click();
    await page.getByRole('button', { name: 'Configure provider' }).click();
    await page.getByLabel('Provider ID').fill('installed-e2e-provider');
    await page.getByLabel('Base URL').fill(fixtures.providerOrigin);
    await page.getByLabel('Models').fill('installed-e2e-model');
    await page.getByRole('button', { name: 'Save provider' }).click();
    await page.getByText('installed-e2e-provider is ready for an auth profile.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Add API key profile' }).click();
    await page.getByLabel('Profile label').fill('Installed smoke profile');
    await page.getByLabel('API key').fill(fixtures.providerKey);
    await page.getByLabel('Share with this machine').check();
    await page.getByRole('button', { name: 'Create profile' }).click();
    await page.getByText('Profile installed on the selected Endpoint.', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Sessions' }).click();
    await page.getByRole('button', { name: 'New session' }).click();
    await page.getByLabel('Provider').selectOption('installed-e2e-provider');
    await page.getByLabel('Model').selectOption('installed-e2e-model');
    const profileSelect = page.getByLabel('Auth profile');
    await profileSelect.selectOption({ label: 'Installed smoke profile' });
    await page.getByRole('button', { name: 'Start session' }).click();
    await page.getByPlaceholder('Message Zode').fill('Reply with the installed-channel smoke marker.');
    await page.getByRole('button', { name: 'Send' }).click();
    await page.getByText('ZODE_INSTALLED_BROWSER_OK', { exact: true }).waitFor({ timeout: 20_000 });
    const edge = new URL(fixtures.edgeOrigin);
    const managementRequests = browserRequests.filter((item) => new URL(item.url).origin === edge.origin);
    if (!managementRequests.some((item) => item.method === 'POST' && /\/v1\/endpoints\/[^/]+\/sessions$/.test(new URL(item.url).pathname))) {
      fail('browser did not create a session through the installed Server');
    }
    if (!managementRequests.some((item) => item.method === 'POST' && /\/messages$/.test(new URL(item.url).pathname))) {
      fail('browser did not append a message through the installed Server');
    }
    if (browserRequests.some((item) => new URL(item.url).origin !== edge.origin && new URL(item.url).protocol.startsWith('http'))) {
      fail('browser contacted a non-management origin');
    }
    if (fixtures.requests.length !== 1 || !fixtures.requests[0].path.endsWith('/v1/chat/completions')) {
      fail('installed Endpoint did not make exactly one provider request', { count: fixtures.requests.length });
    }
    await browser.close();
    browser = null;
    const stopped = await command(process.execPath, [channelEntry, 'stop', '--release-root', root], env);
    if (stopped.status !== 0 || stopped.payload?.ok !== true) fail('installed channel stop failed', stopped);
    started = false;
    process.stdout.write(JSON.stringify({ status: 'PASS', root, browser_origin: fixtures.edgeOrigin, provider_requests: fixtures.requests.length, browser_management_requests: managementRequests.length }) + '\n');
  } catch (error) {
    failure = error;
    preserveFailure(error, { artifact: path.resolve(artifact), root });
    process.stderr.write(`${JSON.stringify({ status: 'RED', error: String(error.message || error), details: error.details || {} })}\n`);
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close().catch(() => {});
    if (started) {
      await command(process.execPath, [channelEntry, 'stop', '--release-root', root], env).catch(() => {});
    }
    await fixtures.close();
    if (!failure) process.exitCode = 0;
  }
}

main().catch((error) => {
  preserveFailure(error, { artifact: path.resolve(artifact || '') });
  process.stderr.write(`${JSON.stringify({ status: 'HARNESS_ERROR', error: String(error.message || error) })}\n`);
  process.exitCode = 2;
});
