#!/usr/bin/env node
'use strict';

/*
 * Installed-channel browser smoke.  The only product processes in this test
 * are the immutable artifact's zode-server/zode children.  The JWKS edge and
 * provider boundary are test-owned fixtures; the browser uses the same
 * Access-protected origin for every management request.  When the live
 * provider variables are present, the provider boundary is the shared
 * recorder URL and the production child receives neither variable.
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
const liveProviderBaseUrl = process.env.ZODE_RELEASE_LIVE_PROVIDER_BASE_URL || null;
const liveProviderApiKey = process.env.ZODE_RELEASE_LIVE_PROVIDER_API_KEY || null;
const liveProviderMode = Boolean(liveProviderBaseUrl || liveProviderApiKey);
const expectedAssistant = liveProviderMode ? 'ZODE_E2_LIVE_OK' : 'ZODE_INSTALLED_BROWSER_OK';
const providerId = liveProviderMode ? 'opencode-go' : 'installed-e2e-provider';
const modelId = liveProviderMode ? 'deepseek-v4-flash' : 'installed-e2e-model';
const profileLabel = liveProviderMode ? 'Installed live smoke profile' : 'Installed smoke profile';
const smokePrompt = liveProviderMode
  ? 'Reply with exactly ZODE_E2_LIVE_OK.'
  : 'Reply with the installed-channel smoke marker.';
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
  if (Boolean(liveProviderBaseUrl) !== Boolean(liveProviderApiKey)) {
    fail('live provider configuration is incomplete');
  }
  let providerOrigin;
  let providerBaseUrl;
  let provider = null;
  const providerKey = liveProviderApiKey || `installed-provider-${randomUUID()}`;
  const controllerSecret = `installed-controller-${randomUUID()}`;
  const requests = [];
  if (liveProviderBaseUrl) {
    let parsed;
    try {
      parsed = new URL(liveProviderBaseUrl);
    } catch {
      fail('live provider base URL is invalid');
    }
    if (
      parsed.protocol !== 'http:' ||
      !['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname)
    ) {
      fail('live provider recorder must use a loopback HTTP URL');
    }
    providerOrigin = parsed.origin;
    providerBaseUrl = liveProviderBaseUrl.replace(/\/$/, '');
  } else {
    provider = http.createServer(async (request, response) => {
      const body = await readRequest(request);
      requests.push({ method: request.method, path: request.url, body });
      response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      response.write('data: {"choices":[{"delta":{"content":"ZODE_INSTALLED_BROWSER_OK"},"finish_reason":null}]}\n\n');
      response.write('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n');
      response.end('data: [DONE]\n\n');
    });
    providerOrigin = await listen(provider);
    providerBaseUrl = providerOrigin;
  }
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
    providerBaseUrl,
    live: liveProviderMode,
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
  let page;
  let browserRequests = [];
  let browserResponses = [];
  let failure;
  const env = {
    ...process.env,
    ZODE_RELEASE_ACCESS_ASSERTION: fixtures.assertion,
    ZODE_RELEASE_ACCESS_ISSUER: fixtures.issuer,
    ZODE_RELEASE_ACCESS_JWKS_URL: `${fixtures.issuer}/jwks`,
    ZODE_RELEASE_ACCESS_AUDIENCE: fixtures.audience,
    ZODE_RELEASE_ENDPOINT_CONTROLLER_BEARER: fixtures.controllerSecret,
    ZODE_RELEASE_PROVIDER_ORIGINS: fixtures.providerOrigin,
  };
  const channelEnv = { ...env };
  for (const key of [
    'ZODE_RELEASE_LIVE_PROVIDER_BASE_URL',
    'ZODE_RELEASE_LIVE_PROVIDER_API_KEY',
    'ZODE_E2E_LIVE_PROVIDER_API_KEY',
    'OPENCODE_GO_API_KEY',
    'OPENCODE_API_KEY',
    'OPENAI_API_KEY',
    'OPENROUTER_API_KEY',
    'ANTHROPIC_API_KEY',
    'GOOGLE_API_KEY',
    'GEMINI_API_KEY',
    'MISTRAL_API_KEY',
    'TOGETHER_API_KEY',
    'XAI_API_KEY',
    'GROQ_API_KEY',
    'COHERE_API_KEY',
  ]) {
    delete channelEnv[key];
  }
  let streamMarkerVisible = false;
  let durableFinalVisible = false;
  try {
    const installed = await command(process.execPath, [channelEntry, 'install', '--artifact', path.resolve(artifact), '--release-root', root], channelEnv);
    if (installed.status !== 0 || installed.payload?.ok !== true) fail('installed artifact install failed', installed);
    const startedResult = await command(process.execPath, [channelEntry, 'start', '--artifact', path.resolve(artifact), '--release-root', root], channelEnv);
    if (startedResult.status !== 0 || startedResult.payload?.ok !== true) fail('installed artifact start failed', startedResult);
    started = true;
    const serverUrl = startedResult.payload?.health?.probes?.server_url;
    if (typeof serverUrl !== 'string') fail('installed start did not expose live server probe', startedResult);
    fixtures.setTarget(new URL(serverUrl).origin);
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    page = await context.newPage();
    browserRequests = [];
    browserResponses = [];
    page.on('request', (request) => {
      const entry = { method: request.method(), url: request.url() };
      if (entry.method === 'POST' && /\/sessions$/.test(new URL(entry.url).pathname)) {
        entry.post_data = request.postData() || '';
      }
      browserRequests.push(entry);
    });
    page.on('response', (response) => {
      const entry = { status: response.status(), url: response.url() };
      browserResponses.push(entry);
      if (entry.status >= 400) {
        void response.text().then((body) => { entry.body = body.slice(0, 4096); }).catch(() => {});
      }
    });
    await page.goto(`${fixtures.edgeOrigin}/`, { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Sessions', exact: true }).waitFor();
    await page.getByText('All-in-one ready', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Providers' }).click();
    await page.getByRole('button', { name: 'Configure provider' }).click();
    await page.getByLabel('Provider ID').fill(providerId);
    await page.getByLabel('Base URL').fill(fixtures.providerBaseUrl);
    await page.getByLabel('Models').fill(modelId);
    await page.getByRole('button', { name: 'Save provider' }).click();
    await page.getByText(`${providerId} is ready for an auth profile.`, { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Add API key profile' }).click();
    await page.getByLabel('Profile label').fill(profileLabel);
    await page.getByLabel('API key').fill(fixtures.providerKey);
    await page.getByLabel('Share with this machine').check();
    await page.getByRole('button', { name: 'Create profile' }).click();
    await page.getByText('Profile installed on the selected Endpoint.', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Sessions' }).click();
    await page.getByRole('button', { name: 'New session' }).click();
    await page.getByLabel('Provider').selectOption(providerId);
    await page.getByLabel('Model').selectOption(modelId);
    const profileSelect = page.getByLabel('Auth profile');
    await profileSelect.selectOption({ label: profileLabel });
    await page.getByRole('button', { name: 'Start session' }).click();
    await page.getByPlaceholder('Message Zode').fill(smokePrompt);
    await page.getByRole('button', { name: 'Send' }).click();
    await page.getByText(expectedAssistant, { exact: true }).waitFor({ timeout: 20_000 });
    streamMarkerVisible = true;
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.getByText(expectedAssistant, { exact: true }).waitFor({ timeout: 20_000 });
    durableFinalVisible = true;
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
    if (!fixtures.live && (fixtures.requests.length !== 1 || !fixtures.requests[0].path.includes('/chat/completions'))) {
      fail('installed Endpoint did not make exactly one provider chat request', {
        count: fixtures.requests.length,
        paths: fixtures.requests.map((request) => request.path),
      });
    }
    await browser.close();
    browser = null;
    const stopped = await command(process.execPath, [channelEntry, 'stop', '--release-root', root], channelEnv);
    if (stopped.status !== 0 || stopped.payload?.ok !== true) fail('installed channel stop failed', stopped);
    started = false;
    process.stdout.write(JSON.stringify({
      status: 'PASS',
      root,
      browser_origin: fixtures.edgeOrigin,
      live_provider: fixtures.live,
      stream_marker_visible: streamMarkerVisible,
      durable_final_visible_after_reload: durableFinalVisible,
      provider_requests: fixtures.live ? null : fixtures.requests.length,
      browser_management_requests: managementRequests.length,
    }) + '\n');
  } catch (error) {
    failure = error;
    const browserState = page
      ? { url: page.url(), body_text: await page.locator('body').innerText().catch(() => '') }
      : {};
    preserveFailure(error, {
      artifact: path.resolve(artifact),
      root,
      browser: browserState,
      requests: browserRequests,
      responses: browserResponses,
      provider_requests: fixtures.requests.map((request) => ({ method: request.method, path: request.path })),
    });
    process.stderr.write(`${JSON.stringify({ status: 'RED', error: String(error.message || error), details: error.details || {} })}\n`);
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close().catch(() => {});
    if (started) {
      await command(process.execPath, [channelEntry, 'stop', '--release-root', root], channelEnv).catch(() => {});
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
