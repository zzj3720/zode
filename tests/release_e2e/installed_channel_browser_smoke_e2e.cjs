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
  unlinkSync,
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
const localChannelEntry = path.join(repositoryRoot, 'release', 'local-channel.cjs');
const runId = `${Date.now()}-${randomUUID()}`;
const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
const persistentRoot = process.env.ZODE_RELEASE_LOCAL_CHANNEL_ROOT || null;
const persistentMode = Boolean(persistentRoot);
const liveProviderBaseUrl = process.env.ZODE_RELEASE_LIVE_PROVIDER_BASE_URL || null;
const liveProviderApiKey = process.env.ZODE_RELEASE_LIVE_PROVIDER_API_KEY || null;
const liveProviderMode = Boolean(liveProviderBaseUrl || liveProviderApiKey);
const expectedAssistant = liveProviderMode ? 'ZODE_E2_LIVE_OK' : 'ZODE_INSTALLED_BROWSER_OK';
const expectedAssistantPattern = liveProviderMode
  ? /^ZODE_E2_LIVE_OK[.!?]?$/
  : /^ZODE_INSTALLED_BROWSER_OK$/;
// The persistent smoke has one explicitly test-owned identity.  It never
// takes over an existing provider with the same ID unless its descriptor
// carries our non-secret ownership marker; a user-owned descriptor is a hard
// failure before any PUT can mutate it.
const testOwnedProviderId = 'zode-installed-live-test';
const testOwnershipMarker = 'zode.installed-channel-live-test.v1';
const providerId = liveProviderMode ? testOwnedProviderId : 'installed-e2e-provider';
const modelId = liveProviderMode ? 'deepseek-v4-flash' : 'installed-e2e-model';
const profileLabel = liveProviderMode
  ? `Installed live smoke ${runId.slice(-8)}`
  : 'Installed smoke profile';
const smokePrompt = liveProviderMode
  ? 'Reply with exactly ZODE_E2_LIVE_OK.'
  : 'Reply with the installed-channel smoke marker.';
const quarantine = path.join(repositoryRoot, 'target', 'test-recordings', 'quarantine', runId);
const approvedProviderBaseUrl = 'https://opencode.ai/zen/go/v1';
const approvedProviderOrigin = new URL(approvedProviderBaseUrl).origin;

function fail(message, details = {}) {
  const error = new Error(message);
  error.details = details;
  throw error;
}

async function waitForAssistantMarkers(page, count, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const markerCount = await page.locator('article.message-assistant').evaluateAll(
      (articles, marker) => articles.filter((article) => {
        const text = article.querySelector('p')?.textContent?.trim() || '';
        return text === marker || text === `${marker}.` || text === `${marker}!` || text === `${marker}?`;
      }).length,
      expectedAssistant,
    );
    if (markerCount >= count) return;
    await page.waitForTimeout(250);
  }
  fail(`browser did not render ${count} durable assistant markers after restart`);
}

async function waitForDurableEventsConnection(page, timeoutMs = 20_000) {
  await page.getByText('Durable events are connected', { exact: true }).waitFor({ timeout: timeoutMs });
}

async function sendComposerPrompt(page, prompt) {
  const input = page.getByPlaceholder('Message Zode');
  const button = page.getByRole('button', { name: 'Send', exact: true });
  await input.waitFor({ timeout: 20_000 });
  const deadline = Date.now() + 20_000;
  while (!(await button.isEnabled()) && Date.now() < deadline) await page.waitForTimeout(100);
  if (!(await button.isEnabled())) {
    fail('browser composer remained disabled after durable SSE reconnect', {
      body: (await page.locator('body').innerText()).slice(-2_000),
    });
  }
  await input.fill(prompt);
  const request = page.waitForRequest((candidate) => {
    if (candidate.method() !== 'POST') return false;
    try { return new URL(candidate.url()).pathname.endsWith('/messages'); } catch { return false; }
  }, { timeout: 10_000 }).catch(() => null);
  await button.click();
  if (!(await request)) {
    fail('browser composer click did not issue the public message request', {
      button_disabled: await button.isDisabled(),
      input_value: await input.inputValue(),
      body: (await page.locator('body').innerText()).slice(-2_000),
    });
  }
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

function acquirePersistentSmokeLock(root) {
  if (!persistentMode) return null;
  const lockPath = path.join(root, '.installed-channel-live-smoke.lock');
  try {
    writeFileSync(lockPath, JSON.stringify({
      schema: 'zode.installed-channel-live-smoke-lock.v1',
      pid: process.pid,
      run_id: runId,
      started_at_unix_ms: Date.now(),
    }) + '\n', { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error?.code === 'EEXIST') {
      let lock;
      try {
        lock = JSON.parse(readFileSync(lockPath, 'utf8'));
      } catch (readError) {
        fail('persistent channel has a malformed live-smoke lock', {
          lock_path: lockPath,
          error: String(readError?.message || readError),
        });
      }
      if (lock?.schema !== 'zode.installed-channel-live-smoke-lock.v1'
        || !Number.isInteger(lock.pid) || lock.pid <= 0) {
        fail('persistent channel has a malformed live-smoke lock', { lock_path: lockPath });
      }
      try {
        process.kill(lock.pid, 0);
      } catch (probeError) {
        if (probeError?.code !== 'ESRCH') {
          fail('persistent channel live-smoke lock owner could not be verified', {
            lock_path: lockPath,
            pid: lock.pid,
            error: String(probeError?.message || probeError),
          });
        }
        try { unlinkSync(lockPath); } catch (removeError) {
          fail('persistent channel stale live-smoke lock could not be reclaimed', {
            lock_path: lockPath,
            error: String(removeError?.message || removeError),
          });
        }
        return acquirePersistentSmokeLock(root);
      }
    }
    fail('persistent channel is already reserved by another live smoke', {
      lock_path: lockPath,
      error: String(error?.message || error),
    });
  }
  return lockPath;
}

function releasePersistentSmokeLock(lockPath) {
  if (!lockPath) return;
  try { unlinkSync(lockPath); } catch { /* preserve the original test failure */ }
}

async function persistentProviderCleanup(page, { ownedProviderId, ownedBaseUrl, ownershipValidated }) {
  if (!persistentMode) return { updated: [], retained_profiles: [] };
  return page.evaluate(async ({ approvedBaseUrl, cleanupKeyPrefix, ownedProviderId, ownedBaseUrl, ownershipMarker, ownershipValidated }) => {
    async function requestJson(method, pathname, body) {
      const response = await fetch(pathname, {
        method,
        headers: {
          accept: 'application/json',
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          ...(['PUT', 'DELETE'].includes(method)
            ? { 'Idempotency-Key': `${cleanupKeyPrefix}-${method}-${pathname}` }
            : {}),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const text = await response.text();
      let value = null;
      try { value = text ? JSON.parse(text) : null; } catch { /* status is enough for DELETE */ }
      if (!response.ok) {
        throw new Error(`${method} ${pathname} returned ${response.status}`);
      }
      return value;
    }

    const providers = (await requestJson('GET', '/v1/providers')).providers || [];
    const normalizeUrl = (value) => {
      try {
        const parsed = new URL(String(value || ''));
        parsed.hash = '';
        return parsed.toString().replace(/\/$/, '');
      } catch {
        return '';
      }
    };
    const testProviders = providers.filter((provider) => {
      const descriptor = provider.descriptor || {};
      return provider.provider === ownedProviderId
        && ((ownershipValidated && normalizeUrl(descriptor.base_url) === normalizeUrl(ownedBaseUrl))
          || descriptor.options?.zode_test_owner === ownershipMarker);
    });
    if (testProviders.length !== 1) {
      throw new Error(`persistent smoke did not find exactly its owned provider descriptor (${ownedProviderId})`);
    }
    const updated = [];
    const retainedProfiles = [];
    for (const provider of testProviders) {
      await requestJson('PUT', `/v1/providers/${encodeURIComponent(provider.provider)}`, {
        kind: provider.descriptor?.kind,
        base_url: approvedBaseUrl,
        models: provider.descriptor?.models || [],
        options: {
          ...(provider.descriptor?.options || {}),
          ...(ownershipValidated ? { zode_test_owner: ownershipMarker } : {}),
        },
      });
      updated.push(provider.provider);
      retainedProfiles.push(provider.auth_profile_count || 0);
    }
    return { updated, retained_profiles: retainedProfiles };
  }, {
    approvedBaseUrl: approvedProviderBaseUrl,
    cleanupKeyPrefix: `persistent-provider-cleanup-${runId}`,
    ownedProviderId,
    ownedBaseUrl,
    ownershipMarker: testOwnershipMarker,
    ownershipValidated: Boolean(ownershipValidated),
  });
}

async function persistentProfileCleanup(page, { ownedProviderId, profileId }) {
  if (!persistentMode || !liveProviderMode || !profileId) return { status: 'not_applicable' };
  return page.evaluate(async ({ cleanupKeyPrefix, ownedProviderId, profileId, ownershipMarker }) => {
    const providersResponse = await fetch('/v1/providers', { headers: { accept: 'application/json' } });
    if (!providersResponse.ok) throw new Error(`provider list returned ${providersResponse.status}`);
    const provider = ((await providersResponse.json()).providers || [])
      .find((item) => item.provider === ownedProviderId);
    if (provider?.descriptor?.options?.zode_test_owner !== ownershipMarker) {
      throw new Error(`refusing to delete profile from non-owned provider ${ownedProviderId}`);
    }
    const response = await fetch(
      `/v1/providers/${encodeURIComponent(ownedProviderId)}/auth-profiles/${encodeURIComponent(profileId)}`,
      {
        method: 'DELETE',
        headers: {
          accept: 'application/json',
          'Idempotency-Key': `${cleanupKeyPrefix}-DELETE-${ownedProviderId}-${profileId}`,
        },
      },
    );
    const text = await response.text();
    let value = null;
    try { value = text ? JSON.parse(text) : null; } catch { /* status is authoritative */ }
    if (!response.ok) throw new Error(`DELETE owned profile returned ${response.status}`);
    if (!['deleted', 'removal_pending'].includes(value?.status)) {
      throw new Error(`owned profile delete returned unexpected status ${value?.status || 'missing'}`);
    }
    return value;
  }, {
    cleanupKeyPrefix: `persistent-profile-cleanup-${runId}`,
    ownedProviderId,
    profileId,
    ownershipMarker: testOwnershipMarker,
  });
}

async function preparePersistentProvider(page) {
  if (!persistentMode || !liveProviderMode) return;
  const existing = await page.evaluate(async (provider) => {
    const response = await fetch('/v1/providers', { headers: { accept: 'application/json' } });
    if (!response.ok) throw new Error(`provider list returned ${response.status}`);
    return ((await response.json()).providers || []).find((item) => item.provider === provider) || null;
  }, providerId);
  const marker = existing?.descriptor?.options?.zode_test_owner;
  if (existing && marker !== testOwnershipMarker) {
    fail('persistent smoke found a user-owned provider at its reserved test identity', {
      provider: providerId,
      descriptor_revision: existing.descriptor?.revision,
    });
  }
}

async function retainProviderOwnershipMarker(page) {
  if (!persistentMode || !liveProviderMode) return;
  await page.evaluate(async ({ provider, marker, markerKey }) => {
    const response = await fetch('/v1/providers', { headers: { accept: 'application/json' } });
    if (!response.ok) throw new Error(`provider list returned ${response.status}`);
    const record = ((await response.json()).providers || []).find((item) => item.provider === provider);
    if (!record?.descriptor) throw new Error(`provider ${provider} was not saved`);
    const descriptor = record.descriptor;
    const put = await fetch(`/v1/providers/${encodeURIComponent(provider)}`, {
      method: 'PUT',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'Idempotency-Key': `persistent-provider-marker-${markerKey}`,
      },
      body: JSON.stringify({
        kind: descriptor.kind,
        base_url: descriptor.base_url,
        models: descriptor.models || [],
        options: { ...(descriptor.options || {}), zode_test_owner: marker },
      }),
    });
    if (!put.ok) throw new Error(`provider ownership marker returned ${put.status}`);
  }, { provider: providerId, marker: testOwnershipMarker, markerKey: runId });
}

async function findOrCreateProfile(page, providerCard, { providerId, profileLabel, providerKey }) {
  if (persistentMode && liveProviderMode) {
    const profile = await page.evaluate(async ({ provider, label }) => {
      const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
        headers: { accept: 'application/json' },
      });
      if (!response.ok) throw new Error(`profile list returned ${response.status}`);
      return ((await response.json()).items || []).find((item) => item.label === label) || null;
    }, { provider: providerId, label: profileLabel });
    if (profile) {
      throw new Error(`unexpected pre-existing profile label ${label}`);
    }
  }
  await providerCard.getByRole('button', { name: 'Add API key profile' }).click();
  await providerCard.getByLabel('Profile label').fill(profileLabel);
  await providerCard.getByLabel('API key').fill(providerKey);
  const makeDefault = providerCard.getByLabel('Make this the default profile');
  if (persistentMode && await makeDefault.isChecked()) await makeDefault.uncheck();
  await providerCard.getByLabel('Share with this machine').check();
  const [profileResponse] = await Promise.all([
    page.waitForResponse((response) =>
      response.request().method() === 'POST'
        && new URL(response.url()).pathname === `/v1/providers/${encodeURIComponent(providerId)}/auth-profiles`),
    providerCard.getByRole('button', { name: 'Create profile' }).click(),
  ]);
  if (profileResponse.status() !== 201) fail(`profile create returned ${profileResponse.status()}`);
  const profilePayload = await profileResponse.json();
  const profileId = profilePayload.auth_profile_id || profilePayload.profile_id || null;
  if (!profileId) fail('profile create omitted auth profile id');
  await page.getByText('Profile installed on the selected Endpoint.', { exact: true }).waitFor();
  return profileId;
}

async function rebindPersistentSession(page, {
  ownedProviderId,
  modelId,
  profileId,
  sessionPath,
  ownershipMarker,
}) {
  const match = String(sessionPath || '').match(
    /^\/endpoints\/([^/]+)\/sessions\/([^/]+)$/,
  );
  if (!match) fail('persistent smoke session API path was malformed');
  const [endpointId, sessionId] = match.slice(1);
  return page.evaluate(async ({ endpointId, sessionId, providerId, modelId, profileId, ownershipMarker, runId }) => {
    const providerResponse = await fetch('/v1/providers', { headers: { accept: 'application/json' } });
    if (!providerResponse.ok) throw new Error(`provider list returned ${providerResponse.status}`);
    const provider = ((await providerResponse.json()).providers || [])
      .find((item) => item.provider === providerId);
    const descriptor = provider?.descriptor;
    if (!descriptor) throw new Error(`owned provider descriptor ${providerId} disappeared`);
    const profilesResponse = await fetch(
      `/v1/providers/${encodeURIComponent(providerId)}/auth-profiles`,
      { headers: { accept: 'application/json' } },
    );
    if (!profilesResponse.ok) throw new Error(`profile list returned ${profilesResponse.status}`);
    const profile = ((await profilesResponse.json()).items || [])
      .find((item) => (item.auth_profile_id || item.profile_id) === profileId);
    if (!profile) throw new Error(`owned profile ${profileId} disappeared`);
    const endpointsResponse = await fetch('/v1/endpoints', { headers: { accept: 'application/json' } });
    if (!endpointsResponse.ok) throw new Error(`endpoint list returned ${endpointsResponse.status}`);
    const endpoints = (await endpointsResponse.json()).items || [];
    const staleSessions = [];
    for (const endpoint of endpoints) {
      const sessionsResponse = await fetch(
        `/v1/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/sessions`,
        { headers: { accept: 'application/json' } },
      );
      if (!sessionsResponse.ok) throw new Error(`session list returned ${sessionsResponse.status}`);
      for (const session of (await sessionsResponse.json()).items || []) {
        const baseUrl = String(session.model?.provider_execution_base_url || '');
        let isLoopback = false;
        try {
          const parsed = new URL(baseUrl);
          isLoopback = parsed.protocol === 'http:'
            && ['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname);
        } catch { /* malformed selections are left for the guard to report */ }
        if (session.model?.provider === providerId
          && session.model?.provider_execution_options?.zode_test_owner === ownershipMarker
          && isLoopback) {
          staleSessions.push({ endpointId: endpoint.endpoint_id, sessionId: session.session_id });
        }
      }
    }
    if (!staleSessions.some((item) => item.endpointId === endpointId && item.sessionId === sessionId)) {
      throw new Error('persistent smoke session is not marked as test-owned');
    }
    const model = {
      provider: providerId,
      provider_execution: {
        schema: 'zode.provider-execution.v1',
        revision: descriptor.revision,
        kind: descriptor.kind,
        base_url: descriptor.base_url,
        options: descriptor.options || {},
      },
      model: modelId,
      auth_profile_id: profile.auth_profile_id || profile.profile_id,
      minimum_auth_revision: profile.revision,
    };
    const reboundBaseUrls = [];
    for (const target of staleSessions) {
      const response = await fetch(
        `/v1/endpoints/${encodeURIComponent(target.endpointId)}/sessions/${encodeURIComponent(target.sessionId)}/model`,
        {
          method: 'PUT',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json',
            'Idempotency-Key': `persistent-session-rebind-${runId}-${providerId}-${target.sessionId}`,
          },
          body: JSON.stringify(model),
        },
      );
      const text = await response.text();
      if (!response.ok) throw new Error(`persistent session model rebind returned ${response.status}: ${text}`);
      let committed = false;
      for (let attempt = 0; attempt < 80; attempt += 1) {
        const snapshot = await fetch(
          `/v1/endpoints/${encodeURIComponent(target.endpointId)}/sessions/${encodeURIComponent(target.sessionId)}`,
          { headers: { accept: 'application/json' } },
        );
        if (snapshot.ok) {
          const value = await snapshot.json();
          if (value?.model?.provider_execution_base_url === descriptor.base_url) {
            reboundBaseUrls.push(value.model.provider_execution_base_url);
            committed = true;
            break;
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      if (!committed) {
        throw new Error(`persistent session model rebind did not become durable for ${target.sessionId}`);
      }
    }
    return { endpointId, sessionId, reboundCount: staleSessions.length, reboundBaseUrls };
  }, {
    endpointId,
    sessionId,
    providerId: ownedProviderId,
    modelId,
    profileId,
    ownershipMarker,
    runId,
  });
}

async function startFixtures({ persistent = false } = {}) {
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
  if (persistent) {
    return {
      providerOrigin,
      providerBaseUrl,
      live: liveProviderMode,
      provider,
      providerKey,
      requests,
      controllerSecret,
      async close() { await close(provider); },
    };
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
  const root = persistentMode ? path.resolve(persistentRoot) : mkdtempSync(path.join(os.tmpdir(), 'zode-installed-browser-smoke-'));
  if (persistentMode) mkdirSync(root, { recursive: true, mode: 0o700 });
  const persistentLockPath = acquirePersistentSmokeLock(root);
  let fixtures;
  try {
    fixtures = await startFixtures({ persistent: persistentMode });
  } catch (error) {
    releasePersistentSmokeLock(persistentLockPath);
    throw error;
  }
  let started = false;
  let browser;
  let page;
  let browserRequests = [];
  let browserResponses = [];
  let failure;
  let browserOrigin = null;
  let ownedSessionUrl = null;
  let createdProfileId = null;
  let providerStateCleaned = false;
  let persistentOwnershipValidated = false;
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
    'DEEPSEEK_API_KEY',
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
    'ZODE_TEST_BLOCK_SECOND_ASSISTANT_EVENTS',
  ]) {
    delete channelEnv[key];
  }
  if (persistentMode) {
    channelEnv.ZODE_RELEASE_PROVIDER_ORIGINS = [fixtures.providerOrigin, approvedProviderOrigin].join(',');
  }
  let streamMarkerVisible = false;
  let durableFinalVisible = false;
  let reboundSessionCount = 0;
  let reboundBaseUrls = [];
  try {
    const currentManifest = persistentMode && existsSync(path.join(root, 'current', 'manifest.json'))
      ? JSON.parse(readFileSync(path.join(root, 'current', 'manifest.json'), 'utf8'))
      : null;
    const artifactManifest = JSON.parse(readFileSync(path.join(path.resolve(artifact), 'manifest.json'), 'utf8'));
    const persistentHasCurrent = Boolean(currentManifest?.revision);
    const persistentNeedsUpdate = persistentMode
      && persistentHasCurrent
      && currentManifest.revision !== artifactManifest?.revision;
    const installed = await command(
      process.execPath,
      persistentMode
        ? !persistentHasCurrent
          ? [localChannelEntry, 'install', '--artifact', path.resolve(artifact), '--channel-root', root]
          : persistentNeedsUpdate
            ? [localChannelEntry, 'update', '--artifact', path.resolve(artifact), '--channel-root', root]
            : [localChannelEntry, 'start', '--channel-root', root]
        : [channelEntry, 'install', '--artifact', path.resolve(artifact), '--release-root', root],
      channelEnv,
    );
    if (installed.status !== 0 || installed.payload?.ok !== true) fail('installed artifact install failed', installed);
    const startedResult = await command(
      process.execPath,
      persistentMode
        ? [localChannelEntry, 'start', '--channel-root', root]
        : [channelEntry, 'start', '--artifact', path.resolve(artifact), '--release-root', root],
      channelEnv,
    );
    if (startedResult.status !== 0 || startedResult.payload?.ok !== true) fail('installed artifact start failed', startedResult);
    started = true;
    if (persistentMode) {
      if (typeof startedResult.payload?.url !== 'string') fail('persistent start did not expose a browser URL', startedResult);
      browserOrigin = new URL(startedResult.payload.url).origin;
    } else {
      const serverUrl = startedResult.payload?.health?.probes?.server_url;
      if (typeof serverUrl !== 'string') fail('installed start did not expose live server probe', startedResult);
      fixtures.setTarget(new URL(serverUrl).origin);
      browserOrigin = new URL(fixtures.edgeOrigin).origin;
    }
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    page = await context.newPage();
    let blockSecondAssistantEvents = false;
    let blockedSessionPath = null;
    let staleSession = null;
    if (process.env.ZODE_TEST_BLOCK_SECOND_ASSISTANT_EVENTS === '1') {
      await page.route('**/v1/endpoints/**', async (route) => {
        const pathname = new URL(route.request().url()).pathname;
        if (blockSecondAssistantEvents && pathname === blockedSessionPath && staleSession) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(staleSession),
          });
        } else if (blockSecondAssistantEvents && pathname.endsWith('/events')) {
          await route.abort('failed');
        } else {
          await route.continue();
        }
      });
    }
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
    await page.goto(`${browserOrigin}/`, { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Sessions', exact: true }).waitFor();
    await page.getByText('All-in-one ready', { exact: true }).waitFor();
    await page.getByRole('link', { name: 'Providers' }).click();
    await preparePersistentProvider(page);
    persistentOwnershipValidated = true;
    await page.getByRole('button', { name: 'Configure provider' }).click();
    await page.getByLabel('Provider ID').fill(providerId);
    await page.getByLabel('Base URL').fill(fixtures.providerBaseUrl);
    await page.getByLabel('Models').fill(modelId);
    await page.getByRole('button', { name: 'Save provider' }).click();
    await page.getByText(`${providerId} is ready for an auth profile.`, { exact: true }).waitFor();
    await retainProviderOwnershipMarker(page);
    const providerCard = page.locator('article.resource-card').filter({
      has: page.getByRole('heading', { name: providerId, exact: true }),
    });
    createdProfileId = await findOrCreateProfile(page, providerCard, {
      providerId,
      profileLabel,
      providerKey: fixtures.providerKey,
    });
    await page.getByRole('link', { name: 'Sessions' }).click();
    await page.getByRole('button', { name: 'New session' }).click();
    await page.getByLabel('Provider').selectOption(providerId);
    await page.getByLabel('Model').selectOption(modelId);
    const profileSelect = page.getByLabel('Auth profile');
    await profileSelect.selectOption({ label: profileLabel });
    await page.getByRole('button', { name: 'Start session' }).click();
    await waitForDurableEventsConnection(page);
    await sendComposerPrompt(page, smokePrompt);
    await page.getByText(expectedAssistantPattern).waitFor({ timeout: 20_000 });
    streamMarkerVisible = true;
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.getByText(expectedAssistantPattern).waitFor({ timeout: 20_000 });
    durableFinalVisible = true;
    if (persistentMode) {
      ownedSessionUrl = page.url();
      const stoppedForRestart = await command(
        process.execPath,
        [localChannelEntry, 'stop', '--channel-root', root],
        channelEnv,
      );
      if (stoppedForRestart.status !== 0 || stoppedForRestart.payload?.ok !== true) {
        fail('persistent channel stop before durable reopen failed', stoppedForRestart);
      }
      const restarted = await command(
        process.execPath,
        [localChannelEntry, 'start', '--channel-root', root],
        channelEnv,
      );
      if (restarted.status !== 0 || restarted.payload?.ok !== true
        || new URL(restarted.payload.url).origin !== new URL(browserOrigin).origin) {
        fail('persistent channel restart did not preserve the installed browser origin', restarted);
      }
      await page.goto(ownedSessionUrl, { waitUntil: 'domcontentloaded' });
      await waitForDurableEventsConnection(page);
      await page.getByText(expectedAssistantPattern).waitFor({ timeout: 20_000 });
      if (liveProviderMode) {
        if (process.env.ZODE_TEST_BLOCK_SECOND_ASSISTANT_EVENTS === '1') {
          const sessionApiRequest = browserRequests.slice().reverse().find((request) => {
            const pathname = new URL(request.url).pathname;
            return request.method === 'GET'
              && /^\/v1\/endpoints\/[^/]+\/sessions\/[^/]+$/.test(pathname);
          });
          if (!sessionApiRequest) fail('test fault seam could not identify the real session API request');
          blockedSessionPath = new URL(sessionApiRequest.url).pathname;
          staleSession = await page.evaluate(async (pathname) => {
            const response = await fetch(pathname, { headers: { accept: 'application/json' } });
            if (!response.ok) throw new Error(`stale session snapshot returned ${response.status}`);
            return response.json();
          }, blockedSessionPath);
          blockSecondAssistantEvents = true;
          await page.reload({ waitUntil: 'domcontentloaded' });
          await waitForDurableEventsConnection(page);
          await page.getByText(expectedAssistantPattern).waitFor({ timeout: 20_000 });
        }
        await sendComposerPrompt(page, smokePrompt);
        await waitForAssistantMarkers(page, 2);
        await page.reload({ waitUntil: 'domcontentloaded' });
        await waitForDurableEventsConnection(page);
        await waitForAssistantMarkers(page, 2);
      }
    }
    if (persistentMode && liveProviderMode) {
      await persistentProviderCleanup(page, {
        ownedProviderId: providerId,
        ownedBaseUrl: fixtures.providerBaseUrl,
        ownershipValidated: persistentOwnershipValidated,
      });
      const rebound = await rebindPersistentSession(page, {
        ownedProviderId: providerId,
        modelId,
        profileId: createdProfileId,
        sessionPath: new URL(ownedSessionUrl).pathname,
        ownershipMarker: testOwnershipMarker,
      });
      reboundSessionCount = rebound.reboundCount;
      reboundBaseUrls = rebound.reboundBaseUrls || [];
      const reboundSession = await page.evaluate(async ({ endpointId, sessionId }) => {
        const response = await fetch(
          `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}`,
          { headers: { accept: 'application/json' } },
        );
        if (!response.ok) throw new Error(`rebound session read returned ${response.status}`);
        return response.json();
      }, rebound);
      const reboundBaseUrl = reboundSession?.model?.provider_execution_base_url;
      if (!reboundBaseUrl) {
        fail('persistent cleanup left a durable session without a provider execution URL', {
          session_id: rebound.sessionId,
        });
      }
      const reboundHost = new URL(reboundBaseUrl).hostname;
      if (['127.0.0.1', 'localhost', '::1'].includes(reboundHost)) {
        fail('persistent cleanup left a durable session pointed at the recorder origin', {
          session_id: rebound.sessionId,
          provider_execution_base_url: reboundBaseUrl,
        });
      }
      await persistentProfileCleanup(page, {
        ownedProviderId: providerId,
        profileId: createdProfileId,
      });
      providerStateCleaned = true;
    } else if (persistentMode) {
      providerStateCleaned = true;
    }
    const edge = new URL(browserOrigin);
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
    const stopped = await command(
      process.execPath,
      persistentMode
        ? [localChannelEntry, 'stop', '--channel-root', root]
        : [channelEntry, 'stop', '--release-root', root],
      channelEnv,
    );
    if (stopped.status !== 0 || stopped.payload?.ok !== true) fail('installed channel stop failed', stopped);
    started = false;
    process.stdout.write(JSON.stringify({
      status: 'PASS',
      root,
      browser_origin: browserOrigin,
      live_provider: fixtures.live,
      test_provider_id: persistentMode && liveProviderMode ? providerId : null,
      stream_marker_visible: streamMarkerVisible,
      durable_final_visible_after_reload: durableFinalVisible,
      provider_requests: fixtures.live ? null : fixtures.requests.length,
      browser_management_requests: managementRequests.length,
      rebound_session_count: reboundSessionCount,
      rebound_base_urls: reboundBaseUrls,
    }) + '\n');
  } catch (error) {
    failure = error;
    const browserState = page
      ? {
        url: page.url(),
        body_text: await page.locator('body').innerText().catch(() => ''),
        provider_profiles: await page.evaluate(async (provider) => {
          try {
            const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
              headers: { accept: 'application/json' },
            });
            return { status: response.status, body: await response.text() };
          } catch (error) {
            return { error: String(error?.message || error) };
          }
        }, providerId).catch((error) => ({ error: String(error?.message || error) })),
      }
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
    if (persistentMode && liveProviderMode && !providerStateCleaned && page) {
      try {
        await persistentProviderCleanup(page, {
          ownedProviderId: providerId,
          ownedBaseUrl: fixtures.providerBaseUrl,
          ownershipValidated: persistentOwnershipValidated,
        });
        await persistentProfileCleanup(page, {
          ownedProviderId: providerId,
          profileId: createdProfileId,
        });
      } catch { /* preserve the original failure and quarantine */ }
    }
    if (browser) await browser.close().catch(() => {});
    if (started) {
      await command(
        process.execPath,
        persistentMode
          ? [localChannelEntry, 'stop', '--channel-root', root]
          : [channelEntry, 'stop', '--release-root', root],
        channelEnv,
      ).catch(() => {});
    }
    await fixtures.close();
    releasePersistentSmokeLock(persistentLockPath);
    if (!failure) process.exitCode = 0;
  }
}

main().catch((error) => {
  preserveFailure(error, { artifact: path.resolve(artifact || '') });
  process.stderr.write(`${JSON.stringify({ status: 'HARNESS_ERROR', error: String(error.message || error) })}\n`);
  process.exitCode = 2;
});
