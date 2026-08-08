#!/usr/bin/env node
'use strict';

/*
 * Post-live-smoke persistent-channel guard.  It exercises the installed
 * browser path after the test-owned provider recorder has been stopped and
 * proves that no recorder origin remains in durable provider descriptors and
 * no session is left in an unbounded Working activation.
 */
const { randomUUID } = require('node:crypto');
const { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const repositoryRoot = path.resolve(__dirname, '..', '..');
const { chromium } = require(path.join(
  repositoryRoot,
  'web',
  'e2e',
  'node_modules',
  '@playwright',
  'test',
));
const channelRoot = path.resolve(
  process.env.ZODE_RELEASE_LOCAL_CHANNEL_ROOT || path.join(os.homedir(), '.zode', 'test-channel'),
);
let configuredChannelUrl = process.env.ZODE_RELEASE_CHANNEL_URL;
if (!configuredChannelUrl) {
  try {
    const config = JSON.parse(readFileSync(path.join(channelRoot, 'local-channel.json'), 'utf8'));
    configuredChannelUrl = 'http://' + config.edge_host + ':' + config.edge_port + '/';
  } catch {
    configuredChannelUrl = 'http://127.0.0.1:60903/';
  }
}
const channelUrl = new URL(configuredChannelUrl);
const runId = `${Date.now()}-${randomUUID()}`;
const quarantine = path.join(
  repositoryRoot,
  'target',
  'test-recordings',
  'quarantine',
  `installed-channel-persistent-state-${runId}`,
);

function loopback(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:'
      && ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
  } catch {
    return false;
  }
}

function normalizeUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    parsed.hash = '';
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return '';
  }
}

function preserveFailure(error, details) {
  mkdirSync(quarantine, { recursive: true, mode: 0o700 });
  chmodSync(quarantine, 0o700);
  writeFileSync(
    path.join(quarantine, 'installed-channel-persistent-state-first-failure.json'),
    `${JSON.stringify({
      schema: 'zode.installed-channel-persistent-state-failure.v1',
      recording_id: runId,
      relation: 'first_post_rule_test_occurrence',
      channel_root: channelRoot,
      channel_url: channelUrl.origin,
      details,
      error: String(error?.message || error),
    }, null, 2)}\n`,
    { mode: 0o600, flag: 'wx' },
  );
}

async function main() {
  let browser;
  let details = {};
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(channelUrl.origin, { waitUntil: 'domcontentloaded' });
    await page.getByRole('link', { name: 'Providers', exact: true }).click();
    await page.getByRole('heading', { name: 'Providers', exact: true }).waitFor();
    const providers = await page.locator('article.resource-card').evaluateAll((cards) => cards.map((card) => ({
      provider: card.querySelector('h2')?.textContent?.trim() || '',
      base_url: Array.from(card.querySelectorAll('p')).map((item) => item.textContent?.trim() || '')
        .find((value) => /^https?:\/\//.test(value)) || '',
    })));
    const ownedProviderIds = new Set(
      String(process.env.ZODE_RELEASE_TEST_PROVIDER_IDS || '')
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean),
    );
    const ownedRecorderBases = new Set(
      String(process.env.ZODE_RELEASE_TEST_PROVIDER_BASE_URLS || '')
        .split(',')
        .map((value) => normalizeUrl(value))
        .filter(Boolean),
    );
    const staleRecorderProviders = providers.filter((item) =>
      ownedProviderIds.has(item.provider)
      && (ownedRecorderBases.size === 0
        ? loopback(item.base_url)
        : ownedRecorderBases.has(normalizeUrl(item.base_url))));
    details.providers = providers;
    details.owned_provider_ids = [...ownedProviderIds];
    const failures = [];
    if (staleRecorderProviders.length > 0) {
      failures.push('persistent provider descriptor still points to a test recorder origin');
    }
    const durableSessions = await page.evaluate(async () => {
      const response = await fetch('/v1/endpoints', { headers: { accept: 'application/json' } });
      if (!response.ok) throw new Error('endpoint list returned ' + response.status);
      const endpoints = (await response.json()).items || [];
      const sessions = [];
      for (const endpoint of endpoints) {
        const sessionResponse = await fetch(
          '/v1/endpoints/' + encodeURIComponent(endpoint.endpoint_id) + '/sessions',
          { headers: { accept: 'application/json' } },
        );
        if (!sessionResponse.ok) throw new Error('session list returned ' + sessionResponse.status);
        for (const session of (await sessionResponse.json()).items || []) {
          sessions.push({ endpoint_id: endpoint.endpoint_id, ...session });
        }
      }
      return sessions;
    });
    const staleRecorderSessions = durableSessions.filter((session) => {
      const baseUrl = session.model?.provider_execution_base_url;
      if (!ownedProviderIds.has(session.model?.provider)) return false;
      return ownedRecorderBases.size > 0
        ? ownedRecorderBases.has(normalizeUrl(baseUrl))
        : loopback(baseUrl);
    });
    details.durable_sessions = durableSessions.map((session) => ({
      endpoint_id: session.endpoint_id,
      session_id: session.session_id,
      provider_execution_base_url: session.model?.provider_execution_base_url || null,
    }));
    if (staleRecorderSessions.length > 0) {
      failures.push('persistent session selection still points to a test recorder origin');
    }

    await page.getByRole('link', { name: 'Sessions', exact: true }).click();
    await page.getByRole('heading', { name: 'Sessions', exact: true }).waitFor();
    const sessionUrls = await page.locator('a[href*="/sessions/"]').evaluateAll((links) =>
      links.map((link) => link.href));
    const stuckSessions = [];
    for (const sessionUrl of sessionUrls) {
      await page.goto(sessionUrl, { waitUntil: 'domcontentloaded' });
      const deadline = Date.now() + 20_000;
      let assistantCount = 0;
      let body = '';
      while (Date.now() < deadline) {
        assistantCount = await page.locator('article.message-assistant').count();
        body = await page.locator('body').innerText();
        if (assistantCount > 0 || !/Working\s+Model activation in progress/.test(body)) break;
        await page.waitForTimeout(250);
      }
      if (/Working\s+Model activation in progress/.test(body) && assistantCount === 0) {
        stuckSessions.push({ url: sessionUrl, body: body.slice(-2_000) });
      }
    }
    details.session_urls = sessionUrls;
    details.stuck_sessions = stuckSessions;
    if (stuckSessions.length > 0) {
      failures.push('persistent session remained Working without a durable assistant final');
    }
    if (failures.length > 0) {
      throw new Error(failures.join('; '));
    }
    process.stdout.write(JSON.stringify({
      status: 'PASS',
      operation: 'installed_channel_persistent_state',
      channel_root: channelRoot,
      channel_url: channelUrl.origin,
      provider_count: providers.length,
      session_count: sessionUrls.length,
    }) + '\n');
  } catch (error) {
    preserveFailure(error, details);
    process.stderr.write(`${JSON.stringify({
      status: 'RED',
      operation: 'installed_channel_persistent_state',
      error: String(error?.message || error),
      details,
    })}\n`);
    process.exitCode = 1;
  } finally {
    await browser?.close().catch(() => {});
  }
}

main().catch((error) => {
  preserveFailure(error, {});
  process.stderr.write(`${JSON.stringify({ status: 'HARNESS_ERROR', error: String(error) })}\n`);
  process.exitCode = 2;
});
