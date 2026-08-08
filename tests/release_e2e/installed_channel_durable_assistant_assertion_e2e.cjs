#!/usr/bin/env node
'use strict';

/*
 * Adversarial browser anchor for the second durable assistant reply.  The
 * test-owned browser route drops the SSE reconnect after the first reply while
 * the real Endpoint still receives a successful second provider exchange. The
 * smoke must reject a false green caused by counting the prompt text itself.
 */
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const repository = path.resolve(__dirname, '..', '..');
const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
const smoke = path.join(repository, 'tests', 'release_e2e', 'installed_channel_browser_smoke_e2e.cjs');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'zode-durable-assistant-red-'));
const channelRoot = path.join(workspace, 'channel');
const quarantine = path.join(
  repository,
  'target',
  'test-recordings',
  'quarantine',
  `installed-channel-durable-assistant-${Date.now()}`,
);

function preserveFailure(error, details) {
  try {
    fs.mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    fs.chmodSync(quarantine, 0o700);
    fs.writeFileSync(path.join(quarantine, 'installed-channel-durable-assistant-first-failure.json'), `${JSON.stringify({
      schema: 'zode.installed-channel-durable-assistant-failure.v1',
      relation: 'first_post_rule_test_occurrence',
      error: String(error?.message || error),
      details,
    }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  } catch { /* retain the process/browser failure even if quarantine is unavailable */ }
}

function close(server) {
  return new Promise((resolve) => server?.close(() => resolve()));
}

async function main() {
  if (!artifact) {
    process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'missing_artifact' }) + '\n');
    process.exitCode = 78;
    return;
  }
  let provider;
  let requests = 0;
  try {
    provider = http.createServer((request, response) => {
      request.resume();
      request.once('end', () => {
        requests += 1;
        response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
        response.write('data: {"choices":[{"delta":{"content":"ZODE_E2_LIVE_OK"},"finish_reason":null}]}\n\n');
        response.write('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n');
        response.end('data: [DONE]\n\n');
      });
    });
    await new Promise((resolve, reject) => {
      provider.once('error', reject);
      provider.listen(0, '127.0.0.1', resolve);
    });
    const origin = `http://127.0.0.1:${provider.address().port}`;
    const result = await new Promise((resolve) => {
      const child = spawn(process.execPath, [smoke], {
        cwd: repository,
        env: {
          ...process.env,
          ZODE_RELEASE_CHANNEL_ARTIFACT: path.resolve(artifact),
          ZODE_RELEASE_LOCAL_CHANNEL_ROOT: channelRoot,
          ZODE_RELEASE_LIVE_PROVIDER_BASE_URL: `${origin}/zen/go/v1`,
          ZODE_RELEASE_LIVE_PROVIDER_API_KEY: 'durable-assistant-red-key',
          ZODE_TEST_BLOCK_SECOND_ASSISTANT_EVENTS: '1',
        },
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
    // The anchor is green only when the smoke rejects the intentional lost
    // second UI render after the provider has completed both exchanges.
    const expectedFailure = result.stderr.includes('did not render 2 durable assistant markers');
    if ((result.status ?? 1) === 0 || requests !== 2 || !expectedFailure) {
      const error = new Error('installed browser smoke accepted a missing second durable assistant reply');
      error.details = {
        smoke_status: result.status ?? 1,
        provider_requests: requests,
        expected_failure_observed: expectedFailure,
        stdout: result.stdout?.slice(-4_096),
        stderr: result.stderr?.slice(-4_096),
      };
      throw error;
    }
    process.stdout.write(JSON.stringify({
      status: 'PASS',
      operation: 'installed_channel_durable_assistant_assertion',
      smoke_status: result.status ?? 1,
      provider_requests: requests,
    }) + '\n');
  } catch (error) {
    preserveFailure(error, { channel_root: channelRoot, provider_requests: requests, artifact: path.resolve(artifact) });
    process.stderr.write(`${JSON.stringify({
      status: 'RED',
      operation: 'installed_channel_durable_assistant_assertion',
      error: String(error?.message || error),
      details: error?.details || {},
    })}\n`);
    process.exitCode = 1;
  } finally {
    await close(provider);
    try {
      const stat = fs.lstatSync(workspace);
      if (stat.isDirectory()) {
        const makeWritable = (value) => {
          const item = fs.lstatSync(value);
          if (item.isDirectory()) {
            for (const name of fs.readdirSync(value)) makeWritable(path.join(value, name));
            fs.chmodSync(value, 0o700);
          } else if (item.isFile()) fs.chmodSync(value, 0o600);
        };
        makeWritable(workspace);
        fs.rmSync(workspace, { recursive: true, force: true });
      }
    } catch { /* evidence remains in quarantine */ }
  }
}

main().catch((error) => {
  preserveFailure(error, {});
  process.stderr.write(`${JSON.stringify({ status: 'HARNESS_ERROR', error: String(error) })}\n`);
  process.exitCode = 2;
});
