#!/usr/bin/env node
'use strict';

// Public red anchor for the installed-channel live-provider seam.  The
// existing smoke must consume the test-owned provider base URL instead of
// silently falling back to its deterministic in-process fixture.
const http = require('node:http');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');

const repositoryRoot = require('node:path').resolve(__dirname, '..', '..');
const smoke = require('node:path').join(__dirname, 'installed_channel_browser_smoke_e2e.cjs');
const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;

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
  return new Promise((resolve) => server.close(() => resolve()));
}

function runSmoke(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [smoke], {
      cwd: repositoryRoot,
      env,
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

async function main() {
  if (!artifact) {
    process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'missing_artifact' }) + '\n');
    process.exitCode = 78;
    return;
  }
  let requests = 0;
  const provider = http.createServer((request, response) => {
    requests += 1;
    request.resume();
    request.on('end', () => {
      response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      response.write('data: {"choices":[{"delta":{"content":"ZODE_E2_LIVE_OK"},"finish_reason":null}]}\n\n');
      response.end('data: [DONE]\n\n');
    });
  });
  const origin = await listen(provider);
  try {
    const env = {
      ...process.env,
      ZODE_RELEASE_LIVE_PROVIDER_BASE_URL: origin,
      ZODE_RELEASE_LIVE_PROVIDER_API_KEY: `contract-${randomUUID()}`,
    };
    const result = await runSmoke(env);
    if (result.status !== 0) {
      throw new Error(`installed browser smoke failed before live-provider assertion: ${result.stderr || result.stdout}`);
    }
    if (requests !== 1) {
      throw new Error(`installed browser smoke ignored live provider base URL (requests=${requests})`);
    }
    process.stdout.write(JSON.stringify({ status: 'PASS', requests }) + '\n');
  } catch (error) {
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error), requests }) + '\n');
    process.exitCode = 1;
  } finally {
    await close(provider);
  }
}

main().catch((error) => {
  process.stderr.write(JSON.stringify({ status: 'HARNESS_ERROR', error: String(error.message || error) }) + '\n');
  process.exitCode = 2;
});
