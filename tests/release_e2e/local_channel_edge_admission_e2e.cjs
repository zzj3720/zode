#!/usr/bin/env node
'use strict';

/*
 * The local edge is a test-channel Access boundary, not a general proxy.  Its
 * private state must fail closed when either the management target or the bind
 * address is changed away from loopback.  The test starts the real edge entry
 * and never sends an unauthenticated product request.
 */
const {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const repository = path.resolve(__dirname, '..', '..');
const channelEntry = path.join(repository, 'release', 'local-channel.cjs');
const edgeEntry = path.join(repository, 'release', 'local-edge.cjs');
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-local-channel-edge-admission-'));
const channelRoot = path.join(workspace, 'channel');
const quarantine = path.join(repository, 'target', 'test-recordings', 'quarantine', `local-channel-edge-admission-${Date.now()}`);

function run(args) {
  const result = spawnSync(process.execPath, [channelEntry, ...args], {
    cwd: repository,
    env: { ...process.env },
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  let payload = null;
  for (const line of String(result.stdout || '').trim().split(/\r?\n/).reverse()) {
    try { payload = JSON.parse(line); break; } catch { /* structured output is last */ }
  }
  return { status: result.status ?? 1, stdout: result.stdout || '', stderr: result.stderr || '', payload };
}

function mutateState(state, field, value) {
  const next = { ...state, [field]: value };
  writeFileSync(path.join(channelRoot, 'local-channel.json'), `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path.join(channelRoot, 'local-channel.json'), 0o600);
}

function startEdge() {
  const child = spawn(process.execPath, [edgeEntry, '--state', path.join(channelRoot, 'local-channel.json')], {
    cwd: repository,
    env: { PATH: '/usr/bin:/bin' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on('data', (value) => stdout.push(String(value)));
  child.stderr.on('data', (value) => stderr.push(String(value)));
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* already exited */ }
      resolve({ status: null, stdout: stdout.join(''), stderr: stderr.join(''), timed_out: true });
    }, 3_000);
    child.once('close', (status, signal) => {
      clearTimeout(timer);
      resolve({ status, signal, stdout: stdout.join(''), stderr: stderr.join(''), timed_out: false });
    });
  });
}

function preserveFailure(error, details) {
  try {
    require('node:fs').mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    chmodSync(quarantine, 0o700);
    writeFileSync(path.join(quarantine, 'local-channel-edge-admission-first-failure.json'), `${JSON.stringify({
      schema: 'zode.local-channel-edge-admission-failure.v1',
      relation: 'first_post_rule_test_occurrence',
      error: String(error?.message || error),
      details,
    }, null, 2)}\n`, { mode: 0o600 });
  } catch { /* evidence is best effort and contains no credentials */ }
}

async function main() {
  try {
    const stateResult = run(['status', '--channel-root', channelRoot]);
    if (stateResult.status !== 0 || !existsSync(path.join(channelRoot, 'local-channel.json'))) {
      throw new Error(`could not create local-channel state: ${JSON.stringify(stateResult)}`);
    }
    const state = JSON.parse(readFileSync(path.join(channelRoot, 'local-channel.json'), 'utf8'));
    const observations = [];
    for (const [field, value] of [
      ['server_origin', 'http://192.0.2.1:43127/'],
      ['edge_host', '0.0.0.0'],
    ]) {
      mutateState(state, field, value);
      const result = await startEdge();
      observations.push({ field, result: { status: result.status, signal: result.signal, timed_out: result.timed_out, stderr: result.stderr } });
      if (result.timed_out || result.status === 0 || !/loopback|invalid local-channel|origin/i.test(result.stderr)) {
        throw new Error(`tampered ${field} state was not rejected: ${JSON.stringify(result)}`);
      }
      mutateState(state, field, state[field]);
    }
    process.stdout.write(JSON.stringify({ status: 'PASS', observations }) + '\n');
  } catch (error) {
    preserveFailure(error, { channel_root: channelRoot });
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error) }) + '\n');
    process.exitCode = 1;
  } finally {
    try { rmSync(workspace, { recursive: true, force: true }); } catch { /* ignored evidence remains */ }
  }
}

main().catch((error) => {
  process.stderr.write(JSON.stringify({ status: 'HARNESS_ERROR', error: String(error.message || error) }) + '\n');
  process.exitCode = 2;
});
