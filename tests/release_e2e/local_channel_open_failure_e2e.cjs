#!/usr/bin/env node
'use strict';

/*
 * Public failure/recovery anchor for the persistent `open` entry.  A fresh
 * channel must not leave its Access edge behind when no installed release can
 * pass health.  The test observes the real detached process and runtime file;
 * it does not call local-channel internals.
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
const { spawnSync } = require('node:child_process');

const repository = path.resolve(__dirname, '..', '..');
const entry = path.join(repository, 'release', 'local-channel.cjs');
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-local-channel-open-failure-'));
const channelRoot = path.join(workspace, 'channel');
const quarantine = path.join(repository, 'target', 'test-recordings', 'quarantine', `local-channel-open-failure-${Date.now()}`);

function run(args) {
  const result = spawnSync(process.execPath, [entry, ...args], {
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

function readRuntime() {
  const value = path.join(channelRoot, 'runtime.json');
  if (!existsSync(value)) return null;
  return JSON.parse(readFileSync(value, 'utf8'));
}

function processCommand(pid) {
  const result = spawnSync('/bin/ps', ['-p', String(pid), '-o', 'command='], { encoding: 'utf8' });
  return String(result.stdout || '').trim();
}

function processAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error?.code === 'EPERM'; }
}

function preserveFailure(error, details) {
  try {
    require('node:fs').mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    chmodSync(quarantine, 0o700);
    const target = path.join(quarantine, 'local-channel-open-first-failure.json');
    if (!existsSync(target)) {
      writeFileSync(target, `${JSON.stringify({
        schema: 'zode.local-channel-open-failure.v1',
        relation: 'first_post_rule_test_occurrence',
        error: String(error?.message || error),
        details,
      }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    }
  } catch { /* evidence is best effort and never contains credentials */ }
}

function cleanup() {
  try { run(['stop', '--channel-root', channelRoot]); } catch { /* preserve evidence */ }
  try { rmSync(workspace, { recursive: true, force: true }); } catch { /* ignored evidence remains */ }
}

function main() {
  try {
    const opened = run(['open', '--channel-root', channelRoot]);
    if (opened.status === 0 || opened.payload?.error?.code !== 'local_channel_not_running') {
      throw new Error(`fresh open returned an unexpected result: ${JSON.stringify(opened)}`);
    }
    const runtime = readRuntime();
    if (runtime) {
      const command = processCommand(runtime.edge_pid);
      if (processAlive(runtime.edge_pid) && command.includes('release/local-edge.cjs')) {
        throw new Error(`failed open left a live Access edge: pid=${runtime.edge_pid}`);
      }
      throw new Error(`failed open left runtime state: pid=${runtime.edge_pid} command=${command}`);
    }
    process.stdout.write(JSON.stringify({ status: 'PASS', operation: 'open', runtime_removed: true }) + '\n');
  } catch (error) {
    const runtime = readRuntime();
    preserveFailure(error, {
      channel_root: channelRoot,
      runtime,
      edge_command: runtime ? processCommand(runtime.edge_pid) : null,
    });
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error) }) + '\n');
    process.exitCode = 1;
  } finally {
    cleanup();
  }
}

main();
