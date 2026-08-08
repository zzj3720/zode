#!/usr/bin/env node
'use strict';

/*
 * A failed update on a fresh channel must not leave the edge that was started
 * only to run the update health path.  This is a real CLI/process regression
 * anchor; it does not import the channel implementation.
 */
const { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repository = path.resolve(__dirname, '..', '..');
const entry = path.join(repository, 'release', 'local-channel.cjs');
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-local-channel-update-failure-'));
const channelRoot = path.join(workspace, 'channel');
const quarantine = path.join(repository, 'target', 'test-recordings', 'quarantine', `local-channel-update-failure-${Date.now()}`);

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

function runtime() {
  const value = path.join(channelRoot, 'runtime.json');
  return existsSync(value) ? JSON.parse(readFileSync(value, 'utf8')) : null;
}

function command(pid) {
  const result = spawnSync('/bin/ps', ['-p', String(pid), '-o', 'command='], { encoding: 'utf8' });
  return String(result.stdout || '').trim();
}

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error?.code === 'EPERM'; }
}

function preserveFailure(error, details) {
  try {
    require('node:fs').mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    chmodSync(quarantine, 0o700);
    writeFileSync(path.join(quarantine, 'local-channel-update-first-failure.json'), `${JSON.stringify({
      schema: 'zode.local-channel-update-failure.v1',
      relation: 'first_post_rule_test_occurrence',
      error: String(error?.message || error),
      details,
    }, null, 2)}\n`, { mode: 0o600 });
  } catch { /* evidence is best effort and contains no credentials */ }
}

function cleanup() {
  try { run(['stop', '--channel-root', channelRoot]); } catch { /* preserve evidence */ }
  try { rmSync(workspace, { recursive: true, force: true }); } catch { /* ignored evidence remains */ }
}

function main() {
  try {
    const missingArtifact = path.join(workspace, 'missing-artifact');
    const updated = run(['update', '--artifact', missingArtifact, '--channel-root', channelRoot]);
    if (updated.status === 0) throw new Error(`fresh invalid update unexpectedly succeeded: ${JSON.stringify(updated)}`);
    const state = runtime();
    if (state && alive(state.edge_pid) && command(state.edge_pid).includes('release/local-edge.cjs')) {
      throw new Error(`failed update left a live Access edge: pid=${state.edge_pid}`);
    }
    if (state) throw new Error(`failed update left runtime state: pid=${state.edge_pid}`);
    process.stdout.write(JSON.stringify({ status: 'PASS', operation: 'update', runtime_removed: true }) + '\n');
  } catch (error) {
    const state = runtime();
    preserveFailure(error, { channel_root: channelRoot, runtime: state, edge_command: state ? command(state.edge_pid) : null });
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error) }) + '\n');
    process.exitCode = 1;
  } finally {
    cleanup();
  }
}

main();
