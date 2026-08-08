#!/usr/bin/env node
'use strict';

/*
 * A persistent channel may be started by the user's Node and inspected by a
 * Vite+ task using its bundled Node.  The real edge executable must remain
 * bound to the path recorded when it was started, rather than to whichever
 * Node happens to inspect the channel later.
 */
const {
  chmodSync,
  existsSync,
  mkdirSync,
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
const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-local-channel-node-runtime-'));
const channelRoot = path.join(workspace, 'channel');
const quarantine = path.join(repository, 'target', 'test-recordings', 'quarantine', `local-channel-node-runtime-${Date.now()}`);

function run(executable, args) {
  return spawnSync(executable, args, {
    cwd: repository,
    env: { ...process.env },
    encoding: 'utf8',
    timeout: 60_000,
    maxBuffer: 8 * 1024 * 1024,
  });
}

function lastJson(stdout) {
  for (const line of String(stdout || '').trim().split(/\r?\n/).reverse()) {
    try { return JSON.parse(line); } catch { /* readiness precedes structured output */ }
  }
  return null;
}

function preserveFailure(error, details) {
  try {
    mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    chmodSync(quarantine, 0o700);
    writeFileSync(path.join(quarantine, 'local-channel-node-runtime-first-failure.json'), `${JSON.stringify({
      schema: 'zode.local-channel-node-runtime-failure.v1',
      relation: 'first_post_rule_test_occurrence',
      error: String(error?.message || error),
      details,
    }, null, 2)}\n`, { mode: 0o600 });
  } catch { /* evidence has no credentials and is best effort */ }
}

function cleanup() {
  try { run(process.execPath, [entry, 'stop', '--channel-root', channelRoot]); } catch { /* preserve first evidence */ }
  try { rmSync(workspace, { recursive: true, force: true }); } catch { /* ignored evidence remains */ }
}

function main() {
  if (!artifact || !existsSync(artifact)) {
    process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'missing_artifact' }) + '\n');
    process.exitCode = 78;
    return;
  }
  try {
    const alternate = run('vp', ['exec', 'node', '-p', 'process.execPath']);
    const alternateNode = String(alternate.stdout || '').trim().split(/\r?\n/).filter(Boolean).at(-1);
    if (alternate.status !== 0 || !path.isAbsolute(alternateNode) || alternateNode === process.execPath) {
      process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'alternate_node_runtime_unavailable' }) + '\n');
      process.exitCode = 78;
      return;
    }
    const installed = run(process.execPath, [entry, 'install', '--artifact', path.resolve(artifact), '--channel-root', channelRoot]);
    if (installed.status !== 0 || lastJson(installed.stdout)?.ok !== true) throw new Error(`install failed: ${installed.stdout}${installed.stderr}`);
    const started = run(process.execPath, [entry, 'start', '--channel-root', channelRoot]);
    if (started.status !== 0 || lastJson(started.stdout)?.ok !== true) throw new Error(`start failed: ${started.stdout}${started.stderr}`);
    const inspected = run(alternateNode, [entry, 'status', '--channel-root', channelRoot]);
    const payload = lastJson(inspected.stdout);
    if (inspected.status !== 0 || payload?.ok !== true || payload?.running !== true || payload?.health?.health?.status !== 'ok') {
      throw new Error(`alternate runtime rejected a live channel: ${inspected.stdout}${inspected.stderr}`);
    }
    const stopped = run(alternateNode, [entry, 'stop', '--channel-root', channelRoot]);
    const stoppedPayload = lastJson(stopped.stdout);
    if (stopped.status !== 0 || stoppedPayload?.ok !== true || stoppedPayload?.edge?.stopped !== true || existsSync(path.join(channelRoot, 'runtime.json'))) {
      throw new Error(`alternate runtime could not stop a live channel: ${stopped.stdout}${stopped.stderr}`);
    }
    process.stdout.write(JSON.stringify({ status: 'PASS', operations: ['status', 'stop'], alternate_runtime: alternateNode, running: true }) + '\n');
  } catch (error) {
    const runtimePath = path.join(channelRoot, 'runtime.json');
    preserveFailure(error, {
      channel_root: channelRoot,
      runtime: (() => { try { return JSON.parse(readFileSync(runtimePath, 'utf8')); } catch { return null; } })(),
    });
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error) }) + '\n');
    process.exitCode = 1;
  } finally {
    cleanup();
  }
}

main();
