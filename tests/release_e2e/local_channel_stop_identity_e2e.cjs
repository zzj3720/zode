#!/usr/bin/env node
'use strict';

/*
 * Stop must not trust a PATH-provided `ps` answer or kill an unrelated process
 * group whose PID was written into private runtime state.  This is a public
 * CLI test with an explicitly owned detached process, not a broad process scan.
 */
const {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const repository = path.resolve(__dirname, '..', '..');
const entry = path.join(repository, 'release', 'local-channel.cjs');
const edgeEntry = path.join(repository, 'release', 'local-edge.cjs');
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-local-channel-stop-identity-'));
const channelRoot = path.join(workspace, 'channel');
const fakeBin = path.join(workspace, 'fake-bin');
const quarantine = path.join(repository, 'target', 'test-recordings', 'quarantine', `local-channel-stop-identity-${Date.now()}`);

function run(args, env = {}) {
  const result = spawnSync(process.execPath, [entry, ...args], {
    cwd: repository,
    env: { ...process.env, ...env },
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

function observation(pid) {
  const result = spawnSync('/bin/ps', ['-p', String(pid), '-o', 'stat=,command='], { encoding: 'utf8' });
  const line = String(result.stdout || '').trim();
  if (!line) return { alive: false, line };
  const state = line.split(/\s+/, 1)[0];
  return { alive: !state.includes('Z') && !line.endsWith('<defunct>'), line };
}

function preserveFailure(error, details) {
  try {
    mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    chmodSync(quarantine, 0o700);
    writeFileSync(path.join(quarantine, 'local-channel-stop-identity-first-failure.json'), `${JSON.stringify({
      schema: 'zode.local-channel-stop-identity-failure.v1',
      relation: 'first_post_rule_test_occurrence',
      error: String(error?.message || error),
      details,
    }, null, 2)}\n`, { mode: 0o600 });
  } catch { /* evidence is best effort and contains no credentials */ }
}

function cleanup(pid) {
  if (pid && observation(pid).alive) {
    try { process.kill(-pid, 'SIGKILL'); } catch { try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ } }
  }
  try { rmSync(workspace, { recursive: true, force: true }); } catch { /* ignored evidence remains */ }
}

function main() {
  let unrelated;
  try {
    const state = run(['status', '--channel-root', channelRoot]);
    if (state.status !== 0) throw new Error(`could not create channel state: ${JSON.stringify(state)}`);
    unrelated = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);'], {
      cwd: repository,
      detached: true,
      stdio: 'ignore',
    });
    if (!unrelated.pid) throw new Error('unrelated process did not expose a PID');
    unrelated.unref();
    const statePath = path.join(channelRoot, 'local-channel.json');
    const fakeCommand = `${process.execPath} ${edgeEntry} --state ${statePath}`;
    const runtimePath = path.join(channelRoot, 'runtime.json');
    writeFileSync(runtimePath, `${JSON.stringify({
      schema: 'zode.local-channel-runtime.v1',
      edge_pid: unrelated.pid,
      started_at_unix_ms: Date.now(),
      url: 'http://127.0.0.1:1/',
    }, null, 2)}\n`, { mode: 0o600 });
    mkdirSync(fakeBin, { recursive: true, mode: 0o700 });
    const fakePs = path.join(fakeBin, 'ps');
    writeFileSync(fakePs, `#!/bin/sh\nif [ "$1" = "-p" ]; then printf '%s\\n' '${fakeCommand.replaceAll("'", "'\\''")}'; else exec /bin/ps "$@"; fi\n`, { mode: 0o700 });
    chmodSync(fakePs, 0o700);

    const stopped = run(['stop', '--channel-root', channelRoot], { PATH: `${fakeBin}:/bin:/usr/bin` });
    const after = observation(unrelated.pid);
    if (!after.alive) {
      throw new Error(`stop trusted a PATH-spoofed process identity and killed pid=${unrelated.pid}: ${JSON.stringify({ stopped, after })}`);
    }
    process.stdout.write(JSON.stringify({ status: 'PASS', unrelated_pid_preserved: unrelated.pid }) + '\n');
  } catch (error) {
    preserveFailure(error, { channel_root: channelRoot, unrelated_pid: unrelated?.pid || null });
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error) }) + '\n');
    process.exitCode = 1;
  } finally {
    cleanup(unrelated?.pid);
  }
}

main();
