#!/usr/bin/env node
'use strict';

/* Real-process recovery E2E for a driver crash before role persistence. */
const {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
} = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
if (!artifact) {
  process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'ZODE_RELEASE_CHANNEL_ARTIFACT is required' }) + '\n');
  process.exitCode = 78;
} else {
  const driver = join(artifact, 'release-driver');
  const workspace = mkdtempSync(join(tmpdir(), 'zode-channel-crash-recovery-e2e-'));
  const root = join(workspace, 'channel-root');
  mkdirSync(root, { mode: 0o700 });
  const child = spawn(process.execPath, [driver, 'bootstrap', '--release-root', root, '--artifact', artifact, '--json'], {
    cwd: artifact,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env,
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += String(chunk); });
  child.stderr.on('data', (chunk) => { stderr += String(chunk); });
  const exited = new Promise((resolve) => child.once('close', (status, signal) => resolve({ status, signal })));

  const exactProcess = (executable, config) => {
    const expected = `${executable} --config ${config}`;
    const result = spawnSync('ps', ['-axo', 'pid=,command='], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
    if (result.status !== 0) return [];
    return String(result.stdout ?? '').split(/\r?\n/).flatMap((line) => {
      const match = line.trim().match(/^(\d+)\s+(.+)$/);
      return match && match[2] === expected ? [Number(match[1])] : [];
    });
  };

  const findEmptyInstance = () => {
    const instances = join(root, 'instances');
    if (!existsSync(instances)) return null;
    for (const name of readdirSync(instances)) {
      const directory = join(instances, name);
      const statePath = join(directory, 'state.json');
      if (!existsSync(statePath)) continue;
      let state;
      try { state = JSON.parse(readFileSync(statePath, 'utf8')); } catch { continue; }
      if (!Array.isArray(state.roles) || state.roles.length !== 0) continue;
      const executable = join(state.artifact.installPath, 'zode-server');
      const config = join(state.directory, 'server.json');
      const pids = exactProcess(executable, config);
      if (pids.length === 1) return { state, pid: pids[0], executable, config };
    }
    return null;
  };

  const waitForBarrier = async () => {
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
      const found = findEmptyInstance();
      if (found) return found;
      if (child.exitCode !== null) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    return null;
  };

  const parsePayload = (value) => {
    const lines = String(value ?? '').trim().split(/\r?\n/).filter(Boolean);
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      try { return JSON.parse(lines[index]); } catch {}
    }
    return null;
  };

  const runTeardown = () => spawnSync(process.execPath, [driver, 'teardown', '--release-root', root, '--json'], {
    cwd: artifact,
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
    env: process.env,
  });

  (async () => {
    const found = await waitForBarrier();
    if (found && child.exitCode === null) child.kill('SIGKILL');
    else if (child.exitCode === null) child.kill('SIGKILL');
    const childExit = await exited;
    const first = runTeardown();
    const firstPayload = parsePayload(first.stdout);
    const orphanAfterFirst = found ? exactProcess(found.executable, found.config).includes(found.pid) : false;
    const second = runTeardown();
    const secondPayload = parsePayload(second.stdout);
    if (found && orphanAfterFirst) {
      try { process.kill(found.pid, 'SIGKILL'); } catch {}
    }
    const report = firstPayload?.stop_reports?.find((entry) => entry.instance_id === found?.state?.instance_id);
    const passed = Boolean(found)
      && childExit.signal === 'SIGKILL'
      && first.status === 0
      && !orphanAfterFirst
      && report?.reaped_pids?.includes(found.pid)
      && second.status === 0
      && !secondPayload?.error;
    process.stdout.write(JSON.stringify({
      status: passed ? 'PASS' : 'RED',
      root,
      instance_id: found?.state?.instance_id ?? null,
      observed_pid: found?.pid ?? null,
      child_exit: childExit,
      first_payload: firstPayload,
      second_payload: secondPayload,
      orphan_after_first: orphanAfterFirst,
      stdout,
      stderr,
      first_stderr: first.stderr,
      second_stderr: second.stderr,
    }) + '\n');
    process.exitCode = passed ? 0 : 1;
  })().catch((error) => {
    if (child.exitCode === null) child.kill('SIGKILL');
    process.stdout.write(JSON.stringify({ status: 'RED', error: String(error), root, stdout, stderr }) + '\n');
    process.exitCode = 1;
  });
}
