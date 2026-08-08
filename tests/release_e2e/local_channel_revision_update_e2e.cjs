#!/usr/bin/env node
'use strict';

/*
 * The persistent update path must replace an older installed revision only
 * after the new candidate is ready, then leave one healthy current instance.
 * This is deliberately a real channel/driver/process scenario: no driver
 * internals or mock HTTP routes are imported.
 */
const {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repository = path.resolve(__dirname, '..', '..');
const entry = path.join(repository, 'release', 'local-channel.cjs');
const baseArtifact = process.env.ZODE_RELEASE_CHANNEL_BASE_ARTIFACT;
const candidateArtifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
const workspace = mkdtempSync(path.join(os.tmpdir(), 'zode-local-channel-revision-update-'));
const channelRoot = path.join(workspace, 'channel');
const quarantine = path.join(repository, 'target', 'test-recordings', 'quarantine', `local-channel-revision-update-${Date.now()}`);

function run(args) {
  return spawnSync(process.execPath, [entry, ...args], {
    cwd: repository,
    env: { ...process.env },
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
  });
}

function json(stdout) {
  for (const line of String(stdout || '').trim().split(/\r?\n/).reverse()) {
    try { return JSON.parse(line); } catch { /* readiness precedes the result */ }
  }
  return null;
}

function preserveFailure(error, operations) {
  mkdirSync(quarantine, { recursive: true, mode: 0o700 });
  chmodSync(quarantine, 0o700);
  writeFileSync(path.join(quarantine, 'local-channel-revision-update-first-failure.json'), `${JSON.stringify({
    schema: 'zode.local-channel-revision-update-failure.v1',
    relation: 'first_post_rule_test_occurrence',
    channel_root: channelRoot,
    base_artifact: baseArtifact,
    candidate_artifact: candidateArtifact,
    operations,
    error: String(error?.message || error),
  }, null, 2)}\n`, { mode: 0o600 });
}

function reapKnownProcesses() {
  const instances = path.join(channelRoot, 'instances');
  if (!existsSync(instances)) return;
  for (const name of readdirSync(instances)) {
    const statePath = path.join(instances, name, 'state.json');
    try {
      const state = JSON.parse(readFileSync(statePath, 'utf8'));
      for (const role of state.roles || []) {
        if (Number.isSafeInteger(role.process_group_id) && role.process_group_id > 0) {
          try { process.kill(-role.process_group_id, 'SIGKILL'); } catch { /* already gone */ }
        } else if (Number.isSafeInteger(role.pid) && role.pid > 0) {
          try { process.kill(role.pid, 'SIGKILL'); } catch { /* already gone */ }
        }
      }
    } catch { /* malformed/empty state is retained for incident evidence */ }
  }
}

function cleanup() {
  const stopped = run(['stop', '--channel-root', channelRoot]);
  if (stopped.status !== 0) {
    reapKnownProcesses();
    try {
      const runtime = JSON.parse(readFileSync(path.join(channelRoot, 'runtime.json'), 'utf8'));
      if (Number.isSafeInteger(runtime.edge_pid) && runtime.edge_pid > 0) {
        try { process.kill(-runtime.edge_pid, 'SIGKILL'); } catch { /* already gone */ }
      }
    } catch { /* no runtime or malformed runtime */ }
  }
  try { rmSync(workspace, { recursive: true, force: true }); } catch { /* ignored evidence remains */ }
}

function main() {
  if (!baseArtifact || !candidateArtifact || !existsSync(baseArtifact) || !existsSync(candidateArtifact)) {
    try { rmSync(workspace, { recursive: true, force: true }); } catch { /* no release process exists in blocked mode */ }
    process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'missing_base_or_candidate_artifact' }) + '\n');
    process.exitCode = 78;
    return;
  }
  const operations = [];
  try {
    const installed = run(['install', '--artifact', path.resolve(baseArtifact), '--channel-root', channelRoot]);
    operations.push({ operation: 'install', status: installed.status, stdout: installed.stdout, stderr: installed.stderr });
    if (installed.status !== 0 || json(installed.stdout)?.ok !== true) throw new Error(`base install failed: ${installed.stdout}${installed.stderr}`);
    const started = run(['start', '--channel-root', channelRoot]);
    operations.push({ operation: 'start', status: started.status, stdout: started.stdout, stderr: started.stderr });
    if (started.status !== 0 || json(started.stdout)?.ok !== true) throw new Error(`base start failed: ${started.stdout}${started.stderr}`);
    const updated = run(['update', '--artifact', path.resolve(candidateArtifact), '--channel-root', channelRoot]);
    operations.push({ operation: 'update', status: updated.status, stdout: updated.stdout, stderr: updated.stderr });
    const updatedPayload = json(updated.stdout);
    if (updated.status !== 0 || updatedPayload?.ok !== true) throw new Error(`revision update failed: ${updated.stdout}${updated.stderr}`);
    if (updatedPayload.health?.status !== 'ok') throw new Error(`updated current is not healthy: ${updated.stdout}`);
    const currentManifest = JSON.parse(readFileSync(path.join(channelRoot, 'current', 'manifest.json'), 'utf8'));
    const candidateManifest = JSON.parse(readFileSync(path.join(path.resolve(candidateArtifact), 'manifest.json'), 'utf8'));
    if (currentManifest.revision !== candidateManifest.revision) {
      throw new Error(`current revision did not advance to candidate: ${currentManifest.revision}`);
    }
    const liveInstances = readdirSync(path.join(channelRoot, 'instances'))
      .filter((name) => existsSync(path.join(channelRoot, 'instances', name, 'state.json')));
    if (liveInstances.length !== 1) throw new Error(`update left ${liveInstances.length} stateful instances instead of one current`);
    const previousBeforeRestart = JSON.parse(readFileSync(path.join(channelRoot, 'previous', 'manifest.json'), 'utf8'));
    const stopped = run(['stop', '--channel-root', channelRoot]);
    operations.push({ operation: 'stop_before_restart', status: stopped.status, stdout: stopped.stdout, stderr: stopped.stderr });
    if (stopped.status !== 0 || json(stopped.stdout)?.ok !== true) throw new Error(`stop before restart failed: ${stopped.stdout}${stopped.stderr}`);
    const restarted = run(['start', '--channel-root', channelRoot]);
    operations.push({ operation: 'start_after_restart', status: restarted.status, stdout: restarted.stdout, stderr: restarted.stderr });
    if (restarted.status !== 0 || json(restarted.stdout)?.ok !== true) throw new Error(`start after restart failed: ${restarted.stdout}${restarted.stderr}`);
    const currentAfterRestart = JSON.parse(readFileSync(path.join(channelRoot, 'current', 'manifest.json'), 'utf8'));
    const previousAfterRestart = JSON.parse(readFileSync(path.join(channelRoot, 'previous', 'manifest.json'), 'utf8'));
    if (currentAfterRestart.revision !== currentManifest.revision) {
      throw new Error(`restart changed current revision: ${currentAfterRestart.revision}`);
    }
    if (previousAfterRestart.revision !== previousBeforeRestart.revision) {
      throw new Error(`restart changed previous revision: ${previousAfterRestart.revision} (expected ${previousBeforeRestart.revision})`);
    }
    process.stdout.write(JSON.stringify({ status: 'PASS', operation: 'update_restart', base_revision: JSON.parse(readFileSync(path.join(path.resolve(baseArtifact), 'manifest.json'), 'utf8')).revision, current_revision: currentAfterRestart.revision, previous_revision: previousAfterRestart.revision }) + '\n');
  } catch (error) {
    preserveFailure(error, operations);
    process.stderr.write(JSON.stringify({ status: 'RED', error: String(error.message || error), operations }) + '\n');
    process.exitCode = 1;
  } finally {
    cleanup();
  }
}

main();
