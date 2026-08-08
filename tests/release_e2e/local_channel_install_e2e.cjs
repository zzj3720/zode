#!/usr/bin/env node
'use strict';

/* Real-process smoke for the first local-channel handoff. */
const { existsSync, lstatSync, mkdtempSync, readdirSync, symlinkSync } = require('node:fs');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const artifact = process.env.ZODE_RELEASE_CHANNEL_ARTIFACT;
if (!artifact) {
  process.stdout.write(JSON.stringify({ status: 'BLOCKED', code: 78, reason: 'ZODE_RELEASE_CHANNEL_ARTIFACT is required' }) + '\n');
  process.exitCode = 78;
} else {
  const channel = join(__dirname, '..', '..', 'release', 'channel.cjs');
  // tmpdir() is intentionally used instead of a repository-relative path: it
  // exercises the normal macOS /tmp alias without touching the active tree.
  const releaseRoot = mkdtempSync(join(tmpdir(), 'zode-local-channel-e2e-'));
  const result = spawnSync(process.execPath, [channel, 'install', '--artifact', artifact, '--release-root', releaseRoot], {
    cwd: join(__dirname, '..', '..'),
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  let payload = null;
  try { payload = JSON.parse(String(result.stdout ?? '').trim().split(/\r?\n/).filter(Boolean).at(-1)); } catch {}
  const installed = existsSync(join(releaseRoot, 'releases'))
    && readdirSync(join(releaseRoot, 'releases')).length === 1
    && !existsSync(join(releaseRoot, 'current'))
    && !existsSync(join(releaseRoot, 'previous'));
  const installedDirectory = installed ? join(releaseRoot, 'releases', readdirSync(join(releaseRoot, 'releases'))[0]) : null;
  const installedManifestSha256 = installedDirectory
    ? createHash('sha256').update(require('node:fs').readFileSync(join(installedDirectory, 'manifest.json'))).digest('hex')
    : null;
  let healthResult = null;
  let healthPayload = null;
  if (result.status === 0 && installedDirectory) {
    symlinkSync(installedDirectory, join(releaseRoot, 'current'), 'dir');
    healthResult = spawnSync(process.execPath, [channel, 'health', '--release-root', releaseRoot], {
      cwd: join(__dirname, '..', '..'), encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
    });
    try { healthPayload = JSON.parse(String(healthResult.stdout ?? '').trim().split(/\r?\n/).filter(Boolean).at(-1)); } catch {}
  }
  // An installed artifact without a bootstrapped instance is a valid recovery
  // state.  Health must return a structured failed probe, not crash while
  // dereferencing an absent live-state record.
  const healthSafe = healthResult && healthResult.status !== 0
    && healthPayload?.operation === 'health'
    && healthPayload?.health?.status === 'failed'
    && !healthPayload?.error;
  const ok = result.status === 0 && payload?.ok === true && installed
    && payload.manifest_sha256 === installedManifestSha256
    && healthSafe
    && lstatSync(releaseRoot).isDirectory() && !lstatSync(releaseRoot).isSymbolicLink();
  process.stdout.write(JSON.stringify({ status: ok ? 'PASS' : 'RED', release_root: releaseRoot, payload, health_payload: healthPayload, stdout: result.stdout, stderr: result.stderr, health_stdout: healthResult?.stdout ?? null, health_stderr: healthResult?.stderr ?? null }) + '\n');
  process.exitCode = ok ? 0 : 1;
}
