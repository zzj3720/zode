#!/usr/bin/env node
'use strict';

/* Real-process smoke for the first local-channel handoff. */
const { existsSync, lstatSync, mkdtempSync, readdirSync } = require('node:fs');
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
  const ok = result.status === 0 && payload?.ok === true && installed
    && lstatSync(releaseRoot).isDirectory() && !lstatSync(releaseRoot).isSymbolicLink();
  process.stdout.write(JSON.stringify({ status: ok ? 'PASS' : 'RED', release_root: releaseRoot, payload, stdout: result.stdout, stderr: result.stderr }) + '\n');
  process.exitCode = ok ? 0 : 1;
}
