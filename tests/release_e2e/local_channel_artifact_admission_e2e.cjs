#!/usr/bin/env node
'use strict';

/* Real-process red/green test for artifact-driver admission ordering. */
const { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } = require('node:fs');
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
  const workspace = mkdtempSync(join(tmpdir(), 'zode-channel-admission-e2e-'));
  const malicious = join(workspace, 'artifact');
  cpSync(artifact, malicious, { recursive: true, force: false, errorOnExist: true });
  const marker = join(workspace, 'driver-ran');
  const driver = join(malicious, 'release-driver');
  chmodSync(driver, 0o700);
  writeFileSync(driver, `#!/usr/bin/env node\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'unexpected');\nprocess.exit(1);\n`, { mode: 0o555 });
  chmodSync(driver, 0o555);
  const releaseRoot = join(workspace, 'channel-root');
  mkdirSync(releaseRoot, { mode: 0o700 });
  const result = spawnSync(process.execPath, [channel, 'install', '--artifact', malicious, '--release-root', releaseRoot], {
    cwd: join(__dirname, '..', '..'),
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  const passed = result.status !== 0 && !existsSync(marker);
  const currentWorkspace = mkdtempSync(join(tmpdir(), 'zode-channel-current-admission-e2e-'));
  const currentRoot = join(currentWorkspace, 'channel-root');
  mkdirSync(currentRoot, { mode: 0o700 });
  const install = spawnSync(process.execPath, [channel, 'install', '--artifact', artifact, '--release-root', currentRoot], {
    cwd: join(__dirname, '..', '..'), encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
  });
  let installPayload = null;
  try { installPayload = JSON.parse(String(install.stdout ?? '').trim().split(/\r?\n/).filter(Boolean).at(-1)); } catch {}
  const installed = installPayload?.artifact;
  const currentMarker = join(currentWorkspace, 'current-driver-ran');
  let currentResult = null;
  if (install.status === 0 && installed) {
    symlinkSync(installed, join(currentRoot, 'current'), 'dir');
    const installedDriver = join(installed, 'release-driver');
    chmodSync(installedDriver, 0o700);
    writeFileSync(installedDriver, `#!/usr/bin/env node\nrequire('node:fs').writeFileSync(${JSON.stringify(currentMarker)}, 'unexpected');\nprocess.exit(1);\n`, { mode: 0o555 });
    chmodSync(installedDriver, 0o555);
    currentResult = spawnSync(process.execPath, [channel, 'health', '--release-root', currentRoot], {
      cwd: join(__dirname, '..', '..'), encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
    });
  }
  const currentSafe = currentResult && currentResult.status !== 0 && !existsSync(currentMarker);
  const fakeWorkspace = mkdtempSync(join(tmpdir(), 'zode-channel-fake-current-e2e-'));
  const fakeRoot = join(fakeWorkspace, 'channel-root');
  const fakeArtifact = join(fakeRoot, 'releases', 'fake');
  mkdirSync(fakeArtifact, { recursive: true, mode: 0o700 });
  const fakeMarker = join(fakeWorkspace, 'fake-driver-ran');
  const fakeDriver = join(fakeArtifact, 'release-driver');
  writeFileSync(fakeDriver, `#!/usr/bin/env node\nrequire('node:fs').writeFileSync(${JSON.stringify(fakeMarker)}, 'unexpected');\nprocess.exit(1);\n`, { mode: 0o555 });
  chmodSync(fakeDriver, 0o555);
  const fakeDriverSha = createHash('sha256').update(require('node:fs').readFileSync(fakeDriver)).digest('hex');
  const fakeManifest = {
    schema: 'zode.release-artifact.v1',
    revision: '0'.repeat(40),
    driver: { kind: 'executable', path: 'release-driver', revision: '0'.repeat(40), binary_sha256: fakeDriverSha },
    binding: { revision: '0'.repeat(40), driver_binary_sha256: fakeDriverSha },
  };
  const fakeEnvelope = Buffer.from(`${JSON.stringify(fakeManifest, null, 2)}\n`, 'utf8');
  writeFileSync(join(fakeArtifact, 'manifest.json'), `${JSON.stringify({ ...fakeManifest, manifest_sha256: createHash('sha256').update(fakeEnvelope).digest('hex') }, null, 2)}\n`, { mode: 0o444 });
  chmodSync(fakeArtifact, 0o555);
  symlinkSync(fakeArtifact, join(fakeRoot, 'current'), 'dir');
  const fakeResult = spawnSync(process.execPath, [channel, 'health', '--release-root', fakeRoot], {
    cwd: join(__dirname, '..', '..'), encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
  });
  const fakeSafe = fakeResult.status !== 0 && !existsSync(fakeMarker);
  const passedAll = passed && currentSafe && fakeSafe;
  process.stdout.write(JSON.stringify({ status: passedAll ? 'PASS' : 'RED', marker, currentMarker, fakeMarker, stdout: result.stdout, stderr: result.stderr, current_stdout: currentResult?.stdout ?? null, current_stderr: currentResult?.stderr ?? null, fake_stdout: fakeResult.stdout, fake_stderr: fakeResult.stderr }) + '\n');
  process.exitCode = passedAll ? 0 : 1;
}
