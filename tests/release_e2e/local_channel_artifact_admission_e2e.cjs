#!/usr/bin/env node
'use strict';

/* Real-process red/green test for artifact-driver admission ordering. */
const { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } = require('node:fs');
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
  process.stdout.write(JSON.stringify({ status: passed ? 'PASS' : 'RED', marker, stdout: result.stdout, stderr: result.stderr }) + '\n');
  process.exitCode = passed ? 0 : 1;
}
