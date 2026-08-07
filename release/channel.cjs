#!/usr/bin/env node
'use strict';

/*
 * Fixed local test-channel operator entry.
 *
 * This wrapper is intentionally thin: artifact validation, installation,
 * readiness, pointer transactions, process ownership, and teardown remain in
 * the immutable release driver.  The wrapper only gives the local channel a
 * stable build/install/start/stop/update vocabulary.  It has no cassette,
 * replay, recorder, browser, or release-control API input.
 */
const { chmodSync, existsSync, lstatSync, mkdirSync, readlinkSync, realpathSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { dirname, join, resolve } = require('node:path');

const MAX_OUTPUT = 16 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 300_000;
const REPO_ROOT = resolve(__dirname, '..');
const BUILD_ENTRY = join(__dirname, 'build.cjs');
const SOURCE_DRIVER = join(__dirname, 'driver');

class ChannelError extends Error {
  constructor(code, message, details = {}, status = 1) {
    super(message);
    this.code = code;
    this.details = details;
    this.status = status;
  }
}

function fail(code, message, details = {}, status = 1) {
  throw new ChannelError(code, message, details, status);
}

function usage() {
  return [
    'usage:',
    '  channel.cjs build --revision COMMIT --output-root DIR [--repo-root DIR] [--keep-build]',
    '  channel.cjs install --artifact DIR --release-root DIR',
    '  channel.cjs start --release-root DIR [--artifact DIR]',
    '  channel.cjs stop --release-root DIR',
    '  channel.cjs health --release-root DIR',
    '  channel.cjs update --artifact DIR --release-root DIR',
    '',
    'start requires --artifact only for an empty channel; update never changes',
    'current unless its candidate passes the release driver readiness gate.',
  ].join('\n');
}

function parseArgs(argv) {
  const operation = argv.shift();
  if (!operation || operation === '--help' || operation === '-h') return { help: true };
  if (!['build', 'install', 'start', 'stop', 'health', 'update'].includes(operation)) {
    fail('channel_usage', 'unknown local-channel operation', { operation }, 2);
  }
  const options = { operation, values: {} };
  while (argv.length) {
    const key = argv.shift();
    if (!key.startsWith('--')) fail('channel_usage', 'options require --name value', { option: key }, 2);
    const name = key.slice(2).replaceAll('-', '_');
    if (!['artifact', 'release_root', 'revision', 'output_root', 'repo_root'].includes(name)) {
      // build.cjs owns only its documented build switches.  The channel does
      // not accept a test-mode, cassette, locator, or arbitrary env switch.
      if (name === 'keep_build') {
        options.values[name] = true;
        continue;
      }
      fail('channel_usage', 'unknown local-channel option', { option: key }, 2);
    }
    if (argv.length === 0) fail('channel_usage', 'options require --name value', { option: key }, 2);
    options.values[name] = argv.shift();
  }
  return options;
}

function requireValue(options, name) {
  const value = options.values[name];
  if (typeof value !== 'string' || value.length === 0) fail('channel_usage', `${name} is required`, {}, 2);
  return resolve(value);
}

function requireRawValue(options, name) {
  const value = options.values[name];
  if (typeof value !== 'string' || value.length === 0) fail('channel_usage', `${name} is required`, {}, 2);
  return value;
}

function channelRoot(options) {
  const root = requireValue(options, 'release_root');
  const existing = (() => { try { return lstatSync(root); } catch (error) { if (error?.code === 'ENOENT') return null; throw error; } })();
  if (existing?.isSymbolicLink()) fail('channel_root_invalid', 'release-root must not be a symlink', { path: root });
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const checked = lstatSync(root);
  if (!checked.isDirectory() || checked.isSymbolicLink()) fail('channel_root_invalid', 'release-root must be a regular directory', { path: root });
  chmodSync(root, 0o700);
  return root;
}

function pointerSnapshot(root) {
  const result = {};
  for (const name of ['current', 'previous']) {
    const path = join(root, name);
    try {
      const stat = lstatSync(path);
      result[name] = stat.isSymbolicLink() ? { link: readlinkSync(path), target: realpathSync(path) } : { target: realpathSync(path) };
    } catch (error) {
      if (error?.code === 'ENOENT') result[name] = null;
      else throw error;
    }
  }
  return result;
}

function sameSnapshot(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function parseLastJson(stdout) {
  const lines = String(stdout ?? '').trim().split(/\r?\n/).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try { return JSON.parse(lines[index]); } catch { /* readiness lines precede the JSON result */ }
  }
  return null;
}

function runExecutable(executable, args, { cwd = REPO_ROOT } = {}) {
  const result = spawnSync(executable, args, {
    cwd,
    env: process.env,
    encoding: 'utf8',
    timeout: COMMAND_TIMEOUT_MS,
    maxBuffer: MAX_OUTPUT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error?.code === 'ETIMEDOUT') fail('channel_timeout', 'local-channel operation exceeded its bound', { executable, args });
  if (result.error) fail('channel_spawn_failed', 'local-channel operation could not start', { executable, error: String(result.error) });
  const payload = parseLastJson(result.stdout);
  return { status: result.status ?? 1, stdout: result.stdout ?? '', stderr: result.stderr ?? '', payload };
}

function driverForArtifact(artifact) {
  const driver = join(artifact, 'release-driver');
  if (!existsSync(driver)) fail('channel_artifact_invalid', 'artifact has no immutable release driver', { artifact });
  return driver;
}

function driverForCurrent(root) {
  try {
    const current = realpathSync(join(root, 'current'));
    return driverForArtifact(current);
  } catch {
    fail('channel_current_missing', 'no installed current release driver is available', { release_root: root });
  }
}

function invokeDriver(operation, root, artifact = null) {
  // An external artifact is data until the trusted checkout driver has
  // validated its immutable manifest. Never execute its embedded driver for
  // install/bootstrap/stage admission; those operations may copy or start
  // files. Once installed, promote/health/teardown use the digest-bound copy
  // under current.
  const driver = artifact && ['install', 'bootstrap', 'stage'].includes(operation)
    ? SOURCE_DRIVER
    : artifact ? driverForArtifact(artifact) : driverForCurrent(root);
  const args = [operation, '--release-root', root];
  if (artifact) args.push('--artifact', artifact);
  args.push('--json');
  const result = runExecutable(driver, args, { cwd: dirname(driver) });
  if (result.status !== 0) {
    const payload = result.payload ?? { ok: false, error: { code: 'driver_failed', message: result.stderr.trim() || `driver exited ${result.status}` } };
    return { ...result, payload };
  }
  if (!result.payload || result.payload.ok !== true) {
    fail('channel_driver_protocol', 'release driver returned no successful JSON result', { operation, stdout: result.stdout, stderr: result.stderr });
  }
  return result;
}

function emit(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function runBuild(options) {
  const values = options.values;
  // A revision is a git expression (`HEAD`, tag, or SHA), not a filesystem
  // path.  Only output/repository locations go through path resolution.
  const args = ['build', '--revision', requireRawValue(options, 'revision'), '--output-root', requireValue(options, 'output_root')];
  if (values.repo_root) args.push('--repo-root', resolve(values.repo_root));
  if (values.keep_build) args.push('--keep-build');
  const result = runExecutable(process.execPath, [BUILD_ENTRY, ...args]);
  if (result.status !== 0) fail('channel_build_failed', 'immutable release build failed', { stdout: result.stdout, stderr: result.stderr });
  const payload = parseLastJson(result.stdout);
  if (!payload?.artifact || !payload?.revision) fail('channel_build_protocol', 'build did not return an artifact manifest', { stdout: result.stdout });
  return payload;
}

function main(options) {
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  if (options.operation === 'build') {
    emit(runBuild(options));
    return 0;
  }
  const root = channelRoot(options);
  if (options.operation === 'install') {
    const artifact = requireValue(options, 'artifact');
    const result = invokeDriver('install', root, artifact);
    if (result.status !== 0 || !result.payload?.ok) {
      emit({ ok: false, operation: 'install', release_root: root, ...(result.payload ?? {}) });
      return result.status || 1;
    }
    emit({ ok: true, operation: 'install', release_root: root, ...result.payload });
    return 0;
  }
  if (options.operation === 'start') {
    const before = pointerSnapshot(root);
    const current = before.current;
    const artifact = options.values.artifact ? resolve(options.values.artifact) : null;
    let result = current ? invokeDriver('health', root) : null;
    if (!result || result.status !== 0) {
      const bootstrapArtifact = artifact ?? current?.target;
      if (!bootstrapArtifact) fail('channel_usage', 'start on an empty channel requires --artifact', {}, 2);
      result = invokeDriver('bootstrap', root, bootstrapArtifact);
    }
    if (result.status !== 0) {
      emit({ ok: false, operation: 'start', release_root: root, ...result.payload });
      return result.status;
    }
    emit({ ok: true, operation: 'start', release_root: root, ...result.payload });
    return 0;
  }
  if (options.operation === 'stop') {
    const result = invokeDriver('teardown', root);
    emit({ ok: result.status === 0, operation: 'stop', release_root: root, ...result.payload });
    return result.status;
  }
  if (options.operation === 'health') {
    const result = invokeDriver('health', root);
    emit({ ok: result.status === 0, operation: 'health', release_root: root, ...result.payload });
    return result.status;
  }
  if (options.operation === 'update') {
    const artifact = requireValue(options, 'artifact');
    const before = pointerSnapshot(root);
    const staged = invokeDriver('stage', root, artifact);
    if (staged.status !== 0) {
      const after = pointerSnapshot(root);
      const unchanged = sameSnapshot(before, after);
      emit({ ok: false, operation: 'update', release_root: root, current_unchanged: unchanged, ...staged.payload });
      return staged.status;
    }
    const promoted = invokeDriver('promote', root);
    if (promoted.status !== 0) {
      emit({ ok: false, operation: 'update', release_root: root, ...promoted.payload });
      return promoted.status;
    }
    emit({ ok: true, operation: 'update', release_root: root, ...promoted.payload });
    return 0;
  }
  fail('channel_usage', 'unsupported local-channel operation', { operation: options.operation }, 2);
}

try {
  process.exitCode = main(parseArgs(process.argv.slice(2)));
} catch (error) {
  const safe = error instanceof ChannelError
    ? { code: error.code, message: error.message, details: error.details }
    : { code: 'channel_error', message: String(error), details: {} };
  emit({ ok: false, error: safe });
  process.exitCode = error instanceof ChannelError ? error.status : 1;
}
