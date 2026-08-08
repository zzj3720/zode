#!/usr/bin/env node
'use strict';

/*
 * Build one immutable release artifact from a committed tree.  This command
 * is deliberately independent from the browser E2E: it never copies the
 * active worktree and it never starts a product process.  The resulting
 * directory is the handoff consumed by release/driver and the local channel.
 */
const {
  chmodSync,
  closeSync,
  cpSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} = require('node:fs');
const { createHash, randomUUID } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { basename, dirname, isAbsolute, join, relative, resolve, sep } = require('node:path');
const { tmpdir } = require('node:os');

const ARTIFACT_SCHEMA = 'zode.release-artifact.v1';
const MAX_BUFFER = 128 * 1024 * 1024;
const REQUIRED_SURFACE = [
  'Cargo.toml',
  'Cargo.lock',
  'src',
  'protocol/Cargo.toml',
  'protocol/src',
  'protocol/src/lib.rs',
  'server/Cargo.toml',
  'server/Cargo.lock',
  'server/src',
  'server/src/main.rs',
  'web/package.json',
  'web/pnpm-lock.yaml',
  'web/pnpm-workspace.yaml',
  'web/tsconfig.json',
  'web/index.html',
  'web/src',
  'web/src/main.ts',
  'web/vite.config.ts',
  'release/driver',
  'release/build.cjs',
  'release/channel.cjs',
];

class BuildError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

function fail(code, message, details = {}) {
  throw new BuildError(code, message, details);
}

function statOrNull(path) {
  try { return lstatSync(path); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function contained(root, candidate) {
  const value = relative(resolve(root), resolve(candidate));
  return value === '' || (!isAbsolute(value) && value !== '..' && !value.startsWith(`..${sep}`));
}

function ensureDirectory(path, mode = 0o700) {
  const value = resolve(path);
  const existing = statOrNull(value);
  if (existing?.isSymbolicLink()) fail('build_path_invalid', 'build output directory must not be a symlink', { path: value });
  mkdirSync(value, { recursive: true, mode });
  const checked = statOrNull(value);
  if (!checked?.isDirectory() || checked.isSymbolicLink()) fail('build_path_invalid', 'build path is not a regular directory', { path: value });
  chmodSync(value, mode);
  return value;
}

function immutableDirectory(path, label) {
  const stat = statOrNull(path);
  if (!stat?.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o222) !== 0) {
    fail('artifact_invalid', `${label} must be an immutable directory`, { path });
  }
  for (const name of readdirSync(path).sort()) {
    const child = join(path, name);
    const childStat = statOrNull(child);
    if (!childStat || childStat.isSymbolicLink() || (childStat.mode & 0o222) !== 0) {
      fail('artifact_invalid', `${label} contains a symlink or writable entry`, { path: child });
    }
    if (childStat.isDirectory()) immutableDirectory(child, label);
    else if (!childStat.isFile()) fail('artifact_invalid', `${label} contains a non-regular entry`, { path: child });
  }
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function treeDigest(path) {
  const entries = [];
  function visit(root, relRoot) {
    for (const name of readdirSync(root).sort()) {
      const absolute = join(root, name);
      const rel = join(relRoot, name);
      const stat = statOrNull(absolute);
      if (!stat || stat.isSymbolicLink() || (stat.mode & 0o222) !== 0) {
        fail('artifact_invalid', 'UI tree is not immutable', { path: absolute });
      }
      if (stat.isDirectory()) visit(absolute, rel);
      else if (stat.isFile()) entries.push({ path: rel, mode: stat.mode & 0o777, sha256: sha256(readFileSync(absolute)) });
      else fail('artifact_invalid', 'UI tree contains a non-regular entry', { path: absolute });
    }
  }
  immutableDirectory(path, 'UI tree');
  visit(path, '');
  return sha256(jsonBytes(entries));
}

function sourceTreeDigest(path) {
  const entries = [];
  function visit(root, relRoot) {
    const stat = statOrNull(root);
    if (!stat || stat.isSymbolicLink()) fail('archive_invalid', 'frozen source contains a symlink', { path: relRoot });
    if (stat.isDirectory()) {
      for (const name of readdirSync(root).sort()) visit(join(root, name), join(relRoot, name));
      return;
    }
    if (!stat.isFile()) fail('archive_invalid', 'frozen source contains a non-regular entry', { path: relRoot });
    entries.push({ path: relRoot, mode: stat.mode & 0o777, sha256: sha256(readFileSync(root)) });
  }
  visit(path, '');
  return sha256(jsonBytes(entries));
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    input: options.input,
    // `null` deliberately requests binary stdout from Node.  The archive
    // checkout passes tar bytes through this helper; coercing null to UTF-8
    // corrupts the stream and makes tar terminate with EPIPE.
    encoding: options.encoding === undefined ? 'utf8' : options.encoding,
    timeout: options.timeout ?? 300_000,
    maxBuffer: MAX_BUFFER,
    stdio: options.input === undefined ? ['ignore', 'pipe', 'pipe'] : undefined,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout ?? (options.encoding === null ? Buffer.alloc(0) : ''),
    stderr: result.stderr ?? (options.encoding === null ? Buffer.alloc(0) : ''),
  };
}

function canonicalCommit(repoRoot, value) {
  const result = run('git', ['rev-parse', '--verify', `${value}^{commit}`], { cwd: repoRoot });
  if (result.status !== 0) fail('revision_invalid', 'revision is not a commit', { revision: value });
  const revision = String(result.stdout).trim();
  if (!/^[a-f0-9]{40}$/.test(revision)) fail('revision_invalid', 'revision did not resolve to a full commit', { revision });
  return revision;
}

function trackedPathExists(repoRoot, revision, path) {
  return run('git', ['cat-file', '-e', `${revision}:${path}`], { cwd: repoRoot }).status === 0;
}

function archiveCheckout(repoRoot, revision, destination) {
  ensureDirectory(destination, 0o700);
  const archive = run('git', ['archive', '--format=tar', revision], { cwd: repoRoot, encoding: null });
  if (archive.status !== 0) fail('archive_failed', 'git archive failed', { revision });
  const unpack = run('tar', ['-xf', '-', '-C', destination], { input: archive.stdout });
  if (unpack.status !== 0) fail('archive_failed', 'frozen archive could not be unpacked', { revision });
  immutableSource(destination, destination);
}

function immutableSource(path, root) {
  const stat = statOrNull(path);
  if (!stat || stat.isSymbolicLink()) fail('archive_invalid', 'frozen source contains a symlink', { path: relative(root, path) });
  if (stat.isDirectory()) {
    for (const name of readdirSync(path).sort()) immutableSource(join(path, name), root);
  } else if (!stat.isFile()) {
    fail('archive_invalid', 'frozen source contains a non-regular entry', { path: relative(root, path) });
  }
}

function copyTree(source, destination) {
  const stat = statOrNull(source);
  if (!stat || stat.isSymbolicLink()) fail('artifact_invalid', 'artifact source contains a symlink', { source });
  if (stat.isDirectory()) {
    mkdirSync(destination, { mode: 0o755 });
    for (const name of readdirSync(source).sort()) copyTree(join(source, name), join(destination, name));
    chmodSync(destination, 0o555);
  } else if (stat.isFile()) {
    cpSync(source, destination, { force: false, errorOnExist: true });
    chmodSync(destination, stat.mode & 0o111 ? 0o555 : 0o444);
  } else fail('artifact_invalid', 'artifact source contains a non-regular entry', { source });
}

function writeExclusive(path, value, mode) {
  const fd = openSync(path, 'wx', mode);
  try { writeFileSync(fd, value); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(path, mode);
}

function buildArtifact({ repoRoot, revision, outputRoot, keepBuild }) {
  revision = canonicalCommit(repoRoot, revision);
  const missing = REQUIRED_SURFACE.filter((path) => !trackedPathExists(repoRoot, revision, path));
  if (missing.length) fail('missing_build_surface', 'frozen revision lacks the complete build surface', { revision, missing });

  const workRoot = resolve(mkdtempSync(join(tmpdir(), 'zode-release-build-')));
  const checkout = join(workRoot, 'checkout');
  const logs = join(workRoot, 'logs');
  ensureDirectory(logs, 0o700);
  try {
    archiveCheckout(repoRoot, revision, checkout);
    const sourceTreeSha256 = sourceTreeDigest(checkout);
    const runBuild = (command, args, cwd, logName) => {
      const result = run(command, args, { cwd });
      const logPath = join(logs, logName);
      writeExclusive(logPath, Buffer.from(`${result.stdout}${result.stderr}`, 'utf8'), 0o600);
      if (result.status !== 0) fail('build_failed', `${command} failed for the frozen revision`, { revision, command, log: logPath });
    };
    runBuild('vp', ['install', '--frozen-lockfile'], join(checkout, 'web'), 'ui-install.log');
    runBuild('vp', ['build'], join(checkout, 'web'), 'ui-build.log');
    runBuild('vp', ['exec', 'cargo', 'build', '--release', '--locked', '--manifest-path', join(checkout, 'Cargo.toml')], checkout, 'endpoint-build.log');
    runBuild('vp', ['exec', 'cargo', 'build', '--release', '--locked', '--manifest-path', join(checkout, 'server', 'Cargo.toml')], checkout, 'server-build.log');

    const ui = join(checkout, 'web', 'dist');
    const endpoint = join(checkout, 'target', 'release', 'zode');
    const server = join(checkout, 'server', 'target', 'release', 'zode-server');
    const driver = join(checkout, 'release', 'driver');
    for (const [path, label] of [[ui, 'web/dist'], [endpoint, 'target/release/zode'], [server, 'server/target/release/zode-server'], [driver, 'release/driver']]) {
      const stat = statOrNull(path);
      if (!stat || (label === 'web/dist' ? !stat.isDirectory() : !stat.isFile()) || stat.isSymbolicLink()) {
        fail('missing_build_output', `frozen revision did not produce ${label}`, { revision, path });
      }
    }

    ensureDirectory(outputRoot, 0o700);
    const finalPath = join(resolve(outputRoot), revision);
    if (statOrNull(finalPath)) fail('artifact_exists', 'artifact output already exists; refusing overwrite', { artifact: finalPath });
    const temporary = join(resolve(outputRoot), `.artifact-${revision}-${randomUUID()}`);
    mkdirSync(temporary, { mode: 0o700 });
    try {
      copyTree(ui, join(temporary, 'ui'));
      cpSync(server, join(temporary, 'zode-server'), { force: false, errorOnExist: true });
      cpSync(endpoint, join(temporary, 'zode'), { force: false, errorOnExist: true });
      cpSync(driver, join(temporary, 'release-driver'), { force: false, errorOnExist: true });
      chmodSync(join(temporary, 'zode-server'), 0o555);
      chmodSync(join(temporary, 'zode'), 0o555);
      chmodSync(join(temporary, 'release-driver'), 0o555);
      immutableDirectory(join(temporary, 'ui'), 'UI artifact tree');
      const components = {
        ui: { kind: 'tree', path: 'ui', revision, tree_sha256: treeDigest(join(temporary, 'ui')) },
        server: { kind: 'binary', path: 'zode-server', revision, binary_sha256: sha256(readFileSync(join(temporary, 'zode-server'))) },
        endpoint: { kind: 'binary', path: 'zode', revision, binary_sha256: sha256(readFileSync(join(temporary, 'zode'))) },
      };
      const driverBinding = { kind: 'executable', path: 'release-driver', revision, binary_sha256: sha256(readFileSync(join(temporary, 'release-driver'))) };
      const manifest = {
        schema: ARTIFACT_SCHEMA,
        revision,
        source: { kind: 'git-archive', revision, tree_sha256: sourceTreeSha256 },
        components,
        driver: driverBinding,
        binding: {
          revision,
          source_tree_sha256: sourceTreeSha256,
          ui_tree_sha256: components.ui.tree_sha256,
          server_binary_sha256: components.server.binary_sha256,
          endpoint_binary_sha256: components.endpoint.binary_sha256,
          driver_binary_sha256: driverBinding.binary_sha256,
        },
      };
      writeExclusive(join(temporary, 'manifest.json'), jsonBytes({ ...manifest, manifest_sha256: sha256(jsonBytes(manifest)) }), 0o444);
      chmodSync(temporary, 0o555);
      renameSync(temporary, finalPath);
      return {
        artifact: finalPath,
        manifest: join(finalPath, 'manifest.json'),
        revision,
        manifest_sha256: sha256(readFileSync(join(finalPath, 'manifest.json'))),
        source_tree_sha256: sourceTreeSha256,
      };
    } catch (error) {
      rmSync(temporary, { recursive: true, force: true });
      throw error;
    }
  } finally {
    if (!keepBuild) rmSync(workRoot, { recursive: true, force: true });
  }
}

function parseArgs(argv) {
  const options = { command: argv.shift(), repoRoot: process.cwd(), outputRoot: null, revision: null, keepBuild: false };
  while (argv.length) {
    const arg = argv.shift();
    if (arg === '--revision') options.revision = argv.shift();
    else if (arg === '--output-root') options.outputRoot = argv.shift();
    else if (arg === '--repo-root') options.repoRoot = argv.shift();
    else if (arg === '--keep-build') options.keepBuild = true;
    else throw new BuildError('usage', `unknown argument: ${arg}`);
  }
  if (options.command !== 'build' || !options.revision || !options.outputRoot) {
    throw new BuildError('usage', 'usage: build --revision COMMIT --output-root DIR [--repo-root DIR] [--keep-build]');
  }
  options.repoRoot = realpathSync(resolve(options.repoRoot));
  options.outputRoot = resolve(options.outputRoot);
  return options;
}

try {
  const options = parseArgs(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(buildArtifact(options))}\n`);
} catch (error) {
  const payload = error instanceof BuildError
    ? { ok: false, error: { code: error.code, message: error.message, details: error.details } }
    : { ok: false, error: { code: 'build_error', message: String(error) } };
  process.stderr.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = error instanceof BuildError && error.code === 'usage' ? 2 : 1;
}
