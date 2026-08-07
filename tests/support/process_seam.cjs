#!/usr/bin/env node
'use strict';

/*
 * Test-only process seam.
 *
 * This file deliberately lives below tests/.  It is not imported by the
 * Endpoint, Server, or web production bundles.  The release and browser
 * harnesses may either require the exported functions or invoke the CLI.
 *
 * The locator is intentionally a small, non-secret description of a child
 * process.  Environment variables, command arguments, access assertions, and
 * bearer values never enter the locator or stop result.
 */

const {
  chmodSync,
  closeSync,
  createReadStream,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  readSync,
  rmSync,
  writeSync,
} = require('node:fs');
const { createHash, randomUUID } = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');
const { basename, dirname, isAbsolute, join, resolve } = require('node:path');

const PROCESS_LOCATOR_SCHEMA = 'zode.e2e.process-locator.v1';
const PROCESS_STOP_SCHEMA = 'zode.e2e.process-stop.v1';
const READY_PREFIX = 'ZODE_PROCESS_READY ';
const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_POLL_MS = 25;
const MAX_TIMEOUT_MS = 120_000;
const MAX_MARKER_BYTES = 1024 * 1024;
const MAX_PROCESS_OUTPUT_BYTES = 16 * 1024 * 1024;
const PROCESS_START_TIME_TOLERANCE_MS = 10 * 1000;
const DEFAULT_REGISTRY = join(tmpdir(), 'zode-e2e-process-seam-v1');
const activeChildren = new Map();
const PROCESS_ROLES = new Set(['supervisor', 'server', 'endpoint']);
const OWNER_SCHEMA = 'zode.e2e.process-owner.v1';

const LOCATOR_KEYS = new Set([
  'schema',
  'instance_id',
  'role',
  'pid',
  'started_at_unix_ms',
  'process_group_id',
  'session_id',
  'executable_path',
  'executable_sha256',
  'control_origin',
]);

class SeamError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'SeamError';
    this.code = code;
    this.details = details;
  }
}

class SecretMarkerError extends SeamError {
  constructor(surface) {
    // Do not interpolate the marker or the value which contained it.  A
    // marker is commonly a real credential in a test environment.
    super('secret_marker', `${surface} contained a configured secret marker`);
    this.name = 'SecretMarkerError';
  }
}

class OutputBoundError extends SeamError {
  constructor() {
    super('output_bound_exceeded', 'child process output exceeded the bounded flush limit');
    this.name = 'OutputBoundError';
  }
}

function privateDirectory(directory) {
  const path = resolve(directory);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new SeamError('locator_directory_invalid', 'locator directory is not a private directory');
  }
  return path;
}

function privateFile(path) {
  const target = resolve(path);
  const parent = privateDirectory(dirname(target));
  let existing = null;
  try {
    existing = lstatSync(target);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw new SeamError('locator_path_invalid', 'locator path could not be inspected');
  }
  if (existing && existing.isSymbolicLink()) {
    throw new SeamError('locator_path_invalid', 'locator path may not be a symlink');
  }
  return join(parent, basename(target));
}

function markerBytes(markers) {
  const values = Array.isArray(markers) ? markers : [];
  const result = [];
  for (const value of values) {
    if (typeof value !== 'string' && !Buffer.isBuffer(value)) {
      throw new SeamError('secret_markers_invalid', 'secret markers must be strings');
    }
    const marker = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
    if (marker.length === 0) continue;
    if (marker.length > MAX_MARKER_BYTES) {
      throw new SeamError('secret_markers_invalid', 'secret marker is too large');
    }
    result.push(marker);
  }
  return result;
}

function configuredMarkers(options = {}) {
  const markers = [];
  if (Array.isArray(options.secretMarkers)) markers.push(...options.secretMarkers);
  if (typeof options.secretMarker === 'string') markers.push(options.secretMarker);
  const raw = process.env.ZODE_E2E_SECRET_MARKERS;
  if (raw) markers.push(...raw.split(',').map((value) => value.trim()).filter(Boolean));
  const json = process.env.ZODE_E2E_SECRET_MARKERS_JSON;
  if (json) {
    try {
      const values = JSON.parse(json);
      if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
        throw new Error('not a string array');
      }
      markers.push(...values);
    } catch {
      throw new SeamError('secret_markers_invalid', 'configured secret markers are not a JSON string array');
    }
  }
  const seen = new Set();
  return markerBytes(markers).filter((marker) => {
    const key = marker.toString('base64');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function assertMarkerFree(value, markers, surface) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value ?? ''), 'utf8');
  for (const marker of markers) {
    if (bytes.includes(marker)) throw new SecretMarkerError(surface);
  }
}

function validateText(value, field, { max = 512 } = {}) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new SeamError('locator_invalid', `${field} is invalid`);
  }
  return value;
}

function generatedInstanceId() {
  // randomUUID has 122 random bits.  The prefix makes this value easy to
  // recognize in test diagnostics without making it a caller-selected ID.
  return `zode-e2e-${randomUUID()}`;
}

function normalizeExecutable(executable, markers) {
  if (typeof executable !== 'string' || executable.length === 0) {
    throw new SeamError('executable_missing', 'an executable path is required');
  }
  const lexical = resolve(executable);
  assertMarkerFree(lexical, markers, 'executable path');
  let path;
  try {
    path = realpathSync(lexical);
  } catch {
    throw new SeamError('executable_missing', 'executable path does not exist');
  }
  assertMarkerFree(path, markers, 'executable path');
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new SeamError('executable_invalid', 'executable path is not a regular file');
  }
  try {
    // accessSync is intentionally avoided so this check remains usable in a
    // restricted test runner; mode bits plus spawn's error are sufficient.
    if ((stat.mode & 0o111) === 0) throw new Error('not executable');
  } catch {
    throw new SeamError('executable_invalid', 'executable path is not executable');
  }
  return path;
}

function hashFile(path) {
  return new Promise((resolvePromise, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.once('error', reject);
    stream.once('end', () => resolvePromise(hash.digest('hex')));
  });
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = openSync(directory, 'r');
    fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function writePrivateJson(path, value) {
  const target = privateFile(path);
  const temp = `${target}.tmp-${process.pid}-${randomUUID()}`;
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  let descriptor;
  let published = false;
  try {
    descriptor = openSync(temp, 'wx', 0o600);
    writeSync(descriptor, bytes);
    fsyncSync(descriptor);
    fchmodSync(descriptor, 0o600);
    closeSync(descriptor);
    descriptor = undefined;
    // A rename would replace a concurrently published locator.  Linking the
    // fsync'd inode gives create-new semantics: an existing target fails with
    // EEXIST and is never overwritten.
    linkSync(temp, target);
    published = true;
    chmodSync(target, 0o600);
    fsyncDirectory(dirname(target));
    rmSync(temp, { force: true });
    fsyncDirectory(dirname(target));
    return target;
  } catch (error) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
    try { rmSync(temp, { force: true }); } catch {}
    if (published) {
      try { rmSync(target, { force: true }); } catch {}
    }
    throw error;
  }
}

function defaultLocatorPath(instanceId, locatorDir) {
  return join(privateDirectory(locatorDir || process.env.ZODE_E2E_PROCESS_LOCATOR_DIR || DEFAULT_REGISTRY), `${instanceId}.locator.json`);
}

function logPaths(locatorPath) {
  return {
    stdout: `${locatorPath}.stdout.log`,
    stderr: `${locatorPath}.stderr.log`,
  };
}

function ownerPath(locatorPath) {
  return `${locatorPath}.owner.json`;
}

function locatorValuesEqual(left, right) {
  for (const key of LOCATOR_KEYS) {
    if ((left[key] ?? undefined) !== (right[key] ?? undefined)) return false;
  }
  return true;
}

function writeOwnerMetadata(locatorPath, locator, markers = []) {
  const metadata = { schema: OWNER_SCHEMA, locator };
  assertMarkerFree(JSON.stringify(metadata), markers, 'process owner metadata');
  return writePrivateJson(ownerPath(locatorPath), metadata);
}

function readOwnerMetadata(locatorPath, markers) {
  const safeMarkers = markerBytes(markers);
  const target = privateFile(ownerPath(locatorPath));
  let metadata;
  try {
    const bytes = readFileSync(target);
    assertMarkerFree(bytes, safeMarkers, 'process owner metadata');
    metadata = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    if (error instanceof SecretMarkerError) throw error;
    throw new SeamError('process_owner_missing', 'process owner metadata is unavailable');
  }
  if (metadata?.schema !== OWNER_SCHEMA || !metadata.locator) {
    throw new SeamError('process_owner_invalid', 'process owner metadata is invalid');
  }
  const ownerLocator = validateLocator(metadata.locator);
  assertMarkerFree(JSON.stringify(ownerLocator), safeMarkers, 'process owner metadata');
  return ownerLocator;
}

function removeOwnPublication(locatorPath, locator) {
  try {
    const current = readLocator(locatorPath);
    if (locatorValuesEqual(current, locator)) rmSync(locatorPath, { force: true });
  } catch {}
  try {
    const currentOwner = readOwnerMetadata(locatorPath, []);
    if (locatorValuesEqual(currentOwner, locator)) rmSync(ownerPath(locatorPath), { force: true });
  } catch {}
}

function validateLocator(locator) {
  if (!locator || typeof locator !== 'object' || Array.isArray(locator)) {
    throw new SeamError('locator_invalid', 'locator must be a JSON object');
  }
  for (const key of Object.keys(locator)) {
    if (!LOCATOR_KEYS.has(key)) throw new SeamError('locator_invalid', 'locator contains an unsupported field');
  }
  if (locator.schema !== PROCESS_LOCATOR_SCHEMA) throw new SeamError('locator_invalid', 'locator schema is unsupported');
  validateText(locator.instance_id, 'instance_id', { max: 256 });
  validateText(locator.role, 'role');
  if (!PROCESS_ROLES.has(locator.role)) throw new SeamError('locator_invalid', 'locator role is unsupported');
  validateText(locator.session_id, 'session_id');
  if (!Number.isSafeInteger(locator.pid) || locator.pid <= 1) throw new SeamError('locator_invalid', 'pid is invalid');
  if (!Number.isSafeInteger(locator.process_group_id) || locator.process_group_id <= 1) {
    throw new SeamError('locator_invalid', 'process_group_id is invalid');
  }
  if (!Number.isSafeInteger(locator.started_at_unix_ms) || locator.started_at_unix_ms <= 0) {
    throw new SeamError('locator_invalid', 'started_at_unix_ms is invalid');
  }
  validateText(locator.executable_path, 'executable_path', { max: 4096 });
  if (!isAbsolute(locator.executable_path)) throw new SeamError('locator_invalid', 'executable_path must be absolute');
  if (!/^[0-9a-f]{64}$/u.test(locator.executable_sha256)) throw new SeamError('locator_invalid', 'executable_sha256 is invalid');
  if (locator.control_origin !== undefined) validateText(locator.control_origin, 'control_origin', { max: 4096 });
  return locator;
}

function readLocator(locatorPath, secretMarkers = []) {
  const target = privateFile(locatorPath);
  let value;
  try {
    const bytes = readFileSync(target);
    const markers = markerBytes(secretMarkers);
    assertMarkerFree(bytes, markers, 'process locator');
    value = JSON.parse(bytes.toString('utf8'));
    assertMarkerFree(JSON.stringify(value), markers, 'process locator');
  } catch {
    throw new SeamError('locator_unreadable', 'locator could not be read');
  }
  return validateLocator(value);
}

function listPids() {
  if (process.platform === 'win32') return [];
  const result = spawnSync('ps', ['-axo', 'pid=,ppid=,pgid=,stat=,comm='], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.status !== 0 || typeof result.stdout !== 'string') return [];
  const entries = [];
  for (const line of result.stdout.split('\n')) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)\s*$/u.exec(line);
    if (!match) continue;
    entries.push({
      pid: Number(match[1]),
      ppid: Number(match[2]),
      pgid: Number(match[3]),
      stat: match[4],
      comm: match[5],
    });
  }
  return entries;
}

function processEntry(pid) {
  return listPids().find((entry) => entry.pid === pid) || null;
}

function processGroupEntries(pgid) {
  return listPids().filter((entry) => entry.pgid === pgid);
}

function processPresent(pid) {
  const entry = processEntry(pid);
  if (entry) return !entry.stat.includes('Z');
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error && error.code === 'EPERM';
  }
}

function processStartTimeUnixMs(pid) {
  if (process.platform === 'win32') return null;
  const result = spawnSync('ps', ['-p', String(pid), '-o', 'lstart='], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    maxBuffer: 8 * 1024,
  });
  if (result.status !== 0 || typeof result.stdout !== 'string') return null;
  const parsed = Date.parse(result.stdout.trim());
  return Number.isFinite(parsed) ? parsed : null;
}

function ownerMismatch() {
  return new SeamError('process_owner_mismatch', 'process owner identity does not match the locator');
}

/**
 * Validate the process named by a locator before sending a signal.  The
 * locator is user-controlled test input, so PID/PGID alone are never enough:
 * the original locator publication, process-group identity, command name,
 * executable digest, and a bounded start-time identity must all agree.
 *
 * A gone process group is an idempotent stop case and returns false.  If a
 * group still has members but its leader is gone, fail closed rather than
 * signalling a potentially reused PGID.
 */
async function validateProcessOwner(locator) {
  if (locator.process_group_id !== locator.pid) throw ownerMismatch();
  const entry = processEntry(locator.pid);
  const groupEntries = processGroupEntries(locator.process_group_id);
  if (!entry || entry.stat.includes('Z')) {
    // A reaped leader may remain as a zombie until its parent observes the
    // exit.  Zombies cannot receive a useful signal; only a live member makes
    // a missing leader an unsafe PGID-reuse ambiguity.
    const liveGroupEntries = groupEntries.filter((candidate) => !candidate.stat.includes('Z'));
    if (liveGroupEntries.length === 0 && !processPresent(locator.pid)) return false;
    throw ownerMismatch();
  }
  if (entry.pgid !== locator.process_group_id) throw ownerMismatch();
  if (basename(entry.comm.trim()) !== basename(locator.executable_path)) throw ownerMismatch();

  const startedAt = processStartTimeUnixMs(locator.pid);
  if (startedAt === null || Math.abs(startedAt - locator.started_at_unix_ms) > PROCESS_START_TIME_TOLERANCE_MS) {
    throw ownerMismatch();
  }

  let executableSha256;
  try {
    executableSha256 = await hashFile(locator.executable_path);
  } catch {
    throw ownerMismatch();
  }
  if (executableSha256 !== locator.executable_sha256) throw ownerMismatch();
  return true;
}

function sleep(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function sendGroupSignal(pgid, signal) {
  if (!Number.isSafeInteger(pgid) || pgid <= 1 || pgid === process.pid) {
    throw new SeamError('process_group_invalid', 'refusing to signal the current process group');
  }
  if (process.platform === 'win32') {
    throw new SeamError('platform_unsupported', 'process-group cleanup is unsupported on Windows');
  }
  try {
    process.kill(-pgid, signal);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    throw error;
  }
}

function parseTimeout(value, fallback = DEFAULT_TIMEOUT_MS) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > MAX_TIMEOUT_MS) {
    throw new SeamError('timeout_invalid', 'cleanup timeout is outside the bounded range');
  }
  return Math.floor(parsed);
}

function parsePoll(value, fallback = DEFAULT_POLL_MS) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 1_000) {
    throw new SeamError('poll_invalid', 'poll interval is outside the bounded range');
  }
  return Math.floor(parsed);
}

async function waitForGroupGone(pgid, pid, timeoutMs, pollMs, observed) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    const entries = processGroupEntries(pgid);
    for (const entry of entries) observed.add(entry.pid);
    if (entries.length === 0 && !processPresent(pid)) return true;
    await sleep(Math.min(pollMs, Math.max(1, deadline - Date.now())));
  }
  for (const entry of processGroupEntries(pgid)) observed.add(entry.pid);
  return !processPresent(pid) && processGroupEntries(pgid).length === 0;
}

function discoverLocatorByInstance(instanceId, locatorDir) {
  validateText(instanceId, 'instance_id', { max: 256 });
  const directory = privateDirectory(locatorDir || process.env.ZODE_E2E_PROCESS_LOCATOR_DIR || DEFAULT_REGISTRY);
  const expectedName = `${instanceId}.locator.json`;
  const direct = join(directory, expectedName);
  if (existsSync(direct)) return direct;
  // A caller may have supplied a nested locator directory to start.  Keep the
  // search bounded and only inspect files with the exact locator suffix.
  const queue = [directory];
  while (queue.length) {
    const current = queue.shift();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const candidate = join(current, entry.name);
      if (entry.isDirectory() && !entry.isSymbolicLink()) queue.push(candidate);
      else if (entry.isFile() && entry.name === expectedName) return candidate;
    }
  }
  throw new SeamError('locator_not_found', 'no locator exists for the instance_id');
}

function readBoundedFlushedLog(path) {
  const descriptor = openSync(path, 'r+');
  try {
    // Flush the file through the same descriptor that is used for the bounded
    // read.  This keeps the stop result a durable observation rather than a
    // best-effort read of a file that may still be buffered by the child.
    fsyncSync(descriptor);
    const initialSize = fstatSync(descriptor).size;
    if (!Number.isSafeInteger(initialSize) || initialSize > MAX_PROCESS_OUTPUT_BYTES) {
      throw new OutputBoundError();
    }
    const bytes = Buffer.alloc(initialSize);
    let offset = 0;
    while (offset < initialSize) {
      const count = readSync(descriptor, bytes, offset, initialSize - offset, offset);
      if (!Number.isSafeInteger(count) || count <= 0) {
        throw new SeamError('output_read_failed', 'child process output could not be read');
      }
      offset += count;
    }
    const finalSize = fstatSync(descriptor).size;
    if (!Number.isSafeInteger(finalSize) || finalSize > MAX_PROCESS_OUTPUT_BYTES) {
      throw new OutputBoundError();
    }
    if (finalSize !== initialSize) {
      throw new SeamError('output_changed', 'child process output changed during bounded flush');
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function flushLogs(locatorPath, markers) {
  try {
    return readProcessOutput(locatorPath, { secretMarkers: markers }).flush_status;
  } catch (error) {
    if (error instanceof SecretMarkerError) return 'secret_marker';
    if (error instanceof OutputBoundError) return 'bound_exceeded';
    return 'failed';
  }
}

/**
 * Durably snapshot the child output without changing its lifecycle.  This is
 * intentionally separate from stopProcess so a harness can seal output
 * before inspecting readiness, asserting behavior, or attempting cleanup.
 */
function readProcessOutput(locatorPath, options = {}) {
  const markers = configuredMarkers(options);
  const paths = logPaths(locatorPath);
  let stdout = Buffer.alloc(0);
  let stderr = Buffer.alloc(0);
  let available = 0;
  for (const [key, path] of [['stdout', paths.stdout], ['stderr', paths.stderr]]) {
    const target = privateFile(path);
    if (!existsSync(target)) continue;
    available += 1;
    const bytes = readBoundedFlushedLog(target);
    fsyncDirectory(dirname(target));
    assertMarkerFree(bytes, markers, 'child process output');
    if (key === 'stdout') stdout = bytes;
    else stderr = bytes;
  }
  return {
    stdout,
    stderr,
    flush_status: available === 2 ? 'ok' : available === 0 ? 'not_available' : 'failed',
  };
}

function exitStatusUnknown() {
  return { known: false, code: null, signal: null };
}

async function reapSpawnFailure(child, pid) {
  try { sendGroupSignal(pid, 'SIGKILL'); } catch {}
  if (!child || child.exitCode !== null) return;
  await new Promise((resolvePromise) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolvePromise();
    };
    child.once('exit', finish);
    setTimeout(finish, DEFAULT_TIMEOUT_MS);
  });
}

/**
 * Start a real child process and atomically publish its non-secret locator.
 *
 * The returned child is only useful when the caller keeps the Node process
 * alive.  CLI callers receive a detached child and use stopProcess by
 * instance_id; no production process imports this module.
 */
async function startProcess(options = {}) {
  const markers = configuredMarkers(options);
  if (options.requireCapture || options.capture !== undefined) {
    const capture = options.capture;
    if (!capture || capture.armed !== true || typeof capture.assertArmed !== 'function') {
      throw new SeamError('capture_not_armed', 'durable process capture must be armed before spawn');
    }
    try {
      capture.assertArmed();
    } catch {
      throw new SeamError('capture_not_armed', 'durable process capture must be armed before spawn');
    }
  }
  const executablePath = normalizeExecutable(options.executable ?? options.executablePath, markers);
  const role = validateText(options.role ?? 'supervisor', 'role');
  if (!PROCESS_ROLES.has(role)) {
    throw new SeamError('role_invalid', 'role must be supervisor, server, or endpoint');
  }
  const sessionId = validateText(options.sessionId ?? options.session_id ?? generatedInstanceId(), 'session_id');
  const requestedInstanceId = options.instanceId ?? options.instance_id;
  if (requestedInstanceId !== undefined
    && !/^zode-e2e-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(String(requestedInstanceId))) {
    throw new SeamError('instance_id_invalid', 'instance_id must be a generated zode-e2e UUID');
  }
  const instanceId = validateText(requestedInstanceId ?? generatedInstanceId(), 'instance_id', { max: 256 });
  const controlOrigin = options.controlOrigin ?? options.control_origin;
  if (controlOrigin !== undefined) validateText(controlOrigin, 'control_origin', { max: 4096 });
  assertMarkerFree(role, markers, 'process role');
  assertMarkerFree(sessionId, markers, 'process session_id');
  assertMarkerFree(instanceId, markers, 'process instance_id');
  if (controlOrigin !== undefined) assertMarkerFree(controlOrigin, markers, 'process control_origin');
  const args = options.args ?? [];
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    throw new SeamError('arguments_invalid', 'process args must be an array of strings');
  }
  const locatorPath = privateFile(options.locatorPath ?? defaultLocatorPath(instanceId, options.locatorDir));
  assertMarkerFree(locatorPath, markers, 'locator path');
  const publicationOwnerPath = privateFile(ownerPath(locatorPath));
  if (existsSync(locatorPath) || existsSync(publicationOwnerPath)) {
    throw new SeamError('locator_exists', 'locator path already exists');
  }
  const executableSha256 = await hashFile(executablePath);
  // Scan the executable bytes as well as the path.  This prevents a test
  // marker accidentally being persisted in a child artifact that is later
  // inspected alongside the locator.
  try {
    const bytes = readFileSync(executablePath);
    assertMarkerFree(bytes, markers, 'executable');
  } catch (error) {
    if (error instanceof SecretMarkerError) throw error;
    throw new SeamError('executable_unreadable', 'executable could not be read');
  }

  const logs = logPaths(locatorPath);
  const stdoutFd = openSync(logs.stdout, 'wx', 0o600);
  let stderrFd;
  try {
    stderrFd = openSync(logs.stderr, 'wx', 0o600);
  } catch (error) {
    closeSync(stdoutFd);
    try { rmSync(logs.stdout, { force: true }); } catch {}
    throw error;
  }

  let child;
  try {
    child = spawn(executablePath, args, {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      // Every managed child gets its own group.  This is what makes a stop
      // by instance_id bounded for a product that has forked helpers; callers
      // may opt out of unref via `detach: false`, but may not inherit the
      // harness process group.
      detached: true,
      stdio: ['ignore', stdoutFd, stderrFd],
    });
    closeSync(stdoutFd);
    closeSync(stderrFd);
  } catch (error) {
    try { closeSync(stdoutFd); } catch {}
    try { closeSync(stderrFd); } catch {}
    try { rmSync(logs.stdout, { force: true }); } catch {}
    try { rmSync(logs.stderr, { force: true }); } catch {}
    throw new SeamError('spawn_failed', 'real child process could not be started');
  }

  const pid = child.pid;
  if (!Number.isSafeInteger(pid) || pid <= 1) {
    try { child.kill('SIGKILL'); } catch {}
    throw new SeamError('spawn_failed', 'child process did not expose a valid pid');
  }
  const locator = {
    schema: PROCESS_LOCATOR_SCHEMA,
    instance_id: instanceId,
    role,
    pid,
    started_at_unix_ms: Date.now(),
    // detached=true creates a new process group on POSIX; Node exposes no
    // portable getter, and the leader PID is the process-group ID by design.
    process_group_id: pid,
    session_id: sessionId,
    executable_path: executablePath,
    executable_sha256: executableSha256,
    ...(controlOrigin === undefined ? {} : { control_origin: controlOrigin }),
  };
  try {
    assertMarkerFree(JSON.stringify(locator), markers, 'process locator');
  } catch (error) {
    await reapSpawnFailure(child, pid);
    try { rmSync(logs.stdout, { force: true }); } catch {}
    try { rmSync(logs.stderr, { force: true }); } catch {}
    throw error;
  }
  try {
    writePrivateJson(locatorPath, locator);
    writeOwnerMetadata(locatorPath, locator, markers);
  } catch (error) {
    await reapSpawnFailure(child, pid);
    try { rmSync(logs.stdout, { force: true }); } catch {}
    try { rmSync(logs.stderr, { force: true }); } catch {}
    removeOwnPublication(locatorPath, locator);
    throw new SeamError('locator_write_failed', 'process locator could not be published');
  }

  activeChildren.set(instanceId, child);
  child.once('exit', (code, signal) => {
    child.__zodeSeamExitStatus = { known: true, code: code ?? null, signal: signal ?? null };
  });
  if (options.detach !== false) child.unref();
  const result = { locator, locatorPath, child };
  if (options.emitReady) process.stdout.write(`${READY_PREFIX}${locatorPath}\n`);
  return result;
}

/**
 * Stop the process group named by a locator.  The function intentionally uses
 * the PID only as a locator: it never treats a PID as release health evidence
 * or as a substitute for an executable digest/HTTP probe.
 */
async function stopProcess(options = {}) {
  const markers = configuredMarkers(options);
  const locatorPath = options.locatorPath
    ? resolve(options.locatorPath)
    : discoverLocatorByInstance(options.instanceId ?? options.instance_id, options.locatorDir);
  const locator = readLocator(locatorPath, markers);
  const ownerLocator = readOwnerMetadata(locatorPath, markers);
  if (!locatorValuesEqual(ownerLocator, locator)) throw ownerMismatch();
  const requestedInstanceId = options.instanceId ?? options.instance_id;
  if (requestedInstanceId !== undefined && requestedInstanceId !== locator.instance_id) {
    throw new SeamError('instance_mismatch', 'locator instance_id does not match the requested instance_id');
  }
  const timeoutMs = parseTimeout(options.timeoutMs ?? options.timeout_ms);
  const pollMs = parsePoll(options.pollMs ?? options.poll_ms);
  const observed = new Set([locator.pid]);
  for (const entry of processGroupEntries(locator.process_group_id)) observed.add(entry.pid);
  let timedOut = false;
  let signal = null;
  let exitStatus = activeChildren.get(locator.instance_id)?.__zodeSeamExitStatus || exitStatusUnknown();
  try {
    const ownerPresent = await validateProcessOwner(locator);
    if (ownerPresent) {
      signal = 'SIGTERM';
      sendGroupSignal(locator.process_group_id, signal);
      const gone = await waitForGroupGone(locator.process_group_id, locator.pid, timeoutMs, pollMs, observed);
      if (!gone) {
        timedOut = true;
        signal = 'SIGKILL';
        sendGroupSignal(locator.process_group_id, signal);
        await waitForGroupGone(locator.process_group_id, locator.pid, timeoutMs, pollMs, observed);
      }
    }
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error;
  }

  for (const entry of processGroupEntries(locator.process_group_id)) observed.add(entry.pid);
  const observedPids = [...observed].filter((pid) => Number.isSafeInteger(pid) && pid > 1).sort((a, b) => a - b);
  const leakedPids = observedPids.filter((pid) => processPresent(pid));
  const reapedPids = observedPids.filter((pid) => !leakedPids.includes(pid));
  const activeChild = activeChildren.get(locator.instance_id);
  if (activeChild?.__zodeSeamExitStatus) exitStatus = activeChild.__zodeSeamExitStatus;
  const flushStatus = flushLogs(locatorPath, markers);
  const result = {
    schema: PROCESS_STOP_SCHEMA,
    instance_id: locator.instance_id,
    observed_pids: observedPids,
    reaped_pids: reapedPids,
    leaked_pids: leakedPids,
    timed_out: timedOut || leakedPids.length > 0,
    exit_status: {
      ...exitStatus,
      signal,
    },
    flush_status: flushStatus,
  };
  activeChildren.delete(locator.instance_id);
  return result;
}

function parseJsonOption(raw, label) {
  try {
    const value = JSON.parse(raw);
    return value;
  } catch {
    throw new SeamError('arguments_invalid', `${label} is not valid JSON`);
  }
}

function parseCli(argv) {
  const command = argv.shift();
  const options = { args: [], secretMarkers: [] };
  const positional = [];
  let passThrough = false;
  while (argv.length) {
    const argument = argv.shift();
    if (passThrough) {
      options.args.push(argument);
      continue;
    }
    if (argument === '--') {
      passThrough = true;
      continue;
    }
    if (!argument.startsWith('--')) {
      positional.push(argument);
      continue;
    }
    const equals = argument.indexOf('=');
    const key = (equals < 0 ? argument.slice(2) : argument.slice(2, equals)).replace(/-/g, '_');
    const inline = equals < 0 ? undefined : argument.slice(equals + 1);
    const needsValue = !['json', 'detach', 'no_detach', 'help'].includes(key);
    const value = needsValue ? (inline ?? argv.shift()) : inline;
    if (needsValue && value === undefined) throw new SeamError('arguments_invalid', `--${key} requires a value`);
    switch (key) {
      case 'role': options.role = value; break;
      case 'session_id': options.sessionId = value; break;
      case 'instance_id': options.instanceId = value; break;
      case 'control_origin': options.controlOrigin = value; break;
      case 'executable':
      case 'executable_path': options.executable = value; break;
      case 'cwd': options.cwd = value; break;
      case 'locator':
      case 'locator_path': options.locatorPath = value; break;
      case 'locator_dir': options.locatorDir = value; break;
      case 'timeout_ms': options.timeoutMs = value; break;
      case 'poll_ms': options.pollMs = value; break;
      case 'secret_marker': options.secretMarkers.push(value); break;
      case 'secret_markers_json': {
        const markers = parseJsonOption(value, 'secret_markers_json');
        if (!Array.isArray(markers) || markers.some((marker) => typeof marker !== 'string')) {
          throw new SeamError('arguments_invalid', 'secret_markers_json must be an array of strings');
        }
        options.secretMarkers.push(...markers);
        break;
      }
      case 'args_json': {
        const args = parseJsonOption(value, 'args_json');
        if (!Array.isArray(args) || args.some((item) => typeof item !== 'string')) {
          throw new SeamError('arguments_invalid', 'args_json must be an array of strings');
        }
        options.args.push(...args);
        break;
      }
      case 'env_json': {
        const env = parseJsonOption(value, 'env_json');
        if (!env || typeof env !== 'object' || Array.isArray(env) || Object.entries(env).some(([key, item]) => typeof key !== 'string' || typeof item !== 'string')) {
          throw new SeamError('arguments_invalid', 'env_json must be an object of string values');
        }
        options.env = env;
        break;
      }
      case 'detach': options.detach = true; break;
      case 'no_detach': options.detach = false; break;
      case 'json': options.json = true; break;
      case 'help': options.help = true; break;
      default: throw new SeamError('arguments_invalid', `unknown option --${key}`);
    }
  }
  if (positional.length) {
    if (!options.executable && (command === 'start' || command === 'launch')) options.executable = positional.shift();
    if (!options.instanceId && (command === 'stop' || command === 'terminate')) options.instanceId = positional.shift();
  }
  if (positional.length) options.args.push(...positional);
  return { command, options };
}

function usage() {
  return [
    'usage:',
    '  process_seam.cjs start --role ROLE --session-id ID --executable PATH [--args-json JSON] [--locator-dir DIR]',
    '  process_seam.cjs stop --instance-id INSTANCE_ID [--locator PATH|--locator-dir DIR] [--timeout-ms N]',
    '  process_seam.cjs read --locator PATH',
    '',
    `start stdout: ${READY_PREFIX}<absolute locator.json>`,
    `stop stdout schema: ${PROCESS_STOP_SCHEMA}`,
  ].join('\n');
}

async function cli(argv = process.argv.slice(2)) {
  if (!argv.length || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  const { command, options } = parseCli([...argv]);
  if (command === 'start' || command === 'launch') {
    const result = await startProcess({ ...options, emitReady: true });
    // A readiness line is the only stdout emitted by start.  The locator is
    // already fsync'd before this write, so consumers can open it immediately.
    return result;
  }
  if (command === 'stop' || command === 'terminate') {
    const result = await stopProcess(options);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return result.timed_out
      || result.leaked_pids.length
      || result.flush_status !== 'ok'
      ? 1
      : 0;
  }
  if (command === 'read' || command === 'inspect') {
    if (!options.locatorPath) throw new SeamError('arguments_invalid', '--locator is required');
    const locator = readLocator(options.locatorPath, configuredMarkers(options));
    process.stdout.write(`${JSON.stringify(locator)}\n`);
    return 0;
  }
  throw new SeamError('arguments_invalid', `unknown command ${command}`);
}

if (require.main === module) {
  cli().then((result) => {
    if (typeof result === 'number') process.exitCode = result;
  }).catch((error) => {
    const safe = error instanceof SeamError ? error : new SeamError('seam_failed', 'process seam failed');
    process.stderr.write(`${JSON.stringify({ error: { code: safe.code, message: safe.message } })}\n`);
    process.exitCode = safe.code === 'locator_not_found' ? 3 : 2;
  });
}

module.exports = {
  DEFAULT_REGISTRY,
  MAX_PROCESS_OUTPUT_BYTES,
  PROCESS_LOCATOR_SCHEMA,
  PROCESS_STOP_SCHEMA,
  READY_PREFIX,
  SeamError,
  SecretMarkerError,
  cli,
  readLocator,
  readProcessOutput,
  startProcess,
  stopProcess,
};
