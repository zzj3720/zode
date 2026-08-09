'use strict';

const {
  createHash,
  createSign,
  generateKeyPairSync,
  randomUUID,
} = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { once } = require('node:events');
const { promisify } = require('node:util');

const ROOT = path.resolve(__dirname, '../../..');
const READY_TIMEOUT_MS = 15_000;
const HTTP_TIMEOUT_MS = 8_000;
const PROCESS_STOP_TIMEOUT_MS = 3_000;
const MAX_RECORDING_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_RECORDING_CHUNKS = 4_096;
const MAX_RECORDING_REQUEST_BYTES = 4 * 1024 * 1024;
const MAX_RECORDING_RAW_BYTES = 40 * 1024 * 1024;
const MAX_STARTUP_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_STARTUP_TOTAL_BYTES = 16 * 1024 * 1024;
const REPLAY_RESULTS_TOKEN = Symbol('zode-replay-results-token');
const execFileAsync = promisify(execFile);
const PROCESS_SEAM_PATH = path.join(ROOT, 'tests', 'support', 'process_seam.cjs');
let processSeam;
try {
  // The process seam owns locator publication, process-group cleanup and
  // bounded reap evidence.  The browser harness only adapts its public API.
  processSeam = require(PROCESS_SEAM_PATH);
} catch {
  processSeam = undefined;
}

class HarnessFailure extends Error {
  constructor(classification, message, details = {}) {
    super(message);
    this.name = 'HarnessFailure';
    this.classification = classification;
    this.details = details;
  }
}

class ProductRouteMissing extends HarnessFailure {
  constructor({ path: routePath, status, surface }) {
    super(
      'PRODUCT_ROUTE_MISSING_SHALLOW_404',
      `${surface} route is missing (${status}) at ${routePath}; shallow 404 is not product behavior evidence`,
      { path: routePath, status, surface, nonEvidence: true },
    );
    this.name = 'ProductRouteMissing';
  }
}

class ProductBehaviorFailure extends HarnessFailure {
  constructor(classification, message, details = {}) {
    super(classification, message, details);
    this.name = 'ProductBehaviorFailure';
  }
}

class SecretLeakFailure extends HarnessFailure {
  constructor(surface, label) {
    super('SECRET_DISCLOSURE', `secret marker detected in ${surface} (${label})`, {
      surface,
      label,
    });
    this.name = 'SecretLeakFailure';
  }
}

class SecretLedger {
  constructor() {
    this.entries = new Map();
  }

  add(label, value, { allowDuplicate = false, derive = true } = {}) {
    if (typeof value !== 'string' || value.length === 0) return;
    const addEntry = (entryLabel, entryValue, derived = false) => {
      if (!entryValue || (!allowDuplicate && [...this.entries.values()].some((entry) => entry.value === entryValue))) return;
      this.entries.set(`${entryLabel}:${this.entries.size}`, {
        label: entryLabel,
        value: entryValue,
        derived,
      });
    };
    addEntry(label, value);
    if (!derive) return;
    const bytes = Buffer.from(value, 'utf8');
    addEntry(`${label}_base64`, bytes.toString('base64'), true);
    addEntry(`${label}_base64url`, bytes.toString('base64url'), true);
    addEntry(`${label}_hex`, bytes.toString('hex'), true);
    addEntry(`${label}_uri`, encodeURIComponent(value), true);
  }

  addQuerySlot(label, wireValue) {
    // Query slots retain the exact bytes sent on the public edge (including
    // percent escapes and `+` separators), so restore() can reproduce the
    // browser's request-target byte-for-byte.  Each occurrence is unique even
    // when duplicate query values are identical.
    this.add(label, wireValue, { allowDuplicate: true, derive: false });
  }

  find(value) {
    if (value === undefined || value === null) return undefined;
    const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
    return [...this.entries.values()]
      .filter((entry) => entry.value && text.includes(entry.value))
      .sort((left, right) => right.value.length - left.value.length)[0];
  }

  redact(value, { preferredLabel } = {}) {
    let text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value ?? '');
    const preferred = preferredLabel
      ? [...this.entries.values()].find((entry) => entry.label === preferredLabel)
      : undefined;
    if (preferred) text = text.split(preferred.value).join(`<secret:${preferred.label}>`);
    for (const entry of [...this.entries.values()]
      .filter((candidate) => candidate !== preferred)
      .sort((left, right) => right.value.length - left.value.length)) {
      text = text.split(entry.value).join(`<secret:${entry.label}>`);
    }
    return text;
  }

  restore(value) {
    let text = String(value ?? '');
    for (const entry of this.entries.values()) {
      text = text.split(`<secret:${entry.label}>`).join(entry.value);
    }
    return text;
  }
}

function ensureDirectory(directory, mode = 0o700) {
  fs.mkdirSync(directory, { recursive: true, mode });
  try {
    fs.chmodSync(directory, mode);
  } catch {}
  return directory;
}

function fsyncFileDescriptor(fd) {
  try {
    fs.fsyncSync(fd);
  } catch (error) {
    throw new HarnessFailure('RECORDING_FLUSH_FAILURE', 'recording bytes could not be durably flushed', {
      cause: error instanceof Error ? error.message : String(error),
    });
  }
}

function fsyncDirectory(directory) {
  let fd;
  try {
    const flags = fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0);
    fd = fs.openSync(directory, flags);
    fs.fsyncSync(fd);
  } catch (error) {
    throw new HarnessFailure('RECORDING_FLUSH_FAILURE', 'recording directory could not be durably flushed', {
      directory,
      cause: error instanceof Error ? error.message : String(error),
    });
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function writeDurable(fd, bytes) {
  const payload = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  let written = 0;
  while (written < payload.length) written += fs.writeSync(fd, payload, written, payload.length - written);
  fsyncFileDescriptor(fd);
}

function replaceBufferOccurrences(value, needle, replacement) {
  if (!needle.length) return Buffer.from(value);
  const source = Buffer.from(value);
  const parts = [];
  let offset = 0;
  for (;;) {
    const index = source.indexOf(needle, offset);
    if (index < 0) {
      parts.push(source.subarray(offset));
      break;
    }
    parts.push(source.subarray(offset, index), replacement);
    offset = index + needle.length;
  }
  return Buffer.concat(parts);
}

function redactBuffer(value, ledger) {
  let bytes = Buffer.from(value || '');
  for (const entry of [...ledger.entries.values()].sort((left, right) => right.value.length - left.value.length)) {
    bytes = replaceBufferOccurrences(bytes, Buffer.from(entry.value), Buffer.from(`<secret:${entry.label}>`));
  }
  return bytes;
}

function restoreBuffer(value, ledger) {
  let bytes = Buffer.from(value || '');
  for (const entry of ledger.entries.values()) {
    bytes = replaceBufferOccurrences(bytes, Buffer.from(`<secret:${entry.label}>`), Buffer.from(entry.value));
  }
  return bytes;
}

function writePrivateFile(filePath, content) {
  ensureDirectory(path.dirname(filePath));
  const fd = fs.openSync(filePath, 'wx', 0o600);
  try {
    writeDurable(fd, Buffer.from(content, 'utf8'));
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(filePath, 0o600);
  fsyncDirectory(path.dirname(filePath));
  return filePath;
}

function replacePrivateJson(filePath, value) {
  ensureDirectory(path.dirname(filePath));
  const temporary = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
  const fd = fs.openSync(temporary, 'wx', 0o600);
  try {
    writeDurable(fd, `${JSON.stringify(value, null, 2)}\n`);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(temporary, 0o600);
  fs.renameSync(temporary, filePath);
  fs.chmodSync(filePath, 0o600);
  fsyncDirectory(path.dirname(filePath));
  return filePath;
}

function writeJsonPrivate(filePath, value) {
  return writePrivateFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readDurableBounded(filePath, maxBytes) {
  const descriptor = fs.openSync(filePath, 'r+');
  try {
    fsyncFileDescriptor(descriptor);
    const initialSize = fs.fstatSync(descriptor).size;
    if (!Number.isSafeInteger(initialSize) || initialSize > maxBytes) {
      throw new HarnessFailure('BOUND_EXCEEDED', 'process output exceeded its bounded capture size');
    }
    const bytes = Buffer.alloc(initialSize);
    let offset = 0;
    while (offset < initialSize) {
      const count = fs.readSync(descriptor, bytes, offset, initialSize - offset, offset);
      if (!Number.isSafeInteger(count) || count <= 0) {
        throw new HarnessFailure('RECORDING_FLUSH_FAILURE', 'process output could not be durably read');
      }
      offset += count;
    }
    const finalSize = fs.fstatSync(descriptor).size;
    if (finalSize !== initialSize || finalSize > maxBytes) {
      throw new HarnessFailure('RECORDING_FLUSH_FAILURE', 'process output changed during durable capture');
    }
    fsyncDirectory(path.dirname(filePath));
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

class StartupCapture {
  constructor({ root, role, e2eName, configBytes, ledger }) {
    this.ledger = ledger;
    this.role = role;
    this.e2eName = e2eName || 'web-e2e-process-startup';
    this.recordingId = `process-${role}-${randomUUID()}`;
    this.configBytes = Buffer.from(configBytes || '');
    const marker = ledger?.find(this.configBytes);
    if (marker) throw new SecretLeakFailure('startup config', marker.label);
    const identityMarker = ledger?.find(this.e2eName || '');
    if (identityMarker) throw new SecretLeakFailure('startup capture identity', identityMarker.label);
    const roleMarker = ledger?.find(this.role || '');
    if (roleMarker) throw new SecretLeakFailure('startup capture role', roleMarker.label);
    this.directory = ensureDirectory(path.join(root, `${role}-${randomUUID()}`));
    this.configPath = path.join(this.directory, 'config.json');
    this.armPath = path.join(this.directory, 'arm.v1.json');
    this.observationPath = path.join(this.directory, 'process-observation.v1.json');
    this.armed = false;
    this.lastObservation = undefined;
    // Config capture is sealed before the child can be spawned.
    writePrivateFile(this.configPath, this.configBytes);
  }

  arm() {
    if (this.armed) return this;
    const arm = {
      schema: 'zode.e2e.process-capture-arm.v1',
      version: 1,
      recording_id: this.recordingId,
      e2e_name: this.e2eName,
      role: this.role,
      armed_at_unix_ms: Date.now(),
    };
    writePrivateFile(this.armPath, `${JSON.stringify(arm, null, 2)}\n`);
    this.armed = true;
    return this;
  }

  assertArmed() {
    if (!this.armed || !fs.existsSync(this.armPath) || !fs.existsSync(this.configPath)) {
      throw new HarnessFailure('PROCESS_CAPTURE_NOT_ARMED', 'durable process capture must be armed before spawn', {
        role: this.role,
      });
    }
    return true;
  }

  captureProcessObservation(processHandle, { phase = 'observation', stopResult } = {}) {
    this.assertArmed();
    const phaseMarker = this.ledger?.find(phase || '');
    if (phaseMarker) throw new SecretLeakFailure('startup observation phase', phaseMarker.label);
    if (!processHandle?.locatorPath) {
      throw new HarnessFailure('PROCESS_CAPTURE_OBSERVATION_FAILURE', 'real process has no locator for durable observation', {
        role: this.role,
      });
    }
    let output;
    let readError;
    const markers = [...(this.ledger?.entries?.values?.() || [])].map((entry) => entry.value);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        output = processSeam?.readProcessOutput
          ? processSeam.readProcessOutput(processHandle.locatorPath, { secretMarkers: markers })
          : (() => {
            const stdoutPath = `${processHandle.locatorPath}.stdout.log`;
            const stderrPath = `${processHandle.locatorPath}.stderr.log`;
            const stdoutExists = fs.existsSync(stdoutPath);
            const stderrExists = fs.existsSync(stderrPath);
            return {
              stdout: stdoutExists ? readDurableBounded(stdoutPath, MAX_STARTUP_OUTPUT_BYTES) : Buffer.alloc(0),
              stderr: stderrExists ? readDurableBounded(stderrPath, MAX_STARTUP_OUTPUT_BYTES) : Buffer.alloc(0),
              flush_status: stdoutExists && stderrExists ? 'ok' : stdoutExists || stderrExists ? 'failed' : 'not_available',
            };
          })();
        readError = undefined;
        break;
      } catch (error) {
        readError = error;
        // A child can append between the initial size read and the final
        // consistency check.  A small bounded retry preserves fail-closed
        // bounds/marker handling without turning ordinary startup output into
        // a readiness timeout.
        if (error?.code !== 'output_changed' || attempt === 2) break;
      }
    }
    if (readError) {
      const error = readError;
      if (error?.code === 'output_bound_exceeded') {
        throw new HarnessFailure('BOUND_EXCEEDED', 'process output exceeded its bounded capture size', { role: this.role });
      }
      if (error?.code === 'secret_marker') {
        throw new SecretLeakFailure('startup process output', 'process_output');
      }
      throw error instanceof HarnessFailure
        ? error
        : new HarnessFailure('PROCESS_CAPTURE_OBSERVATION_FAILURE', 'process output could not be durably observed', { role: this.role });
    }
    // A readiness/exit/stop barrier is not allowed to proceed on a missing
    // sidecar.  The process seam creates both files before spawn, so
    // `not_available` means the durable quarantine was lost or never armed.
    if (!output || output.flush_status !== 'ok') {
      throw new HarnessFailure('PROCESS_OUTPUT_FLUSH_FAILURE', 'process output was not durably flushed', {
        role: this.role,
        flushStatus: output?.flush_status || 'not_available',
      });
    }
    const bytes = Buffer.concat([output.stdout || Buffer.alloc(0), output.stderr || Buffer.alloc(0)]);
    if (bytes.length > MAX_STARTUP_TOTAL_BYTES) {
      throw new HarnessFailure('BOUND_EXCEEDED', 'process output exceeded its bounded quarantine size', {
        role: this.role,
      });
    }
    const marker = this.ledger?.find(bytes);
    if (marker) throw new SecretLeakFailure('startup process output', marker.label);
    const child = processHandle.child;
    const stopExit = stopResult?.exit_status;
    const knownExit = Boolean(
      (child && (child.exitCode !== null || child.signalCode !== null))
      || stopExit?.known === true,
    );
    const observation = {
      schema: 'zode.e2e.process-observation.v1',
      version: 1,
      recording_id: this.recordingId,
      e2e_name: this.e2eName,
      role: this.role,
      phase,
      observed_at_unix_ms: Date.now(),
      process: {
        instance_id: processHandle.locator?.instance_id,
        pid: processHandle.locator?.pid,
        process_group_id: processHandle.locator?.process_group_id,
      },
      stdout_hex: Buffer.from(output.stdout || '').toString('hex'),
      stderr_hex: Buffer.from(output.stderr || '').toString('hex'),
      exit_status: {
        known: Boolean(knownExit),
        code: knownExit ? (child?.exitCode ?? stopExit?.code ?? null) : null,
        signal: knownExit ? (child?.signalCode ?? stopExit?.signal ?? null) : null,
      },
      flush_status: output.flush_status,
      ...(stopResult ? {
        stop: {
          observed_pids: Array.isArray(stopResult.observed_pids) ? stopResult.observed_pids : [],
          reaped_pids: Array.isArray(stopResult.reaped_pids) ? stopResult.reaped_pids : [],
          leaked_pids: Array.isArray(stopResult.leaked_pids) ? stopResult.leaked_pids : [],
          timed_out: Boolean(stopResult.timed_out),
          flush_status: stopResult.flush_status || 'not_available',
        },
      } : {}),
    };
    replacePrivateJson(this.observationPath, observation);
    this.lastObservation = observation;
    return observation;
  }

  recoverProcessObservation({ locatorPath, locator, phase = 'recovered' } = {}) {
    const recovered = {
      locatorPath,
      locator: locator || (locatorPath && processSeam?.readLocator(locatorPath)),
      child: undefined,
    };
    return this.captureProcessObservation(recovered, { phase });
  }

  async flushFailure({ process, failure, stopError }) {
    if (process?.locatorPath && this.armed) {
      this.captureProcessObservation(process, {
        phase: 'failure',
        stopResult: process.stopResult,
      });
    }
    const stdoutPath = process?.locatorPath ? `${process.locatorPath}.stdout.log` : undefined;
    const stderrPath = process?.locatorPath ? `${process.locatorPath}.stderr.log` : undefined;
    const stdout = stdoutPath && fs.existsSync(stdoutPath)
      ? readDurableBounded(stdoutPath, MAX_STARTUP_OUTPUT_BYTES)
      : Buffer.alloc(0);
    const stderr = stderrPath && fs.existsSync(stderrPath)
      ? readDurableBounded(stderrPath, MAX_STARTUP_OUTPUT_BYTES)
      : Buffer.alloc(0);
    if (stdout.length + stderr.length > MAX_STARTUP_TOTAL_BYTES) {
      throw new HarnessFailure('BOUND_EXCEEDED', 'startup process output exceeded its bounded capture size', { role: this.role });
    }
    const marker = this.ledger?.find(Buffer.concat([stdout, stderr]));
    if (marker) throw new SecretLeakFailure('startup process output', marker.label);
    let exit;
    try {
      exit = await withTimeout(process?.exitPromise || Promise.resolve({ code: null, signal: null }), PROCESS_STOP_TIMEOUT_MS, 'startup process exit status timed out');
    } catch {
      exit = { code: null, signal: null };
    }
    const termination = stopError?.classification || failure?.classification || 'PROCESS_STARTUP_FAILURE';
    const stop = process?.stopResult || {
      observed_pids: [],
      reaped_pids: [],
      leaked_pids: [],
      timed_out: false,
      flush_status: 'not_available',
    };
    const stopProof = stop.flush_status === 'ok'
      && !stop.timed_out
      && !(stop.leaked_pids || []).length
      && Array.isArray(stop.observed_pids)
      && stop.observed_pids.length > 0
      && Array.isArray(stop.reaped_pids)
      && stop.reaped_pids.length > 0;
    const files = {
      stdout: path.join(this.directory, 'stdout.log'),
      stderr: path.join(this.directory, 'stderr.log'),
      exit: path.join(this.directory, 'exit.json'),
      termination: path.join(this.directory, 'termination.json'),
    };
    writePrivateFile(files.stdout, stdout);
    writePrivateFile(files.stderr, stderr);
    writeJsonPrivate(files.exit, { code: exit?.code ?? null, signal: exit?.signal ?? null });
    writeJsonPrivate(files.termination, termination);
    if (!stopProof) {
      throw new HarnessFailure(
        'PROCESS_CAPTURE_REAP_FAILURE',
        'startup evidence was retained without a promotable process-stop proof',
        { role: this.role, quarantinePath: this.directory, stopError: stopError?.message },
      );
    }
    const envelopeWithoutDigest = {
      schema: 'zode.process-incident-recording.v1',
      version: 1,
      recording_id: this.recordingId,
      e2e_name: this.e2eName,
      classification: failure?.classification || 'PROCESS_STARTUP_FAILURE',
      first_observed: failure?.classification || 'PROCESS_STARTUP_FAILURE',
      config: {
        label: `${this.role}-config`,
        bytes_hex: this.configBytes.toString('hex'),
        sha256: sha256(this.configBytes),
      },
      processes: [{
        name: this.role,
        stdout_hex: stdout.toString('hex'),
        stderr_hex: stderr.toString('hex'),
        exit_code: exit?.code ?? null,
        signal: exit?.signal ?? null,
        termination,
        stop: {
          observed_pids: Array.isArray(stop.observed_pids) ? stop.observed_pids : [],
          reaped_pids: Array.isArray(stop.reaped_pids) ? stop.reaped_pids : [],
          leaked_pids: Array.isArray(stop.leaked_pids) ? stop.leaked_pids : [],
          timed_out: Boolean(stop.timed_out),
          flush_status: stop.flush_status || 'not_available',
          proof: stopProof,
        },
      }],
    };
    const unsigned = { ...envelopeWithoutDigest, integrity_sha256: '' };
    const envelope = {
      ...envelopeWithoutDigest,
      integrity_sha256: sha256(JSON.stringify(unsigned)),
    };
    const envelopePath = path.join(this.directory, 'capture.v1.json');
    writeJsonPrivate(envelopePath, envelope);
    return envelopePath;
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function withTimeout(promise, timeoutMs, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    timer.unref?.();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function readyFromLog(logPath, prefix) {
  if (!fs.existsSync(logPath)) return undefined;
  let text;
  try {
    text = fs.readFileSync(logPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return undefined;
    throw error;
  }
  const line = text.split(/\r?\n/u).find((candidate) => candidate.startsWith(prefix));
  return line ? line.slice(prefix.length).trim() : undefined;
}

// A child can emit its final bytes and close in the same turn in which Node
// delivers the `exit` event.  The process seam has already fsync'd the
// sidecar before this poll starts; the short bounded retry only closes the
// visibility window between that durable snapshot and the file becoming
// observable to the readiness reader.  Never wait indefinitely after exit.
async function readyAfterExit(logPath, prefix, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  do {
    const value = readyFromLog(logPath, prefix);
    if (value) return value;
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await new Promise((resolve) => setTimeout(resolve, Math.min(5, remaining)));
  } while (Date.now() <= deadline);
  return undefined;
}

async function waitForReadyLog(logPath, prefix, timeoutMs = READY_TIMEOUT_MS, beforeRead) {
  const read = async () => {
    if (beforeRead) await beforeRead();
    return readyFromLog(logPath, prefix);
  };
  const immediate = await read();
  if (immediate) return immediate;
  const parent = path.dirname(logPath);
  ensureDirectory(parent);
  let watcher;
  let settled = false;
  let checking = false;
  const closeWatcher = () => {
    try { watcher?.close(); } catch {}
  };
  const pending = new Promise((resolve, reject) => {
    const check = async () => {
      if (settled || checking) return;
      checking = true;
      try {
        // Re-snapshot output before reading the readiness line.  This makes
        // durable quarantine the prerequisite for a readiness barrier.
        const value = await read();
        if (value) {
          settled = true;
          closeWatcher();
          resolve(value);
        }
      } catch (error) {
        settled = true;
        closeWatcher();
        reject(error);
      } finally {
        checking = false;
      }
    };
    try {
      watcher = fs.watch(parent, { persistent: false }, () => { void check(); });
      // The write may have happened between the immediate read and watcher
      // registration; this post-registration check closes that lost-event
      // window deterministically.
      void check();
    } catch (error) {
      settled = true;
      reject(error);
    }
  });
  try {
    return await withTimeout(pending, timeoutMs, `${prefix.trim()} readiness timed out`);
  } finally {
    settled = true;
    closeWatcher();
  }
}

class Barrier {
  constructor(label) {
    this.label = label;
    this.waiters = new Set();
  }

  notify(value) {
    for (const waiter of this.waiters) waiter(value);
    this.waiters.clear();
  }

  wait(timeoutMs = HTTP_TIMEOUT_MS) {
    return withTimeout(
      new Promise((resolve) => this.waiters.add(resolve)),
      timeoutMs,
      `${this.label} barrier timed out`,
    );
  }
}

async function startHttpServer(handler) {
  const failures = [];
  const server = http.createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch((error) => {
      failures.push(error);
      if (!response.headersSent) response.writeHead(500, { 'content-type': 'application/json' });
      if (!response.writableEnded) response.end(JSON.stringify({ error: { code: 'fixture_failed', retryable: false } }));
    });
  });
  server.on('clientError', (error, socket) => socket.destroy(error));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('fixture did not receive a TCP address');
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
    failures,
    get failure() { return failures[0]; },
    async close() {
      if (!server.listening) return;
      server.closeAllConnections?.();
      await withTimeout(new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }), PROCESS_STOP_TIMEOUT_MS, 'fixture server did not stop within the bounded timeout');
      if (failures[0]) throw failures[0];
    },
  };
}

function readRequestBody(request, maxBytes = 4 * 1024 * 1024, onChunk) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    request.on('data', (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        try {
          const remaining = Math.max(0, maxBytes - (total - chunk.length));
          if (remaining > 0) onChunk?.(chunk.subarray(0, remaining));
        } catch (error) {
          fail(error);
          request.destroy();
          return;
        }
        fail(new HarnessFailure('BOUND_EXCEEDED', 'fixture request exceeded its bounded body size'));
        request.destroy();
        return;
      }
      try { onChunk?.(chunk); } catch (error) {
        fail(error);
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks));
      }
    });
    request.on('error', (error) => fail(error));
    request.on('aborted', () => fail(new Error('fixture request was aborted')));
  });
}

function publicHeaders(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers || {})) {
    if (![
      'accept', 'content-type', 'cache-control', 'forwarded', 'host', 'idempotency-key', 'last-event-id',
      'origin', 'user-agent', 'x-forwarded-host',
    ].includes(name.toLowerCase())) continue;
    result[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return result;
}

function redactedPath(rawPath, ledger) {
  const input = String(rawPath ?? '');
  try {
    const parsed = new URL(input, 'http://fixture.invalid');
    const queryStart = input.indexOf('?');
    const fragmentStart = queryStart >= 0 ? input.indexOf('#', queryStart) : -1;
    const rawQuery = queryStart >= 0
      ? input.slice(queryStart + 1, fragmentStart >= 0 ? fragmentStart : input.length)
      : '';
    if (queryStart < 0 || rawQuery.length === 0) return ledger.redact(`${parsed.pathname}${parsed.search}`);

    const sensitiveMarkers = [
      'ticket', 'code', 'state', 'token', 'secret', 'authorization', 'assertion',
      'bearer', 'credential', 'password', 'key',
    ];
    const occurrences = new Map();
    const redactedQuery = rawQuery.split('&').map((pair) => {
      const equals = pair.indexOf('=');
      if (equals < 0) return pair;
      const rawKey = pair.slice(0, equals);
      const rawValue = pair.slice(equals + 1);
      if (!rawValue) return pair;
      let decodedKey = rawKey;
      try { decodedKey = decodeURIComponent(rawKey.replace(/\+/gu, ' ')); } catch {}
      const lowered = decodedKey.toLowerCase();
      if (!sensitiveMarkers.some((marker) => lowered.includes(marker))) return pair;
      const slug = (lowered.replace(/[^a-z0-9]+/gu, '_').replace(/^_+|_+$/gu, '') || 'value').slice(0, 48);
      const occurrence = occurrences.get(slug) || 0;
      occurrences.set(slug, occurrence + 1);
      const label = `query_${slug}_${occurrence}`;
      ledger.addQuerySlot(label, rawValue);
      return `${rawKey}=${ledger.redact(rawValue, { preferredLabel: label })}`;
    }).join('&');
    const pathPrefix = parsed.pathname;
    return ledger.redact(`${pathPrefix}?${redactedQuery}`);
  } catch {
    return ledger.redact(input);
  }
}

function safeBody(body, ledger) {
  const bytes = redactBuffer(body, ledger);
  const text = bytes.toString('utf8');
  let canonical;
  try {
    canonical = JSON.parse(text);
  } catch {}
  return {
    raw_base64: bytes.toString('base64'),
    ...(canonical === undefined ? {} : { canonical_json: canonical }),
    sha256: sha256(bytes),
  };
}

function decodeBase64Strict(value, label, maxBytes) {
  if (typeof value !== 'string' || value.length % 4 === 1
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', `${label} was not canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) {
    throw new HarnessFailure('CASSETTE_INTEGRITY_FAILURE', `${label} was not canonical base64`);
  }
  if (maxBytes !== undefined && bytes.length > maxBytes) {
    throw new HarnessFailure('BOUND_EXCEEDED', `${label} exceeded its bounded size`);
  }
  return bytes;
}

function validateSyntheticSecretSlots(slots) {
  if (!Array.isArray(slots) || slots.length > 256) {
    throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette synthetic secret slots were not bounded');
  }
  const seen = new Set();
  for (const slot of slots) {
    if (typeof slot !== 'string' || slot.length > 128
      || !/^<secret:[a-z][a-z0-9_]{0,63}>$/u.test(slot) || seen.has(slot)) {
      throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette synthetic secret slot was invalid or duplicated');
    }
    seen.add(slot);
  }
}

function validateRawMember(record, { captureSetId, recordingId }) {
  if (!record || typeof record !== 'object' || Array.isArray(record)
    || record.schema !== 'zode.http-incident-recording.v1'
    || record.recording_id !== recordingId
    || record.capture_set_id !== captureSetId
    || typeof record.boundary !== 'string' || !record.boundary
    || typeof record.method !== 'string' || !record.method
    || typeof record.path !== 'string' || !record.path
    || !record.request_headers || Array.isArray(record.request_headers)
    || typeof record.request_headers !== 'object'
    || !record.response || Array.isArray(record.response)
    || typeof record.response !== 'object'
    || !record.response.headers || Array.isArray(record.response.headers)
    || typeof record.response.headers !== 'object'
    || !Number.isInteger(record.response.status)
    || record.response.status < 100 || record.response.status > 599
    || !Array.isArray(record.response.chunks)
    || !['completed', 'disconnected', 'transport_error', 'client_disconnected', 'timed_out'].includes(record.response.outcome)) {
    throw new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set raw member schema was invalid');
  }
  decodeBase64Strict(record.request_body_base64, 'raw request body', MAX_RECORDING_REQUEST_BYTES);
  if (record.response.chunks.length > MAX_RECORDING_CHUNKS) {
    throw new HarnessFailure('BOUND_EXCEEDED', 'capture-set raw member exceeded its chunk bound');
  }
  let previousOffset = -1;
  let responseBytes = 0;
  for (const chunk of record.response.chunks) {
    if (!chunk || typeof chunk.data_base64 !== 'string' || !Number.isFinite(chunk.offset_us)
      || chunk.offset_us < 0 || chunk.offset_us < previousOffset || chunk.offset_us > 60 * 1_000_000) {
      throw new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set raw member response timing was invalid');
    }
    responseBytes += decodeBase64Strict(chunk.data_base64, 'raw response chunk', MAX_RECORDING_RESPONSE_BYTES).length;
    if (responseBytes > MAX_RECORDING_RESPONSE_BYTES) {
      throw new HarnessFailure('BOUND_EXCEEDED', 'capture-set raw member response exceeded its byte bound');
    }
    previousOffset = chunk.offset_us;
  }
  return record;
}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [name, value] of Object.entries(headers || {})) {
    normalized[String(name).toLowerCase()] = Array.isArray(value)
      ? value.map(String).join(', ')
      : String(value);
  }
  return normalized;
}

function loopbackOrigin(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new HarnessFailure('ORIGIN_INVALID', `${label} must be an HTTP loopback origin`);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new HarnessFailure('ORIGIN_INVALID', `${label} must be an HTTP loopback origin`);
  }
  const hostname = parsed.hostname.toLowerCase();
  const ipv4Loopback = /^127(?:\.\d{1,3}){3}$/u.test(hostname)
    && hostname.split('.').slice(1).every((part) => Number(part) <= 255);
  const loopback = hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || ipv4Loopback
    || hostname === '[::1]';
  if (parsed.protocol !== 'http:' || !loopback || parsed.username || parsed.password
    || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new HarnessFailure('ORIGIN_INVALID', `${label} must be an HTTP loopback origin`);
  }
  return parsed.origin;
}

function canonicalHost(canonicalOrigin) {
  if (canonicalOrigin === undefined) return undefined;
  return loopbackOrigin(canonicalOrigin, 'canonical origin').replace(/^https?:\/\//u, '');
}

function restoreHeaders(headers, ledger) {
  const restored = {};
  for (const [name, value] of Object.entries(headers || {})) {
    restored[name] = Array.isArray(value)
      ? value.map((item) => ledger.restore(item))
      : ledger.restore(value);
  }
  return restored;
}

async function requestRaw(target, { method, headers, body, timeoutMs = HTTP_TIMEOUT_MS }) {
  return withTimeout(new Promise((resolve, reject) => {
    const started = process.hrtime.bigint();
    const request = http.request(target, { method, headers }, (response) => {
      const chunks = [];
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        resolve({
          status: response.statusCode || 502,
          headers: response.headers,
          chunks,
          outcome: value,
        });
      };
      response.on('data', (chunk) => chunks.push({
        offsetUs: Number(process.hrtime.bigint() - started) / 1_000,
        data: Buffer.from(chunk),
      }));
      response.once('end', () => finish('completed'));
      // Terminal outcome is an observation of this replay target, never a
      // hint from the captured cassette.  Otherwise a target that disconnects
      // or errors differently could be relabeled as the expected outcome.
      response.once('aborted', () => finish('disconnected'));
      response.once('error', () => finish('transport_error'));
      response.once('close', () => {
        if (!settled && !response.complete) finish('disconnected');
      });
    });
    request.once('error', reject);
    request.end(body || undefined);
  }), timeoutMs, 'replay response timed out');
}

class RecordingJournal {
  constructor({ rootDir, ledger, recoveryOnly = false }) {
    this.ledger = ledger;
    this.records = [];
    this.active = new Map();
    this.sequence = 0;
    this.fatalError = undefined;
    this.captureSets = new Map();
    this.captureSetSequence = 0;
    this.replayDepth = 0;
    this.fatalBarrier = new Barrier('recording fatal');
    this.recoveryOnly = recoveryOnly === true;
    if (this.recoveryOnly) {
      try {
        const stat = fs.lstatSync(rootDir);
        if (!stat.isDirectory()) throw new Error('recovery root is not a directory');
        this.rootDir = path.resolve(rootDir);
      } catch (error) {
        throw new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'recovery root was not an existing regular directory', {
          rootDir,
          cause: error instanceof Error ? error.message : String(error),
        });
      }
      this.promotedDir = undefined;
      this.defaultCaptureSetId = undefined;
      return;
    }
    this.rootDir = ensureDirectory(rootDir);
    this.promotedDir = ensureDirectory(path.join(rootDir, 'promoted'));
    this.defaultCaptureSetId = this.beginCaptureSet({ e2eName: 'web-e2e-harness-run', maxMembers: 64 });
  }

  /**
   * Open an already flushed quarantine root without creating a child
   * directory, manifest, or promoted output.  The caller must reload a
   * specific sealed capture set before any promotion is possible.
   */
  static openFlushedCaptureRoot({ rootDir, ledger }) {
    return new RecordingJournal({ rootDir, ledger, recoveryOnly: true });
  }

  beginCaptureSet({ e2eName = 'web-e2e-capture-set', maxMembers = 64 } = {}) {
    this._healthy();
    if (!Number.isSafeInteger(maxMembers) || maxMembers < 1 || maxMembers > 256) {
      throw new HarnessFailure('BOUND_EXCEEDED', 'capture set member bound is invalid');
    }
    const id = `${String(++this.captureSetSequence).padStart(4, '0')}-${randomUUID()}`;
    const captureSet = {
      id,
      e2eName,
      maxMembers,
      members: [],
      active: new Set(),
      fatalError: undefined,
      sealed: false,
      firstFailureRecordingId: undefined,
      manifestPath: path.join(this.rootDir, `${id}.manifest.json`),
      manifestAnchorPath: path.join(this.rootDir, `${id}.manifest.anchor.json`),
    };
    this.captureSets.set(id, captureSet);
    this._persistCaptureSet(captureSet, 'open');
    this.currentCaptureSetId = id;
    return id;
  }

  _persistCaptureSet(captureSet, state, firstFailureRecordingId) {
    const unsignedManifest = {
      schema: 'zode.http-capture-set.v1',
      version: 1,
      capture_set_id: captureSet.id,
      e2e_name: captureSet.e2eName,
      max_members: captureSet.maxMembers,
      state,
      members: captureSet.members.map((record) => record.recordingId).sort(),
      member_digests: Object.fromEntries(
        captureSet.members
          .map((record) => [record.recordingId, record.rawDigest])
          .sort(([left], [right]) => left.localeCompare(right)),
      ),
      active: [...captureSet.active].sort(),
      ...(firstFailureRecordingId ? { first_failure_recording_id: firstFailureRecordingId } : {}),
    };
    const manifest = {
      ...unsignedManifest,
      integrity_sha256: sha256(JSON.stringify(unsignedManifest)),
    };
    captureSet.sourceDigest = manifest.integrity_sha256;
    try {
      if (fs.existsSync(captureSet.manifestPath)) replacePrivateJson(captureSet.manifestPath, manifest);
      else writePrivateFile(captureSet.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    } catch (error) {
      throw this._fail(error);
    }
    if (state === 'flushed') this._sealManifest(captureSet, manifest);
    return manifest;
  }

  _sealManifest(captureSet, manifest) {
    const manifestDigest = sha256(JSON.stringify(manifest));
    const anchor = {
      schema: 'zode.http-capture-set-anchor.v1',
      version: 1,
      capture_set_id: captureSet.id,
      manifest_digest: manifestDigest,
    };
    try {
      if (fs.existsSync(captureSet.manifestAnchorPath)) {
        const existing = JSON.parse(fs.readFileSync(captureSet.manifestAnchorPath, 'utf8'));
        if (existing.schema !== anchor.schema || existing.version !== anchor.version
          || existing.capture_set_id !== anchor.capture_set_id
          || existing.manifest_digest !== anchor.manifest_digest) {
          throw new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest anchor did not match its sealed manifest');
        }
        return;
      }
      writePrivateFile(captureSet.manifestAnchorPath, `${JSON.stringify(anchor, null, 2)}\n`);
      fs.chmodSync(captureSet.manifestAnchorPath, 0o444);
      fsyncDirectory(this.rootDir);
    } catch (error) {
      throw this._fail(error);
    }
  }

  reloadCaptureSet(captureSetId) {
    let captureSet = this.captureSets.get(captureSetId);
    if (!captureSet) {
      const manifestPath = path.join(this.rootDir, `${captureSetId}.manifest.json`);
      let bootstrap;
      try { bootstrap = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch (error) {
        throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest could not be reloaded', {
          captureSetId,
          cause: error instanceof Error ? error.message : String(error),
        }));
      }
      if (bootstrap.capture_set_id !== captureSetId || typeof bootstrap.e2e_name !== 'string'
        || !Number.isSafeInteger(bootstrap.max_members)
        || typeof bootstrap.integrity_sha256 !== 'string') {
        throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest identity was invalid', { captureSetId }));
      }
      captureSet = {
        id: captureSetId,
        e2eName: bootstrap.e2e_name,
        maxMembers: bootstrap.max_members,
        members: [],
        active: new Set(),
        fatalError: undefined,
        sealed: bootstrap.state !== 'open',
        firstFailureRecordingId: bootstrap.first_failure_recording_id,
        manifestPath,
        manifestAnchorPath: path.join(this.rootDir, `${captureSetId}.manifest.anchor.json`),
      };
      this.captureSets.set(captureSetId, captureSet);
    }
    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(captureSet.manifestPath, 'utf8'));
    } catch (error) {
      throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest could not be reloaded', {
        captureSetId,
        cause: error instanceof Error ? error.message : String(error),
      }));
    }
    const { integrity_sha256: manifestIntegrity, ...unsignedManifest } = manifest || {};
    if (typeof manifestIntegrity !== 'string' || !/^[0-9a-f]{64}$/u.test(manifestIntegrity)
      || manifestIntegrity !== sha256(JSON.stringify(unsignedManifest))) {
      throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest integrity did not match its fields', { captureSetId }));
    }
    if (manifest.schema !== 'zode.http-capture-set.v1' || manifest.version !== 1
      || manifest.capture_set_id !== captureSetId || manifest.e2e_name !== captureSet.e2eName
      || manifest.max_members !== captureSet.maxMembers
      || !['open', 'flushed'].includes(manifest.state)
      || !Array.isArray(manifest.members) || !Array.isArray(manifest.active)
      || !manifest.member_digests || typeof manifest.member_digests !== 'object'
      || Array.isArray(manifest.member_digests)
      || manifest.members.length > captureSet.maxMembers
      || Object.keys(manifest.member_digests).length !== manifest.members.length) {
      throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest schema or bounds were invalid', { captureSetId }));
    }
    if (manifest.state === 'flushed') {
      try {
        const anchor = JSON.parse(fs.readFileSync(captureSet.manifestAnchorPath, 'utf8'));
        if (anchor.schema !== 'zode.http-capture-set-anchor.v1' || anchor.version !== 1
          || anchor.capture_set_id !== captureSetId
          || anchor.manifest_digest !== sha256(JSON.stringify(manifest))) {
          throw new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest anchor did not match its durable manifest');
        }
      } catch (error) {
        throw this._fail(error instanceof HarnessFailure ? error : new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest anchor could not be reloaded', { captureSetId }));
      }
    }
    const records = [];
    let previous = '';
    for (const recordingId of manifest.members) {
      if (typeof recordingId !== 'string' || !/^\d{6}-[0-9a-f-]{36}$/u.test(recordingId)
        || recordingId <= previous
        || typeof manifest.member_digests[recordingId] !== 'string'
        || !/^[0-9a-f]{64}$/u.test(manifest.member_digests[recordingId])) {
        throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set members were not strictly ordered', { captureSetId }));
      }
      previous = recordingId;
      const rawPath = path.join(this.rootDir, `${recordingId}.raw.json`);
      let rawBytes;
      let record;
      try {
        const stat = fs.lstatSync(rawPath);
        if (!stat.isFile() || stat.size > MAX_RECORDING_RAW_BYTES) throw new Error('raw member is not a bounded regular file');
        rawBytes = fs.readFileSync(rawPath);
        record = JSON.parse(rawBytes.toString('utf8'));
      } catch (error) {
        throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set member was not durably readable', { captureSetId, recordingId }));
      }
      if (sha256(rawBytes) !== manifest.member_digests[recordingId]) {
        throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set raw member digest did not match its manifest', { captureSetId, recordingId }));
      }
      try {
        validateRawMember(record, { captureSetId, recordingId });
      } catch (error) {
        throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set raw member schema was invalid', {
          captureSetId,
          recordingId,
          cause: error instanceof Error ? error.message : String(error),
        }));
      }
      records.push({ ...record, recordingId, rawPath, rawDigest: manifest.member_digests[recordingId], captureSetId });
    }
    const memberIds = new Set(records.map((record) => record.recordingId));
    if (manifest.active.some((recordingId) => memberIds.has(recordingId))
      || (manifest.state !== 'open' && manifest.active.length)) {
      throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set manifest retained an active member after sealing', { captureSetId }));
    }
    if (manifest.first_failure_recording_id !== undefined
      && (typeof manifest.first_failure_recording_id !== 'string'
        || !memberIds.has(manifest.first_failure_recording_id))) {
      throw this._fail(new HarnessFailure(
        'CAPTURE_SET_RELOAD_FAILURE',
        'capture-set first-failure identity was not a durable member',
        { captureSetId, firstFailureRecordingId: manifest.first_failure_recording_id },
      ));
    }
    captureSet.members = records;
    captureSet.active = new Set(manifest.active);
    captureSet.sealed = manifest.state !== 'open';
    captureSet.firstFailureRecordingId = manifest.first_failure_recording_id;
    captureSet.sourceDigest = manifest.integrity_sha256;
    for (const record of records) {
      if (!this.records.some((existing) => existing.recordingId === record.recordingId)) this.records.push(record);
    }
    return {
      captureSetId,
      e2eName: manifest.e2e_name,
      records,
      active: [...captureSet.active],
      state: manifest.state,
      firstFailureRecordingId: manifest.first_failure_recording_id,
      sourceDigest: manifest.integrity_sha256,
    };
  }

  _captureSet(id) {
    const captureSet = this.captureSets.get(id);
    if (!captureSet) throw new HarnessFailure('CAPTURE_SET_MISSING', 'capture set does not exist', { id });
    return captureSet;
  }

  _validateFirstFailureRecordingId(captureSet, firstFailureRecordingId) {
    if (firstFailureRecordingId === undefined) return;
    if (typeof firstFailureRecordingId !== 'string'
      || !captureSet.members.some((record) => record.recordingId === firstFailureRecordingId)) {
      throw this._fail(new HarnessFailure(
        'CAPTURE_SET_RELOAD_FAILURE',
        'capture-set first-failure identity was not a durable member',
        { captureSetId: captureSet.id, firstFailureRecordingId },
      ));
    }
  }

  _healthy() {
    if (this.fatalError) throw this.fatalError;
  }

  _fail(error) {
    if (!this.fatalError) {
      this.fatalError = error instanceof HarnessFailure
        ? error
        : new HarnessFailure('RECORDING_FLUSH_FAILURE', 'recording capture failed before durable flush', {
          cause: error instanceof Error ? error.message : String(error),
        });
    }
    for (const captureSet of this.captureSets.values()) captureSet.fatalError ||= this.fatalError;
    this.fatalBarrier.notify(this.fatalError);
    return this.fatalError;
  }

  _append(context, event) {
    this._healthy();
    try {
      writeDurable(context.fd, `${JSON.stringify(event)}\n`);
    } catch (error) {
      throw this._fail(error);
    }
  }

  async withRecordingDisabled(operation) {
    this.replayDepth += 1;
    try {
      return await operation();
    } finally {
      this.replayDepth -= 1;
    }
  }

  begin({ boundary, method, requestPath, requestHeaders, requestBody, captureSetId = this.currentCaptureSetId || this.defaultCaptureSetId }) {
    this._healthy();
    if (this.replayDepth > 0) {
      return {
        disabled: true,
        id: `replay-${randomUUID()}`,
        boundary,
        method,
        path: requestPath,
        requestHeaders: { ...(requestHeaders || {}) },
        requestBody: Buffer.from(requestBody || ''),
        responseStatus: undefined,
        responseHeaders: {},
        responseChunks: [],
        responseBytes: 0,
        outcome: undefined,
        captureSetId,
        finished: false,
      };
    }
    const captureSet = this._captureSet(captureSetId);
    if (captureSet.sealed) {
      throw this._fail(new HarnessFailure('CAPTURE_SET_SEALED', 'capture set cannot accept exchanges after its durable flush'));
    }
    if (captureSet.members.length + captureSet.active.size >= captureSet.maxMembers) {
      throw this._fail(new HarnessFailure('BOUND_EXCEEDED', 'capture set exceeded its member bound'));
    }
    const body = Buffer.from(requestBody || '');
    if (body.length > 4 * 1024 * 1024) {
      throw this._fail(new HarnessFailure('BOUND_EXCEEDED', 'recording request body exceeded its bounded size'));
    }
    const id = `${String(++this.sequence).padStart(6, '0')}-${randomUUID()}`;
    const eventsPath = path.join(this.rootDir, `${id}.events`);
    let fd;
    try {
      fd = fs.openSync(eventsPath, 'wx', 0o600);
      fsyncDirectory(this.rootDir);
    } catch (error) {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
      throw this._fail(error);
    }
    const context = {
      id,
      eventsPath,
      fd,
      boundary,
      method,
      path: requestPath,
      requestHeaders: { ...(requestHeaders || {}) },
      requestBody: body,
      responseStatus: undefined,
      responseHeaders: {},
      responseChunks: [],
      responseBytes: 0,
      outcome: undefined,
      startedAt: process.hrtime.bigint(),
      finished: false,
      captureSetId,
    };
    try {
      this._append(context, {
        kind: 'request',
        schema: 'zode.http-incident-recording.v1',
        recording_id: id,
        boundary,
        method,
        path: requestPath,
        request_headers: requestHeaders || {},
        request_body_base64: body.toString('base64'),
      });
      this.active.set(id, context);
      captureSet.active.add(id);
      this._persistCaptureSet(captureSet, 'open');
      return context;
    } catch (error) {
      try { fs.closeSync(fd); } catch {}
      throw error;
    }
  }

  beginIngress({ boundary, method, requestPath, requestHeaders, captureSetId }) {
    const context = this.begin({
      boundary,
      method,
      requestPath,
      requestHeaders,
      requestBody: Buffer.alloc(0),
      captureSetId,
    });
    context.requestBodyChunks = [];
    context.requestBytes = 0;
    return context;
  }

  ingressChunk(context, data) {
    if (!context || context.finished) throw new HarnessFailure('RECORDING_STATE_FAILURE', 'ingress chunk arrived after completion');
    const bytes = Buffer.from(data || '');
    const current = context.requestBodyChunks || [];
    const currentBytes = context.requestBytes || 0;
    if (currentBytes + bytes.length > 4 * 1024 * 1024) {
      const remaining = Math.max(0, (4 * 1024 * 1024) - currentBytes);
      if (remaining > 0) {
        const prefix = bytes.subarray(0, remaining);
        current.push(prefix);
        context.requestBytes = currentBytes + prefix.length;
        if (!context.disabled) {
          this._append(context, { kind: 'request_chunk', data_base64: prefix.toString('base64') });
        }
      }
      throw new HarnessFailure('BOUND_EXCEEDED', 'recording request exceeded its bounded body size');
    }
    current.push(bytes);
    context.requestBytes = currentBytes + bytes.length;
    if (!context.disabled) {
      this._append(context, { kind: 'request_chunk', data_base64: bytes.toString('base64') });
    }
  }

  endIngress(context) {
    if (!context || context.finished) throw new HarnessFailure('RECORDING_STATE_FAILURE', 'ingress ended after completion');
    context.requestBody = Buffer.concat(context.requestBodyChunks || []);
    if (!context.disabled) {
      this._append(context, {
        kind: 'request_end',
        length: context.requestBody.length,
        sha256: sha256(context.requestBody),
      });
    }
    return context.requestBody;
  }

  updateIngressHeaders(context, requestHeaders) {
    if (!context || context.finished) throw new HarnessFailure('RECORDING_STATE_FAILURE', 'ingress headers updated after completion');
    context.requestHeaders = { ...(requestHeaders || {}) };
    if (!context.disabled) this._append(context, { kind: 'request_headers', headers: context.requestHeaders });
  }

  responseStarted(context, { status, headers }) {
    if (!context || context.finished) throw new HarnessFailure('RECORDING_STATE_FAILURE', 'recording response started after completion');
    context.responseStatus = status;
    context.responseHeaders = { ...(headers || {}) };
    if (context.disabled) return;
    this._append(context, { kind: 'response_start', status, headers: context.responseHeaders });
  }

  chunk(context, data, offsetUs) {
    if (!context || context.finished) throw new HarnessFailure('RECORDING_STATE_FAILURE', 'recording chunk arrived after completion');
    if (!Number.isFinite(offsetUs) || offsetUs < 0) {
      throw this._fail(new HarnessFailure('RECORDING_STATE_FAILURE', 'recording chunk offset was not a finite non-negative value'));
    }
    const bytes = Buffer.from(data || '');
    if (context.responseChunks.length >= MAX_RECORDING_CHUNKS || context.responseBytes + bytes.length > MAX_RECORDING_RESPONSE_BYTES) {
      throw this._fail(new HarnessFailure('BOUND_EXCEEDED', 'recording response exceeded its bounded stream size'));
    }
    const chunk = { offsetUs, data: bytes };
    context.responseChunks.push(chunk);
    context.responseBytes += bytes.length;
    if (context.disabled) return;
    this._append(context, {
      kind: 'response_chunk',
      offset_us: offsetUs,
      data_base64: bytes.toString('base64'),
    });
  }

  finish(context, outcome = 'completed') {
    if (!context || context.finished) return context?.record;
    if (context.responseStatus === undefined) {
      throw this._fail(new HarnessFailure('RECORDING_STATE_FAILURE', 'recording finished without response headers'));
    }
    context.outcome = outcome;
    if (context.disabled) {
      context.finished = true;
      context.record = {
        schema: 'zode.http-incident-recording.v1',
        recording_id: context.id,
        capture_set_id: context.captureSetId,
        boundary: context.boundary,
        method: context.method,
        path: context.path,
        request_headers: context.requestHeaders,
        request_body_base64: context.requestBody.toString('base64'),
        response: {
          status: context.responseStatus,
          headers: context.responseHeaders,
          chunks: context.responseChunks.map((chunk) => ({
            offset_us: chunk.offsetUs,
            data_base64: chunk.data.toString('base64'),
          })),
          outcome,
        },
      };
      return context.record;
    }
    this._append(context, { kind: 'response_end', outcome });
    context.finished = true;
    this.active.delete(context.id);
    try {
      fs.closeSync(context.fd);
      const raw = {
        schema: 'zode.http-incident-recording.v1',
        recording_id: context.id,
        capture_set_id: context.captureSetId,
        boundary: context.boundary,
        method: context.method,
        path: context.path,
        request_headers: context.requestHeaders,
        request_body_base64: context.requestBody.toString('base64'),
        response: {
          status: context.responseStatus,
          headers: context.responseHeaders,
          chunks: context.responseChunks.map((chunk) => ({
            offset_us: chunk.offsetUs,
            data_base64: chunk.data.toString('base64'),
          })),
          outcome,
        },
      };
      const rawPath = path.join(this.rootDir, `${context.id}.raw.json`);
      const rawPayload = `${JSON.stringify(raw, null, 2)}\n`;
      const fd = fs.openSync(rawPath, 'wx', 0o600);
      try {
        writeDurable(fd, rawPayload);
      } finally {
        fs.closeSync(fd);
      }
      fs.chmodSync(rawPath, 0o600);
      fsyncDirectory(this.rootDir);
      try { fs.unlinkSync(context.eventsPath); } catch {}
      fsyncDirectory(this.rootDir);
      const record = { ...raw, recordingId: context.id, rawPath, rawDigest: sha256(rawPayload) };
      context.record = record;
      const captureSet = this._captureSet(context.captureSetId);
      captureSet.active.delete(context.id);
      captureSet.members.push(record);
      this._persistCaptureSet(captureSet, 'open');
      record.captureSetId = context.captureSetId;
      this.records.push(record);
      return record;
    } catch (error) {
      throw this._fail(error);
    }
  }

  record({ boundary, method, requestPath, requestHeaders, requestBody, responseStatus, responseHeaders, responseChunks, outcome = 'completed', captureSetId }) {
    const context = this.begin({ boundary, method, requestPath, requestHeaders, requestBody, captureSetId });
    try {
      this.responseStarted(context, { status: responseStatus, headers: responseHeaders });
      for (const chunk of responseChunks || []) this.chunk(context, chunk.data, chunk.offsetUs);
      return this.finish(context, outcome);
    } catch (error) {
      this._fail(error);
      throw error;
    }
  }

  first({ boundary, requestPath, responseStatus, captureSetId } = {}) {
    return [...this.records]
      .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)))
      .find((record) =>
        (boundary === undefined || record.boundary === boundary)
        && (requestPath === undefined || record.path === requestPath)
        && (responseStatus === undefined || record.response.status === responseStatus)
        && (captureSetId === undefined || record.captureSetId === captureSetId));
  }

  flushCaptureSet(captureSetId, { firstFailureRecordingId } = {}) {
    this._healthy();
    const captureSet = this._captureSet(captureSetId);
    if (captureSet.fatalError) throw captureSet.fatalError;
    if (captureSet.sealed) {
      if (firstFailureRecordingId !== undefined
        && firstFailureRecordingId !== captureSet.firstFailureRecordingId) {
        throw this._fail(new HarnessFailure(
          'CAPTURE_SET_RELOAD_FAILURE',
          'recovery promotion attempted to replace the sealed first-failure identity',
          { captureSetId, firstFailureRecordingId },
        ));
      }
      const reloaded = this.reloadCaptureSet(captureSetId);
      return {
        captureSetId,
        e2eName: captureSet.e2eName,
        records: reloaded.records,
        firstFailureRecordingId: reloaded.firstFailureRecordingId,
        sourceDigest: reloaded.sourceDigest,
      };
    }
    if (captureSet.active.size) {
      throw new HarnessFailure('RECORDING_FLUSH_FAILURE', 'capture set has unflushed exchanges', {
        captureSetId,
        active: [...captureSet.active],
      });
    }
    // Validate before sealing or rewriting the manifest.  A bogus first
    // occurrence must leave the durable raw members intact and cannot create a
    // partially promoted cassette.
    this._validateFirstFailureRecordingId(captureSet, firstFailureRecordingId);
    captureSet.sealed = true;
    captureSet.firstFailureRecordingId = firstFailureRecordingId;
    this._persistCaptureSet(captureSet, 'flushed', firstFailureRecordingId);
    const reloaded = this.reloadCaptureSet(captureSetId);
    if (reloaded.active.length || reloaded.records.length !== captureSet.members.length
      || reloaded.records.some((record, index) => record.recordingId !== captureSet.members[index].recordingId)) {
      throw this._fail(new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'capture-set durable manifest did not match its members', { captureSetId }));
    }
    return {
      captureSetId,
      e2eName: captureSet.e2eName,
      records: reloaded.records,
      firstFailureRecordingId: reloaded.firstFailureRecordingId,
      sourceDigest: reloaded.sourceDigest,
    };
  }

  _safeExchange(record, sequence = record.recordingId) {
    return {
      sequence,
      recording_id: record.recordingId,
      boundary: record.boundary,
      method: record.method,
      path: redactedPath(record.path, this.ledger),
      request_headers: publicHeaders(record.request_headers),
      request_body: safeBody(Buffer.from(record.request_body_base64, 'base64'), this.ledger),
      response: {
        status: record.response.status,
        headers: publicHeaders(record.response.headers),
        chunks: record.response.chunks.map((chunk) => ({
          offset_us: chunk.offset_us,
          data_base64: redactBuffer(Buffer.from(chunk.data_base64, 'base64'), this.ledger).toString('base64'),
        })),
        outcome: record.response.outcome,
      },
    };
  }

  _scanSafeEnvelope(envelope) {
    const serialized = JSON.stringify(envelope);
    const leak = this.ledger.find(serialized);
    if (leak) throw new SecretLeakFailure('promotion cassette', leak.label);
    for (const marker of ['authorization', 'cookie', 'access_assertion', 'provider_secret', 'controller_secret']) {
      if (serialized.toLowerCase().includes(`"${marker}"`)) {
        throw new HarnessFailure('SECRET_SCAN_FAILURE', `promotion cassette retained forbidden ${marker} field`);
      }
    }
  }

  preparePromotion(record, { e2eName, classification, firstObserved } = {}) {
    if (!record) throw new HarnessFailure('RECORDING_MISSING', 'first failing exchange was not retained');
    const envelopeWithoutDigest = {
      schema: 'zode.http-incident-recording.v1',
      version: 1,
      recording_id: record.recordingId,
      e2e_name: e2eName || 'web-e2e-unclassified',
      boundary: record.boundary,
      first_observed: firstObserved,
      classification,
      exchanges: [this._safeExchange(record, '000001')],
      synthetic_secret_slots: [...this.ledger.entries.values()]
        .filter((entry) => !entry.derived)
        .map((entry) => `<secret:${entry.label}>`),
    };
    this._scanSafeEnvelope(envelopeWithoutDigest);
    return {
      envelope: {
        ...envelopeWithoutDigest,
        integrity_sha256: sha256(JSON.stringify(envelopeWithoutDigest)),
      },
      record,
    };
  }

  prepareCaptureSetPromotion(captureSetId, { e2eName, classification, firstObserved, firstFailureRecordingId } = {}) {
    const current = this._captureSet(captureSetId);
    const sealedFirstFailureRecordingId = firstFailureRecordingId ?? current.firstFailureRecordingId;
    const captureSet = this.flushCaptureSet(captureSetId, { firstFailureRecordingId: sealedFirstFailureRecordingId });
    if (!captureSet.records.length) throw new HarnessFailure('RECORDING_MISSING', 'capture set has no durable exchanges');
    const envelopeWithoutDigest = {
      schema: 'zode.http-incident-recording.v1',
      version: 1,
      recording_id: `${captureSetId}-${randomUUID()}`,
      e2e_name: e2eName || captureSet.e2eName,
      boundary: 'browser-capture-set',
      first_observed: firstObserved,
      classification,
      ...(captureSet.sourceDigest ? { source_digest: captureSet.sourceDigest } : {}),
      ...(captureSet.firstFailureRecordingId ? { first_failure_recording_id: captureSet.firstFailureRecordingId } : {}),
      exchanges: captureSet.records.map((record, index) => this._safeExchange(record, String(index + 1).padStart(6, '0'))),
      synthetic_secret_slots: [...this.ledger.entries.values()]
        .filter((entry) => !entry.derived)
        .map((entry) => `<secret:${entry.label}>`),
    };
    this._scanSafeEnvelope(envelopeWithoutDigest);
    return {
      captureSet,
      envelope: {
        ...envelopeWithoutDigest,
        integrity_sha256: sha256(JSON.stringify(envelopeWithoutDigest)),
      },
    };
  }

  async promote(record, options) {
    const prepared = this.preparePromotion(record, options);
    let replay;
    if (typeof options?.replay === 'function') replay = await options.replay(prepared.envelope);
    else if (options?.replayProof) replay = options.replayProof;
    else throw new HarnessFailure('REPLAY_PROOF_REQUIRED', 'promotion requires a secret-safe replay proof before writing a cassette');
    return this._writePromotion(prepared, replay, options);
  }

  async promoteCaptureSet(captureSetId, options = {}) {
    const prepared = this.prepareCaptureSetPromotion(captureSetId, options);
    let replay;
    if (typeof options?.replay === 'function') replay = await options.replay(prepared.envelope);
    else if (options?.replayProof) replay = options.replayProof;
    else throw new HarnessFailure('REPLAY_PROOF_REQUIRED', 'capture-set promotion requires a secret-safe replay proof before writing a cassette');
    return this._writePromotion(prepared, replay, options);
  }

  async promoteFlushedCaptureSet(captureSetId, options = {}) {
    const captureSet = this._captureSet(captureSetId);
    if (!captureSet.sealed) {
      throw new HarnessFailure('CAPTURE_SET_NOT_FLUSHED', 'recovery promotion requires an already flushed capture set', {
        captureSetId,
      });
    }
    if (options.e2eName !== undefined && options.e2eName !== captureSet.e2eName) {
      throw new HarnessFailure('CAPTURE_SET_RELOAD_FAILURE', 'recovery promotion cannot replace the flushed E2E owner', {
        captureSetId,
        expectedE2eName: captureSet.e2eName,
        actualE2eName: options.e2eName,
      });
    }
    if (typeof options.replay !== 'function') {
      throw new HarnessFailure('REPLAY_PROOF_REQUIRED', 'recovery promotion requires a same-entry replay callback that returns complete results');
    }
    this._validateRecoveryDestination(options.destinationDirectory);
    const prepared = this.prepareCaptureSetPromotion(captureSetId, options);
    const results = await options.replay(prepared.envelope);
    const proof = this.createReplayProof(prepared.envelope, results);
    this._validateBoundReplayProof(prepared, proof);
    return this._writePromotion(prepared, proof, options);
  }

  _isWithinRoot(candidate) {
    const root = `${path.resolve(this.rootDir)}${path.sep}`;
    const resolved = path.resolve(candidate);
    return resolved === path.resolve(this.rootDir) || resolved.startsWith(root);
  }

  _validateRecoveryDestination(candidate) {
    if (typeof candidate !== 'string' || candidate.length === 0 || this._isWithinRoot(candidate)) {
      throw new HarnessFailure('RECOVERY_DESTINATION_INVALID', 'recovery promotion requires an independent destination directory');
    }
    const resolved = path.resolve(candidate);
    let stat;
    try { stat = fs.lstatSync(resolved); } catch (error) {
      throw new HarnessFailure('RECOVERY_DESTINATION_INVALID', 'recovery promotion destination must already be a durable directory', {
        destinationDirectory: resolved,
        cause: error instanceof Error ? error.message : String(error),
      });
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new HarnessFailure('RECOVERY_DESTINATION_INVALID', 'recovery promotion destination must be a non-symlink directory', {
        destinationDirectory: resolved,
      });
    }
    try {
      const rootReal = fs.realpathSync(this.rootDir);
      const destinationReal = fs.realpathSync(resolved);
      if (destinationReal === rootReal || destinationReal.startsWith(`${rootReal}${path.sep}`)) {
        throw new HarnessFailure('RECOVERY_DESTINATION_INVALID', 'recovery promotion destination resolves inside the forensic root');
      }
    } catch (error) {
      if (error instanceof HarnessFailure) throw error;
      throw new HarnessFailure('RECOVERY_DESTINATION_INVALID', 'recovery promotion destination could not be resolved', {
        destinationDirectory: resolved,
        cause: error instanceof Error ? error.message : String(error),
      });
    }
    return resolved;
  }

  _writePromotion(prepared, replay, options = {}) {
    if (replay?.ok === false) throw new HarnessFailure('REPLAY_MISMATCH', 'redacted replay did not reproduce the complete public exchange set');
    if (this.recoveryOnly && !options?.destinationDirectory) {
      throw new HarnessFailure('RECOVERY_DESTINATION_INVALID', 'recovery promotion requires an independent destination directory');
    }
    const destinationDirectory = this.recoveryOnly
      ? this._validateRecoveryDestination(options?.destinationDirectory)
      : ensureDirectory(options?.destinationDirectory || this.promotedDir);
    this._scanSafeEnvelope(prepared.envelope);
    const cassettePath = path.join(destinationDirectory, `${prepared.envelope.recording_id || prepared.record.recordingId}.v1.json`);
    let fd;
    let created = false;
    try {
      fd = fs.openSync(cassettePath, 'wx', 0o600);
      created = true;
      writeDurable(fd, `${JSON.stringify(prepared.envelope, null, 2)}\n`);
      fs.closeSync(fd);
      fd = undefined;
      fs.chmodSync(cassettePath, 0o444);
      fsyncDirectory(destinationDirectory);
      this._scanSafeEnvelope(JSON.parse(fs.readFileSync(cassettePath, 'utf8')));
    } catch (error) {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
      if (created) {
        try { fs.unlinkSync(cassettePath); } catch {}
      }
      throw this._fail(error);
    }
    return {
      cassettePath,
      envelope: prepared.envelope,
      replay,
      ...(prepared.captureSet ? { captureSet: prepared.captureSet } : {}),
    };
  }

  _readCassette(cassetteOrPath) {
    let cassette;
    try {
      cassette = typeof cassetteOrPath === 'string'
        ? JSON.parse(fs.readFileSync(cassetteOrPath, 'utf8'))
        : cassetteOrPath;
    } catch (error) {
      throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette JSON could not be parsed', {
        cause: error instanceof Error ? error.message : String(error),
      });
    }
    const { integrity_sha256: integrity, ...unsigned } = cassette || {};
    if (!integrity || integrity !== sha256(JSON.stringify(unsigned))) {
      throw new HarnessFailure('CASSETTE_INTEGRITY_FAILURE', 'secret-safe cassette integrity verification failed');
    }
    if (cassette.schema !== 'zode.http-incident-recording.v1' || cassette.version !== 1
      || typeof cassette.e2e_name !== 'string' || !cassette.e2e_name
      || (cassette.source_digest !== undefined
        && (typeof cassette.source_digest !== 'string' || !/^[0-9a-f]{64}$/u.test(cassette.source_digest)))
      || !Array.isArray(cassette.synthetic_secret_slots)
      || !Array.isArray(cassette.exchanges) || cassette.exchanges.length > MAX_RECORDING_CHUNKS) {
      throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette schema, version, owner, or exchange bound was invalid');
    }
    validateSyntheticSecretSlots(cassette.synthetic_secret_slots);
    this._scanSafeEnvelope(unsigned);
    const seenSequences = new Set();
    for (const [index, exchange] of cassette.exchanges.entries()) {
      const expectedSequence = String(index + 1).padStart(6, '0');
      if (!exchange || exchange.sequence !== expectedSequence || seenSequences.has(exchange.sequence)
        || typeof exchange.recording_id !== 'string' || !exchange.recording_id) {
        throw new HarnessFailure('CASSETTE_SEQUENCE_FAILURE', 'cassette exchange sequences were not contiguous and unique');
      }
      seenSequences.add(exchange.sequence);
      if (typeof exchange.boundary !== 'string' || typeof exchange.method !== 'string'
        || typeof exchange.path !== 'string' || !exchange.request_headers || typeof exchange.request_headers !== 'object'
        || !exchange.request_body || typeof exchange.request_body !== 'object'
        || !exchange.response || typeof exchange.response !== 'object'
        || !exchange.response.headers || typeof exchange.response.headers !== 'object'
        || !Number.isInteger(exchange.response.status)
        || exchange.response.status < 100 || exchange.response.status > 599) {
        throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette exchange fields were invalid');
      }
      if (typeof exchange.request_body.raw_base64 !== 'string') {
        throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette request body encoding was invalid');
      }
      const body = decodeBase64Strict(exchange.request_body.raw_base64, 'cassette request body', MAX_RECORDING_REQUEST_BYTES);
      if (exchange.request_body?.sha256 !== sha256(body)) {
        throw new HarnessFailure('CASSETTE_INTEGRITY_FAILURE', 'cassette request body digest did not match its bytes');
      }
      if (!Array.isArray(exchange.response?.chunks) || exchange.response.chunks.length > MAX_RECORDING_CHUNKS) {
        throw new HarnessFailure('BOUND_EXCEEDED', 'cassette response chunk count exceeded its bound');
      }
      if (!['completed', 'disconnected', 'transport_error', 'client_disconnected', 'timed_out'].includes(exchange.response.outcome)) {
        throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette response termination outcome was unknown');
      }
      let previousOffset = -1;
      let responseBytes = 0;
      for (const chunk of exchange.response.chunks) {
        if (typeof chunk?.data_base64 !== 'string') {
          throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette response chunk encoding was invalid');
        }
        if (!chunk || !Number.isFinite(chunk.offset_us) || chunk.offset_us < 0
          || chunk.offset_us < previousOffset || chunk.offset_us > 60 * 1_000_000) {
          throw new HarnessFailure('CASSETTE_INTEGRITY_FAILURE', 'cassette response chunk offsets were not ordered');
        }
        const bytes = decodeBase64Strict(chunk.data_base64, 'cassette response chunk', MAX_RECORDING_RESPONSE_BYTES);
        responseBytes += bytes.length;
        if (responseBytes > MAX_RECORDING_RESPONSE_BYTES) {
          throw new HarnessFailure('BOUND_EXCEEDED', 'cassette response bytes exceeded its bound');
        }
        previousOffset = chunk.offset_us;
      }
    }
    if (cassette.first_failure_recording_id
      && !cassette.exchanges.some((exchange) => exchange.recording_id === cassette.first_failure_recording_id)) {
      throw new HarnessFailure('CASSETTE_SCHEMA_FAILURE', 'cassette first-failure identity was not present in its exchange set');
    }
    return cassette;
  }

  async replay(cassetteOrPath, { baseUrl, boundaryBaseUrls = {}, headers = {}, timingMode = 'immediate' }) {
    return this.withRecordingDisabled(async () => {
      const cassette = this._readCassette(cassetteOrPath);
      const results = [];
      for (const exchange of cassette.exchanges || []) {
        results.push(await this._replayExchange(exchange, { baseUrl, boundaryBaseUrls, headers, timingMode }));
      }
      if (results.length !== (cassette.exchanges || []).length) {
        throw new HarnessFailure('REPLAY_UNCONSUMED_EXCHANGES', 'replay did not consume the cassette exchange list');
      }
      for (const result of results) Object.freeze(result);
      Object.defineProperty(results, REPLAY_RESULTS_TOKEN, {
        value: Object.freeze({ journal: this, envelopeDigest: cassette.integrity_sha256 }),
        enumerable: false,
        configurable: false,
        writable: false,
      });
      Object.freeze(results);
      return results;
    });
  }

  /**
   * Bind a replay result list to the exact safe capture-set envelope.  A
   * caller cannot use a boolean success value as a recovery proof: the source
   * manifest digest, first-failure member, exchange count, and response
   * fingerprint all have to match the loaded envelope.
   */
  createReplayProof(envelope, results) {
    if (!envelope || typeof envelope.source_digest !== 'string'
      || !/^[0-9a-f]{64}$/u.test(envelope.source_digest)
      || !Array.isArray(envelope.exchanges) || !Array.isArray(results)
      || results.length !== envelope.exchanges.length) {
      throw new HarnessFailure('REPLAY_PROOF_INVALID', 'replay results were not bound to a complete capture-set source');
    }
    const replayToken = results[REPLAY_RESULTS_TOKEN];
    if (!replayToken || replayToken.journal !== this
      || replayToken.envelopeDigest !== envelope.integrity_sha256) {
      throw new HarnessFailure('REPLAY_PROOF_INVALID', 'replay results were not produced by the shared public replay primitive for this envelope');
    }
    try {
      this._readCassette(envelope);
    } catch (error) {
      throw new HarnessFailure('REPLAY_PROOF_INVALID', 'the replay callback changed the loaded capture-set envelope', {
        cause: error instanceof Error ? error.message : String(error),
      });
    }
    const expected = envelope.exchanges.map((exchange) => ({
      status: exchange.response.status,
      path: exchange.path,
      outcome: exchange.response.outcome,
      chunks: exchange.response.chunks.length,
    }));
    const actual = results.map((result) => ({
      status: result?.status,
      path: result?.path,
      outcome: result?.outcome,
      chunks: result?.chunks,
    }));
    if (JSON.stringify(expected) !== JSON.stringify(actual)) {
      throw new HarnessFailure('REPLAY_MISMATCH', 'same-entry replay did not reproduce the complete capture-set exchange results');
    }
    return {
      schema: 'zode.http-replay-proof.v1',
      ok: true,
      source_digest: envelope.source_digest,
      exchange_count: actual.length,
      first_failure_recording_id: envelope.first_failure_recording_id || null,
      response_fingerprint: sha256(JSON.stringify(actual)),
    };
  }

  _validateBoundReplayProof(prepared, proof) {
    const envelope = prepared.envelope;
    if (!proof || proof.schema !== 'zode.http-replay-proof.v1' || proof.ok !== true
      || proof.source_digest !== envelope.source_digest
      || proof.exchange_count !== envelope.exchanges.length
      || (proof.first_failure_recording_id || null) !== (envelope.first_failure_recording_id || null)
      || typeof proof.response_fingerprint !== 'string'
      || !/^[0-9a-f]{64}$/u.test(proof.response_fingerprint)) {
      throw new HarnessFailure('REPLAY_PROOF_INVALID', 'replay proof was not bound to the loaded capture-set source');
    }
    const expected = envelope.exchanges.map((exchange) => ({
      status: exchange.response.status,
      path: exchange.path,
      outcome: exchange.response.outcome,
      chunks: exchange.response.chunks.length,
    }));
    if (proof.response_fingerprint !== sha256(JSON.stringify(expected))) {
      throw new HarnessFailure('REPLAY_PROOF_INVALID', 'replay response fingerprint did not match the loaded capture-set source');
    }
  }

  async startReplayServer(cassetteOrPath, { timingMode = 'immediate' } = {}) {
    const cassette = this._readCassette(cassetteOrPath);
    if (timingMode !== 'immediate' && timingMode !== 'captured') {
      throw new HarnessFailure('REPLAY_MODE_INVALID', 'replay timing mode is invalid');
  }
  let nextExchange = 0;
  let nextReservation = 0;
  let reservationTail = Promise.resolve();
  const consumedReservations = new Set();
  const reserveExchange = async () => {
    const predecessor = reservationTail;
    let release;
    reservationTail = new Promise((resolve) => { release = resolve; });
    await predecessor;
    try {
      if (nextReservation >= (cassette.exchanges || []).length) {
        throw new HarnessFailure('REPLAY_EXTRA_REQUEST', 'replay received more requests than the cassette contains');
      }
      const exchangeIndex = nextReservation;
      nextReservation += 1;
      return exchangeIndex;
    } finally {
      release();
    }
  };
  const markConsumed = (exchangeIndex) => {
    consumedReservations.add(exchangeIndex);
    while (consumedReservations.has(nextExchange)) {
      consumedReservations.delete(nextExchange);
      nextExchange += 1;
    }
  };
  let closing = false;
  let notifyClosing;
  const closingSignal = new Promise((resolve) => { notifyClosing = resolve; });
  let activeHandlers = 0;
  const handlerIdle = new Barrier('replay handler idle');
  const fixture = await startHttpServer(async (request, response) => {
    activeHandlers += 1;
    try {
      return await (async () => {
      const exchangeIndex = await reserveExchange();
      const exchange = cassette.exchanges?.[exchangeIndex];
      const requestBody = await readRequestBody(request);
      const expectedPath = this.ledger.restore(exchange.path);
      if (request.method !== exchange.method || request.url !== expectedPath) {
        throw new HarnessFailure('REPLAY_REQUEST_MISMATCH', 'replay server received a different request method or path', {
          expectedMethod: exchange.method,
          actualMethod: request.method,
          expectedPath: exchange.path,
          actualPath: redactedPath(request.url, this.ledger),
        });
      }
      const expectedHeaders = normalizeHeaders(restoreHeaders(exchange.request_headers, this.ledger));
      const actualHeaders = normalizeHeaders(publicHeaders(request.headers));
      const names = new Set([...Object.keys(expectedHeaders), ...Object.keys(actualHeaders)]);
      for (const name of names) {
        if (expectedHeaders[name] !== actualHeaders[name]) {
          throw new HarnessFailure('REPLAY_REQUEST_HEADER_MISMATCH', 'replay server received different request headers', { name });
        }
      }
      const expectedBody = restoreBuffer(decodeBase64Strict(exchange.request_body.raw_base64, 'replay request body', MAX_RECORDING_REQUEST_BYTES), this.ledger);
      if (!requestBody.equals(expectedBody)) {
      throw new HarnessFailure('REPLAY_REQUEST_BODY_MISMATCH', 'replay server received different request bytes');
      }
      let clientAborted = false;
      let terminal = false;
      let serverTerminating = false;
      let acceptedChunks = 0;
      let allChunksDelivered = true;
      let notifyClientAbort;
      const clientAbort = new Promise((resolve) => { notifyClientAbort = resolve; });
      const markClientAborted = () => {
        if (!terminal && !serverTerminating) {
          clientAborted = true;
          notifyClientAbort();
          if (!closing && ['client_disconnected', 'timed_out'].includes(exchange.response.outcome)
            && acceptedChunks >= exchange.response.chunks.length) {
            terminal = true;
            markConsumed(exchangeIndex);
          }
        }
      };
      const markResponseError = () => {
        if (!terminal && !serverTerminating) {
          clientAborted = true;
          notifyClientAbort();
          if (!closing && ['client_disconnected', 'timed_out'].includes(exchange.response.outcome)
            && acceptedChunks >= exchange.response.chunks.length) {
            terminal = true;
            markConsumed(exchangeIndex);
          }
        }
      };
      request.once('aborted', markClientAborted);
      request.once('error', markClientAborted);
      response.once('error', markResponseError);
      response.once('close', () => {
        if (!terminal && !serverTerminating) markClientAborted();
      });
      if (response.destroyed || response.writableEnded) return;
      response.writeHead(exchange.response.status, restoreHeaders(exchange.response.headers, this.ledger));
      try {
        response.flushHeaders();
      } catch {
        return;
      }
      const started = process.hrtime.bigint();
      const writeChunk = (bytes) => new Promise((resolve) => {
        if (clientAborted || response.destroyed || response.writableEnded) {
          resolve(false);
          return;
        }
        let settled = false;
        let accepted = false;
        const settle = (ok) => {
          if (settled) return;
          settled = true;
          response.removeListener('close', onClose);
          response.removeListener('error', onError);
          resolve(ok);
        };
        const onClose = () => settle(accepted);
        const onError = () => settle(false);
        response.once('close', onClose);
        response.once('error', onError);
        try {
          response.write(bytes, (error) => settle(!error && !response.destroyed));
          accepted = true;
          acceptedChunks += 1;
        } catch {
          settle(false);
        }
      });
      for (const chunk of exchange.response.chunks) {
        if (request.aborted || request.readableAborted || response.destroyed || response.socket?.destroyed) markClientAborted();
        if (timingMode === 'captured') {
          const targetUs = Math.min(chunk.offset_us, 60 * 1_000_000);
          const elapsedUs = Number(process.hrtime.bigint() - started) / 1_000;
          if (targetUs > elapsedUs) {
            await Promise.race([
              new Promise((resolve) => setTimeout(resolve, Math.ceil((targetUs - elapsedUs) / 1_000))),
              closingSignal,
            ]);
            if (closing) return;
          }
        }
        if (!await writeChunk(restoreBuffer(decodeBase64Strict(chunk.data_base64, 'replay response chunk', MAX_RECORDING_RESPONSE_BYTES), this.ledger))) {
          allChunksDelivered = false;
          break;
        }
      }
      if (!allChunksDelivered) return;
      if (exchange.response.outcome === 'completed') {
        if (request.aborted || request.readableAborted || response.destroyed || response.socket?.destroyed) markClientAborted();
        if (clientAborted || response.destroyed) return;
        await new Promise((resolve) => {
          let settled = false;
          const settle = (consumed) => {
            if (settled) return;
            settled = true;
            terminal = true;
            response.removeListener('close', onClose);
            if (consumed) markConsumed(exchangeIndex);
            resolve();
          };
          const onClose = () => settle(false);
          response.once('close', onClose);
          try {
            if (request.aborted || request.readableAborted || response.destroyed || response.socket?.destroyed) markClientAborted();
            serverTerminating = true;
            response.end(() => settle(!clientAborted && !response.destroyed && !response.socket?.destroyed));
          } catch {
            settle(false);
          }
        });
        return;
      }
      // A recorded disconnect/error is a partial response: flush the headers
      // and every recorded chunk before cutting the connection.  Destroying
      // immediately after writeHead loses both the status and partial body.
      try {
        response.flushHeaders();
      } catch {
        return;
      }
      await new Promise((resolve) => setImmediate(resolve));
      if (exchange.response.outcome === 'client_disconnected' || exchange.response.outcome === 'timed_out') {
        // These outcomes are caused by the downstream, not by the replay
        // fixture.  Keep the response open until the client actually aborts;
        // closing the fixture during finish() must remain unconsumed.
        if (response.destroyed && !clientAborted) markClientAborted();
        if (!clientAborted && !response.destroyed) await clientAbort;
        if (!closing && clientAborted && !terminal) {
          terminal = true;
          markConsumed(exchangeIndex);
        }
        return;
      }
      if (clientAborted || response.destroyed) return;
      serverTerminating = true;
      await new Promise((resolve) => {
        const onClose = () => {
          response.removeListener('error', onError);
          resolve();
        };
        const onError = () => {
          response.removeListener('close', onClose);
          resolve();
        };
        response.once('close', onClose);
        response.once('error', onError);
        if (exchange.response.outcome === 'transport_error') response.destroy(new Error('replay transport error'));
        else response.destroy();
      });
      if (!closing && !clientAborted) {
        terminal = true;
        markConsumed(exchangeIndex);
      }
      })();
    } finally {
      activeHandlers -= 1;
      handlerIdle.notify();
    }
    });
    return {
      ...fixture,
      get consumed() { return nextExchange; },
      async finish() {
        try {
          while (activeHandlers > 0) await handlerIdle.wait(PROCESS_STOP_TIMEOUT_MS);
        } catch {}
        if (!closing) {
          closing = true;
          notifyClosing();
        }
        let error;
        try { await fixture.close(); } catch (closeError) { error = closeError; }
        if (!error) {
          try {
            while (activeHandlers > 0) await handlerIdle.wait(PROCESS_STOP_TIMEOUT_MS);
          } catch (waitError) {
            error = new HarnessFailure('REPLAY_TERMINAL_TIMEOUT', 'replay handler did not reach a bounded terminal state', {
              activeHandlers,
              cause: waitError instanceof Error ? waitError.message : String(waitError),
            });
          }
        }
        if (!error && nextExchange !== (cassette.exchanges || []).length) {
          error = new HarnessFailure('REPLAY_UNCONSUMED_EXCHANGES', 'replay server closed before consuming the complete cassette', {
            consumed: nextExchange,
            expected: cassette.exchanges?.length || 0,
          });
        }
        if (error) throw error;
      },
    };
  }

  async startReplayEdge(cassetteOrPath, {
    timingMode = 'immediate',
    canonicalOrigin,
    onDispatch,
  } = {}) {
    if (canonicalOrigin === undefined) {
      throw new HarnessFailure('ORIGIN_INVALID', 'replay edge requires a canonical origin for exact Host restoration');
    }
    const cassette = this._readCassette(cassetteOrPath);
    const replayServer = await this.startReplayServer(cassetteOrPath, { timingMode });
    let nextEdgeExchange = 0;
    let edgeReservationTail = Promise.resolve();
    const reserveEdgeExchange = async () => {
      const predecessor = edgeReservationTail;
      let release;
      edgeReservationTail = new Promise((resolve) => { release = resolve; });
      await predecessor;
      if (nextEdgeExchange >= (cassette.exchanges || []).length) {
        release();
        throw new HarnessFailure('REPLAY_EXTRA_REQUEST', 'replay edge received more requests than the cassette contains');
      }
      const exchangeIndex = nextEdgeExchange;
      nextEdgeExchange += 1;
      let released = false;
      const reservation = {
        exchangeIndex,
        release() {
          if (released) return;
          released = true;
          release();
        },
      };
      return reservation;
    };
    let edge;
    try {
      edge = await startHttpServer(async (request, response) => {
        const reservation = await reserveEdgeExchange();
        try {
          if (typeof onDispatch === 'function') {
            await onDispatch({ request, exchangeIndex: reservation.exchangeIndex });
          }
          const capturedHeaders = cassette.exchanges[reservation.exchangeIndex]?.request_headers || {};
          const extraHeaders = {};
          for (const name of ['forwarded', 'x-forwarded-host']) {
            if (request.headers[name] === undefined && capturedHeaders[name] !== undefined) {
              extraHeaders[name] = this.ledger.restore(capturedHeaders[name]);
            }
          }
          return await this.withRecordingDisabled(() => proxyHttp({
            targetBaseUrl: replayServer.baseUrl,
            request,
            response,
            extraHeaders,
            boundary: 'replay-canonical-edge',
            journal: this,
            ledger: this.ledger,
            canonicalOrigin,
          }));
        } finally {
          // Keep the edge reservation through proxyHttp's complete request
          // body read and replay response terminal.  A later browser request
          // cannot overtake a held body merely because its headers arrived.
          reservation.release();
        }
      });
    } catch (error) {
      try { await replayServer.finish(); } catch {}
      throw error;
    }
    let finished = false;
    return {
      server: replayServer,
      edge,
      baseUrl: edge.baseUrl,
      replayBaseUrl: replayServer.baseUrl,
      get consumed() { return replayServer.consumed; },
      get failures() { return [...edge.failures, ...replayServer.failures]; },
      get failure() { return replayServer.failures[0] || edge.failures[0]; },
      async finish() {
        if (finished) return;
        finished = true;
        let error;
        try { await edge.close(); } catch (closeError) { error = closeError; }
        try { await replayServer.finish(); } catch (replayError) { error ||= replayError; }
        if (error) throw error;
      },
    };
  }

  async _replayExchange(exchange, { baseUrl, boundaryBaseUrls = {}, headers, timingMode }) {
    if (timingMode !== 'immediate' && timingMode !== 'captured') {
      throw new HarnessFailure('REPLAY_MODE_INVALID', 'replay timing mode is invalid');
    }
    const requestBody = restoreBuffer(decodeBase64Strict(exchange.request_body.raw_base64, 'replay request body', MAX_RECORDING_REQUEST_BYTES), this.ledger);
    const requestHeaders = { ...restoreHeaders(exchange.request_headers, this.ledger), ...headers };
    const target = new URL(
      this.ledger.restore(exchange.path),
      boundaryBaseUrls[exchange.boundary] || baseUrl,
    );
    const expectedHeaders = normalizeHeaders(restoreHeaders(exchange.request_headers, this.ledger));
    const actualHeaders = normalizeHeaders(requestHeaders);
    const requestHeaderNames = new Set([...Object.keys(expectedHeaders), ...Object.keys(actualHeaders)]);
    for (const name of requestHeaderNames) {
      if (actualHeaders[name] !== expectedHeaders[name]) {
        throw new HarnessFailure('REPLAY_REQUEST_HEADER_MISMATCH', 'replay request headers differed from the captured exchange', { name });
      }
    }
    const response = await requestRaw(target, {
      method: exchange.method,
      headers: requestHeaders,
      body: requestBody,
      timeoutMs: HTTP_TIMEOUT_MS,
    });
    const expectedResponseHeaders = normalizeHeaders(restoreHeaders(exchange.response.headers, this.ledger));
    const actualResponseHeaders = normalizeHeaders(publicHeaders(response.headers));
    const responseHeaderNames = new Set([...Object.keys(expectedResponseHeaders), ...Object.keys(actualResponseHeaders)]);
    for (const name of responseHeaderNames) {
      if (actualResponseHeaders[name] !== expectedResponseHeaders[name]) {
        throw new HarnessFailure('REPLAY_RESPONSE_HEADER_MISMATCH', 'replay response headers differed from the captured exchange', { name });
      }
    }
    const expectedChunks = exchange.response.chunks.map((chunk) => decodeBase64Strict(chunk.data_base64, 'replay response chunk', MAX_RECORDING_RESPONSE_BYTES));
    // A live HTTP hop is allowed to coalesce or split transport reads.  The
    // replay server below re-emits the captured chunk boundaries, but a
    // same-entry replay through a real product/edge can only compare the
    // ordered response bytes and terminal outcome.  Treating Node's read
    // segmentation as product semantics makes a captured CSS/font response
    // fail even when its status, headers, bytes, and termination all match.
    const expectedBody = Buffer.concat(expectedChunks);
    const actualBody = redactBuffer(Buffer.concat(response.chunks.map((chunk) => chunk.data)), this.ledger);
    if (response.status !== exchange.response.status || !actualBody.equals(expectedBody)) {
      throw new HarnessFailure('REPLAY_MISMATCH', 'secret-safe cassette replay did not reproduce the public exchange', {
        expectedStatus: exchange.response.status,
        actualStatus: response.status,
        path: exchange.path,
      });
    }
    if (response.outcome !== exchange.response.outcome) {
      throw new HarnessFailure('REPLAY_TERMINATION_MISMATCH', 'replay response termination differed from the captured exchange', {
        expected: exchange.response.outcome,
        actual: response.outcome,
        path: exchange.path,
      });
    }
    return {
      status: response.status,
      path: exchange.path,
      outcome: response.outcome,
      // Proof summaries use the captured logical chunk count.  The byte
      // comparison above intentionally tolerates transport re-segmentation;
      // startReplayServer remains the exact chunk-boundary replay primitive.
      chunks: expectedChunks.length,
    };
  }

  assertFlushed() {
    this._healthy();
    if (this.active.size) {
      throw new HarnessFailure('RECORDING_FLUSH_FAILURE', 'recording capture closed with unflushed exchanges', {
        active: [...this.active.keys()],
      });
    }
  }

  async waitForIdle(timeoutMs = PROCESS_STOP_TIMEOUT_MS) {
    await withTimeout((async () => {
      while (this.active.size) await new Promise((resolve) => setImmediate(resolve));
    })(), timeoutMs, 'recording capture did not reach an idle boundary');
    this.assertFlushed();
  }

  async waitForFatal(timeoutMs = HTTP_TIMEOUT_MS) {
    if (this.fatalError) return this.fatalError;
    return this.fatalBarrier.wait(timeoutMs);
  }
}

class RealProcess {
  constructor({ name, child, baseUrl, output, ledger, logDir, locatorPath, locator, startupCapture }) {
    this.name = name;
    this.child = child;
    this.baseUrl = baseUrl;
    this.output = output;
    this.ledger = ledger;
    this.logDir = logDir;
    this.locatorPath = locatorPath;
    this.locator = locator;
    this.startupCapture = startupCapture;
    this.captureError = undefined;
    this.stopResult = undefined;
    this.exitPromise = child && typeof child.once === 'function'
      ? new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })))
      : Promise.resolve({ code: undefined, signal: undefined });
    this.stopped = false;
  }

  static async start({
    name,
    binary,
    args,
    cwd,
    env,
    readyPrefix,
    ledger,
    logDir,
    startupCaptureRoot,
    startupConfigBytes,
    e2eName,
    startupCapture,
  }) {
    if (!processSeam) {
      throw new HarnessFailure('HARNESS_PROCESS_SEAM_MISSING', 'browser harness process seam is unavailable', {
        path: PROCESS_SEAM_PATH,
      });
    }
    if (!binary || !fs.existsSync(binary)) {
      throw new HarnessFailure('HARNESS_BINARY_MISSING', `${name} binary is missing`, { name, binary });
    }
    try {
      fs.accessSync(binary, fs.constants.X_OK);
    } catch {
      throw new HarnessFailure('HARNESS_BINARY_NOT_EXECUTABLE', `${name} binary is not executable`, { name, binary });
    }
    if (!startupCapture && startupCaptureRoot !== undefined) {
      startupCapture = new StartupCapture({
        root: startupCaptureRoot,
        role: name,
        e2eName: e2eName || 'web-e2e-process-startup',
        configBytes: startupConfigBytes,
        ledger,
      });
      startupCapture.arm();
    }
    if (!startupCapture || startupCapture.armed !== true) {
      throw new HarnessFailure('PROCESS_CAPTURE_NOT_ARMED', 'durable process capture must be armed before spawn', { name });
    }
    startupCapture.assertArmed();
    const locatorDir = ensureDirectory(path.join(logDir, '..', 'process-locators'));
    const markers = [...ledger.entries.values()].map((entry) => entry.value);
    let started;
    try {
      started = await processSeam.startProcess({
        executable: binary,
        role: name,
        sessionId: `${name}-${randomUUID()}`,
        args,
        cwd,
        env,
        locatorDir,
        secretMarkers: markers,
        detach: false,
        capture: startupCapture,
        requireCapture: true,
      });
    } catch (error) {
      throw new HarnessFailure('PROCESS_START_FAILURE', `${name} could not start through the process seam`, { name });
    }
    const output = { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), lines: [] };
    const process = new RealProcess({
      name,
      child: started.child,
      baseUrl: undefined,
      output,
      ledger,
      logDir,
      locatorPath: started.locatorPath,
      locator: started.locator,
      startupCapture,
    });
    try {
      startupCapture.captureProcessObservation(process, { phase: 'spawned' });
    } catch (error) {
      try { await process.stop(); } catch {}
      throw error;
    }
    process.exitPromise.then(() => {
      // Once stopProcess has returned, its stop proof is the authoritative
      // terminal observation; do not let the later Node `exit` callback
      // overwrite the durable phase=stop record.
      if (process.stopResult) return;
      try {
        startupCapture.captureProcessObservation(process, {
          phase: 'exit',
          stopResult: process.stopResult,
        });
      } catch (error) {
        process.captureError ||= error;
      }
    });
    let baseUrl;
    try {
      if (started.locatorPath) {
        const locator = processSeam.readLocator(started.locatorPath);
        process.locator = locator;
        const readyLog = `${started.locatorPath}.stdout.log`;
        baseUrl = await Promise.race([
          waitForReadyLog(
            readyLog,
            readyPrefix,
            READY_TIMEOUT_MS,
            () => startupCapture.captureProcessObservation(process, { phase: 'ready_probe' }),
          ),
          process.exitPromise.then((status) => {
            // A child may flush a readiness line and exit in the same event
            // turn.  Prefer the durable line already present in quarantine to
            // misclassifying that observation as an exit-before-ready race.
            startupCapture.captureProcessObservation(process, { phase: 'exit' });
            return readyAfterExit(readyLog, readyPrefix).then((ready) => {
              if (ready) return ready;
              throw new HarnessFailure('PROCESS_EXITED_BEFORE_READY', `${name} exited before publishing readiness`, {
                name,
                exitCode: status.code,
                signal: status.signal,
              });
            });
          }),
        ]);
      }
    } catch (error) {
      let stopError;
      try { await process.stop(); } catch (cleanupError) { stopError = cleanupError; }
      let quarantinePath;
      if (startupCapture) {
        try {
          quarantinePath = await startupCapture.flushFailure({ process, failure: error, stopError });
        } catch (captureError) {
          throw captureError instanceof HarnessFailure
            ? captureError
            : new HarnessFailure('STARTUP_CAPTURE_FLUSH_FAILURE', `${name} startup evidence could not be durably captured`, { name });
        }
      }
      const failure = error instanceof HarnessFailure
        ? error
        : new HarnessFailure('PROCESS_NOT_READY', `${name} did not become ready`, { name });
      failure.details = { ...failure.details, ...(quarantinePath ? { quarantinePath } : {}) };
      if (stopError && ['PROCESS_REAP_FAILURE', 'PROCESS_OUTPUT_FLUSH_FAILURE'].includes(stopError.classification)) {
        stopError.details = { ...stopError.details, ...(quarantinePath ? { quarantinePath } : {}) };
        throw stopError;
      }
      throw failure;
    }
    if (!/^https?:\/\/[^\s]+$/.test(baseUrl)) {
      const failure = new HarnessFailure('PROCESS_READY_LINE_INVALID', `${name} readiness line did not contain a URL`, { name });
      let stopError;
      try { await process.stop(); } catch (cleanupError) { stopError = cleanupError; }
      let quarantinePath;
      if (startupCapture) quarantinePath = await startupCapture.flushFailure({ process, failure, stopError });
      failure.details = { ...failure.details, ...(quarantinePath ? { quarantinePath } : {}) };
      if (stopError && ['PROCESS_REAP_FAILURE', 'PROCESS_OUTPUT_FLUSH_FAILURE'].includes(stopError.classification)) {
        stopError.details = { ...stopError.details, ...(quarantinePath ? { quarantinePath } : {}) };
        throw stopError;
      }
      throw failure;
    }
    process.baseUrl = baseUrl;
    return process;
  }

  async stop() {
    if (this.stopped) return;
    this.stopped = true;
    if (!processSeam || !this.locatorPath) {
      throw new HarnessFailure('HARNESS_PROCESS_SEAM_MISSING', `${this.name} has no process seam locator`, { name: this.name });
    }
    let stopResult;
    stopResult = await processSeam.stopProcess({
      locatorPath: this.locatorPath,
      timeoutMs: PROCESS_STOP_TIMEOUT_MS,
      secretMarkers: [...this.ledger.entries.values()].map((entry) => entry.value),
    });
    this.stopResult = stopResult;
    try {
      this.startupCapture?.captureProcessObservation(this, {
        phase: 'stop',
        stopResult,
      });
    } catch (error) {
      this.captureError ||= error;
      throw error;
    }
    if (this.captureError) throw this.captureError;
    if (stopResult.timed_out || stopResult.leaked_pids?.length) {
      throw new HarnessFailure('PROCESS_REAP_FAILURE', `${this.name} process group was not fully reaped`, {
        name: this.name,
        leakedPids: stopResult.leaked_pids,
      });
    }
    if (stopResult.flush_status === 'secret_marker') {
      throw new SecretLeakFailure(`${this.name} process output`, 'process_output');
    }
    if (stopResult.flush_status !== 'ok') {
      throw new HarnessFailure('PROCESS_OUTPUT_FLUSH_FAILURE', `${this.name} process output was not durably flushed`, {
        name: this.name,
        flushStatus: stopResult.flush_status,
      });
    }
    if (this.locatorPath) {
      const stdoutPath = `${this.locatorPath}.stdout.log`;
      const stderrPath = `${this.locatorPath}.stderr.log`;
      this.output.stdout = fs.existsSync(stdoutPath) ? fs.readFileSync(stdoutPath) : Buffer.alloc(0);
      this.output.stderr = fs.existsSync(stderrPath) ? fs.readFileSync(stderrPath) : Buffer.alloc(0);
    }
    ensureDirectory(this.logDir);
    const stdoutPath = path.join(this.logDir, `${this.name}.stdout.log`);
    const stderrPath = path.join(this.logDir, `${this.name}.stderr.log`);
    writePrivateFile(stdoutPath, this.output.stdout);
    writePrivateFile(stderrPath, this.output.stderr);
    const leak = this.ledger.find(Buffer.concat([this.output.stdout, this.output.stderr]));
    if (leak) throw new SecretLeakFailure(`${this.name} process output`, leak.label);
  }
}

async function proxyHttp({
  targetBaseUrl,
  request,
  response,
  extraHeaders,
  boundary,
  journal,
  ledger,
  captureSetId,
  canonicalOrigin,
  preserveIncomingHost = false,
}) {
  // Register the ingress before parsing the target, reading the body, or
  // deciding whether this request is admissible.  A malformed/aborted/bounded
  // request is still a first occurrence and must remain recoverable in the
  // test-owned quarantine.  No upstream request is allowed before the
  // request_end marker has been durably appended.
  let recording;
  const inboundHeaders = { ...request.headers, ...extraHeaders };
  try {
    recording = journal.beginIngress({
      boundary,
      method: request.method,
      requestPath: request.url,
      requestHeaders: inboundHeaders,
      captureSetId: captureSetId || journal.currentCaptureSetId,
    });
  } catch {
    if (!response.headersSent) response.writeHead(503, { 'content-type': 'application/json' });
    if (!response.writableEnded) response.end(JSON.stringify({ error: { code: 'recording_unavailable', retryable: true } }));
    return;
  }
  let requestBody;
  const finishIngressFailure = (error) => {
    const classification = error?.classification || error?.code;
    const status = classification === 'BOUND_EXCEEDED' ? 413
      : classification === 'RECORDING_FLUSH_FAILURE' ? 503 : 400;
    try {
      if (recording.responseStatus === undefined) {
        journal.responseStarted(recording, {
          status,
          headers: { 'content-type': 'application/json' },
        });
      }
      journal.finish(recording, classification === 'BOUND_EXCEEDED' ? 'disconnected' : 'transport_error');
    } catch (flushError) {
      journal._fail(flushError);
    }
    if (response.destroyed || response.writableEnded) return;
    if (!response.headersSent) response.writeHead(status, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: {
      code: classification === 'BOUND_EXCEEDED' ? 'request_body_too_large' : 'request_capture_failed',
      retryable: false,
    } }));
  };
  try {
    requestBody = await readRequestBody(
      request,
      MAX_RECORDING_REQUEST_BYTES,
      (chunk) => journal.ingressChunk(recording, chunk),
    );
    // `readRequestBody` only resolves after the final chunk has been written;
    // endIngress adds a durable digest/length boundary before any parse or
    // network operation.
    requestBody = journal.endIngress(recording);
  } catch (error) {
    finishIngressFailure(error);
    return;
  }

  let target;
  const headers = { ...inboundHeaders };
  const incomingHost = headers.host;
  delete headers.host;
  delete headers.connection;
  delete headers['content-length'];
  delete headers['accept-encoding'];
  try {
    target = new URL(request.url, targetBaseUrl);
    const host = canonicalHost(canonicalOrigin);
    if (host !== undefined) headers.host = host;
    else if (preserveIncomingHost && incomingHost !== undefined) headers.host = incomingHost;
    headers['accept-encoding'] = 'identity';
    if (requestBody.length) headers['content-length'] = String(requestBody.length);
    journal.updateIngressHeaders(recording, headers);
  } catch (error) {
    finishIngressFailure(error);
    return;
  }
  let responseStartedAt = process.hrtime.bigint();
  let settled = false;
  let responseStatus;
  let responseHeaders;
  const bufferedChunks = [];
  const sendUnavailable = () => {
    if (response.destroyed || response.writableEnded) return;
    if (!response.headersSent) response.writeHead(503, { 'content-type': 'application/json' });
    if (!response.writableEnded) response.end(JSON.stringify({ error: { code: 'recording_unavailable', retryable: true } }));
  };
  const sendBuffered = () => {
    if (response.destroyed || response.writableEnded) return;
    response.writeHead(responseStatus, responseHeaders);
    for (const bytes of bufferedChunks) response.write(bytes);
    response.end();
  };
  const finish = (outcome) => {
    if (settled) return;
    settled = true;
    if (recording.responseStatus === undefined) {
      // A client can disconnect before the upstream emits headers. Preserve
      // that boundary as a bounded synthetic status rather than dropping an
      // otherwise durable first occurrence.
      try { journal.responseStarted(recording, { status: 499, headers: {} }); } catch {}
    }
    return journal.finish(recording, outcome);
  };
  const finishAndRespond = (outcome) => {
    try {
      finish(outcome);
      sendBuffered();
    } catch (error) {
      journal._fail(error);
      sendUnavailable();
    }
  };
  await new Promise((resolve) => {
    const upstream = http.request(target, { method: request.method, headers }, (upstreamResponse) => {
      responseStartedAt = process.hrtime.bigint();
      responseStatus = upstreamResponse.statusCode || 502;
      responseHeaders = upstreamResponse.headers;
      try {
        journal.responseStarted(recording, { status: responseStatus, headers: responseHeaders });
      } catch (error) {
        upstreamResponse.destroy();
        journal._fail(error);
        sendUnavailable();
        resolve();
        return;
      }
      upstreamResponse.on('data', (chunk) => {
        try {
          const bytes = Buffer.from(chunk);
          journal.chunk(recording, bytes, Number(process.hrtime.bigint() - responseStartedAt) / 1_000);
          bufferedChunks.push(bytes);
        } catch (error) {
          journal._fail(error);
          upstreamResponse.destroy();
          sendUnavailable();
          resolve();
        }
      });
      upstreamResponse.on('end', () => {
        finishAndRespond('completed');
        resolve();
      });
      upstreamResponse.on('aborted', () => {
        finishAndRespond('disconnected');
        resolve();
      });
      upstreamResponse.on('error', () => {
        finishAndRespond('transport_error');
        resolve();
      });
      upstreamResponse.once('close', () => {
        if (!settled && !upstreamResponse.complete) {
          finishAndRespond('disconnected');
          resolve();
        }
      });
    });
    upstream.on('error', (error) => {
      // The client may close immediately after the bounded disconnect
      // observation has been durably finished.  In that case the upstream
      // socket error is a late transport notification, not a second response
      // start; never turn it into a recording-state failure.
      if (recording.finished) {
        resolve();
        return;
      }
      responseStartedAt = process.hrtime.bigint();
      const upstreamErrorStatus = 502;
      const upstreamErrorHeaders = { 'content-type': 'application/json' };
      const body = Buffer.from(JSON.stringify({ error: { code: 'upstream_unavailable', retryable: true } }));
      try {
        journal.responseStarted(recording, { status: upstreamErrorStatus, headers: upstreamErrorHeaders });
        journal.chunk(recording, body, Number(process.hrtime.bigint() - responseStartedAt) / 1_000);
        responseStatus = upstreamErrorStatus;
        responseHeaders = upstreamErrorHeaders;
        bufferedChunks.push(body);
        finishAndRespond('transport_error');
      } catch (flushError) {
        journal._fail(flushError || error);
        sendUnavailable();
      }
      resolve();
    });
    response.once('close', () => {
      if (!settled && !upstream.destroyed) {
        upstream.destroy();
        try { finish('client_disconnected'); } catch {}
      }
    });
    upstream.end(requestBody);
  });
  const responseLeak = ledger.find(JSON.stringify(recording.responseHeaders));
  if (responseLeak) throw new SecretLeakFailure(`${boundary} response headers`, responseLeak.label);
  return recording.record;
}

async function startFakeProvider({ ledger }) {
  const requests = [];
  const requestBarrier = new Barrier('fake provider request');
  const fixture = await startHttpServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/healthz') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ ok: true }));
      return;
    }
    const body = await readRequestBody(request);
    const authorization = String(request.headers.authorization || '');
    const requestRecord = { method: request.method, path: request.url, body, authorization };
    requests.push(requestRecord);
    requestBarrier.notify(requestRecord);
    response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
    response.write('data: {"choices":[{"delta":{"content":"E2E_OK"},"finish_reason":null}]}\n\n');
    response.write('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n');
    response.end('data: [DONE]\n\n');
  });
  return {
    ...fixture,
    requests,
    requestBarrier,
    async waitForRequest(count = 1) {
      while (requests.length < count) await requestBarrier.wait();
      return requests[count - 1];
    },
    ledger,
  };
}

async function startRecordingProxy({ targetBaseUrl, journal, ledger, captureSetId }) {
  const fixture = await startHttpServer((request, response) => proxyHttp({
    targetBaseUrl,
    request,
    response,
    extraHeaders: {},
    boundary: 'provider-recording-proxy',
    journal,
    ledger,
    captureSetId: captureSetId || journal.currentCaptureSetId,
    canonicalOrigin: targetBaseUrl,
  }).catch((error) => {
    journal._fail(error);
    if (!response.writableEnded) response.end();
  }));
  return fixture;
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function signJwt(privateKey, header, claims) {
  const encodedHeader = base64UrlJson(header);
  const encodedClaims = base64UrlJson(claims);
  const signer = createSign('RSA-SHA256');
  signer.update(`${encodedHeader}.${encodedClaims}`);
  const signature = signer.sign(privateKey).toString('base64url');
  return `${encodedHeader}.${encodedClaims}.${signature}`;
}

async function startAccessFixture({ ledger, journal, captureSetId, managementOrigin, callbackOrigin }) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const kid = `web-e2e-${randomUUID()}`;
  const requests = [];
  const requestBarrier = new Barrier('JWKS request');
  const jwksServer = await startHttpServer(async (request, response) => {
    let recording;
    try {
      recording = journal.beginIngress({
        boundary: 'access-jwks-fixture',
        method: request.method,
        requestPath: request.url,
        requestHeaders: request.headers,
        captureSetId: captureSetId || journal.currentCaptureSetId,
      });
      await readRequestBody(request, MAX_RECORDING_REQUEST_BYTES, (chunk) => journal.ingressChunk(recording, chunk));
      journal.endIngress(recording);
    } catch (error) {
      journal._fail(error);
      response.writeHead(503, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: { code: 'recording_unavailable', retryable: true } }));
      return;
    }
    const notFound = request.method !== 'GET' || request.url !== '/jwks';
    const status = notFound ? 404 : 200;
    const body = notFound
      ? JSON.stringify({ error: { code: 'not_found' } })
      : JSON.stringify({ keys: [{ ...jwk, kid, use: 'sig', alg: 'RS256' }] });
    if (!notFound) {
      requests.push({ method: request.method, path: request.url });
      requestBarrier.notify(requests[requests.length - 1]);
    }
    try {
      journal.responseStarted(recording, {
        status,
        headers: { 'content-type': 'application/json', ...(notFound ? {} : { 'cache-control': 'no-store' }) },
      });
      journal.chunk(recording, Buffer.from(body), 0);
      journal.finish(recording, 'completed');
    } catch (error) {
      journal._fail(error);
      if (!response.headersSent) response.writeHead(503, { 'content-type': 'application/json' });
      if (!response.writableEnded) response.end(JSON.stringify({ error: { code: 'recording_unavailable', retryable: true } }));
      return;
    }
    response.writeHead(status, { 'content-type': 'application/json', ...(notFound ? {} : { 'cache-control': 'no-store' }) });
    response.end(body);
  });
  const issuer = jwksServer.baseUrl;
  let tokenNumber = 0;
  const issue = ({ service = false } = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const token = signJwt(privateKey, { alg: 'RS256', kid, typ: 'JWT' }, {
      iss: issuer,
      aud: ['zode-web-e2e-audience'],
      sub: service ? '' : 'web-e2e-human-subject',
      ...(service ? { common_name: 'web-e2e-service-client' } : {}),
      email: 'web-e2e-human@example.invalid',
      type: 'app',
      iat: now,
      nbf: now - 1,
      exp: now + 300,
    });
    tokenNumber += 1;
    ledger.add(`access_assertion_${tokenNumber}`, token);
    return token;
  };
  const access = {
    issuer,
    jwksUrl: `${jwksServer.baseUrl}/jwks`,
    jwksRequests: requests,
    jwksBarrier: requestBarrier,
    issue,
    async waitForJwksRequest() {
      while (requests.length < 1) await requestBarrier.wait();
    },
    jwksServer,
    edge: undefined,
  };
  access.startEdge = async (targetBaseUrl, { canonicalOrigin = managementOrigin, extraHeaders = {} } = {}) => {
    const edge = await startHttpServer((request, response) => {
      const assertion = issue();
      access.forwardedAssertions = (access.forwardedAssertions || 0) + 1;
      return proxyHttp({
        targetBaseUrl,
        request,
        response,
        extraHeaders: { 'cf-access-jwt-assertion': assertion, ...extraHeaders },
        boundary: 'management-access-edge',
        journal,
        ledger,
        captureSetId: captureSetId || journal.currentCaptureSetId,
        canonicalOrigin,
      }).catch((error) => {
        journal._fail(error);
        if (!response.writableEnded) {
          response.writeHead(502, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: { code: 'management_unavailable', retryable: true } }));
        }
      });
    });
    access.edge = edge;
    return edge;
  };
  access.startCallbackEdge = async (targetBaseUrl, { canonicalOrigin = callbackOrigin, extraHeaders = {} } = {}) => {
    const edge = await startHttpServer((request, response) => proxyHttp({
      targetBaseUrl,
      request,
      response,
      extraHeaders,
      boundary: 'callback-public-edge',
      journal,
      ledger,
      captureSetId: captureSetId || journal.currentCaptureSetId,
      canonicalOrigin,
    }).catch((error) => {
      journal._fail(error);
      if (!response.writableEnded) {
        response.writeHead(502, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ error: { code: 'callback_unavailable', retryable: true } }));
      }
    }));
    access.callbackEdge = edge;
    return edge;
  };
  return access;
}

function defaultEnv() {
  const env = { ...process.env, NODE_ENV: 'test' };
  for (const key of [
    'OPENCODE_API_KEY', 'DEEPSEEK_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY',
    'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY',
    'TOGETHER_API_KEY', 'XAI_API_KEY', 'GROQ_API_KEY', 'COHERE_API_KEY',
  ]) delete env[key];
  return env;
}

function resolveAuthorityId(value, fallback) {
  const authorityId = value === undefined ? fallback : value;
  if (typeof authorityId !== 'string'
    || authorityId.length === 0
    || Buffer.byteLength(authorityId, 'utf8') > 64
    || authorityId.trim() !== authorityId) {
    throw new HarnessFailure('AUTHORITY_INVALID', 'authorityId must be a bounded non-control string');
  }
  for (const character of authorityId) {
    const codePoint = character.codePointAt(0);
    if (codePoint < 0x20
      || (codePoint >= 0x7f && codePoint <= 0x9f)
      || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
      throw new HarnessFailure('AUTHORITY_INVALID', 'authorityId must be a bounded non-control string');
    }
  }
  return authorityId;
}

function endpointConfig({ root, database, providerOrigin, controllerSecret, authorityId }) {
  const credentials = ensureDirectory(path.join(root, 'credentials'));
  const blobs = ensureDirectory(path.join(root, 'blobs'));
  const secretFile = writePrivateFile(path.join(root, 'controller.secret'), controllerSecret);
  const controllerAuthorityId = resolveAuthorityId(authorityId, 'web-e2e-controller');
  return writeJsonPrivate(path.join(root, 'endpoint-config.json'), {
    schema: 'zode.config.v1',
    listen: '127.0.0.1:0',
    runtime_store: { kind: 'sqlite', path: database },
    credential_replica_store: { kind: 'files', directory: credentials },
    blob_store: { kind: 'files', directory: blobs },
    controller_auth: [{
      authority_id: controllerAuthorityId,
      revision: 1,
      kind: 'bearer_secret_file',
      secret_file: secretFile,
    }],
    runtime: {
      tool_foreground_ms: 100,
      max_rounds_per_activation: 8,
      model_step_max_attempts: 1,
      model_retry_base_ms: 1,
      model_retry_max_ms: 10,
      snapshot_every_events: 1,
    },
    provider_execution: {
      adapter_kinds: ['openai_compatible'],
      allowed_base_url_origins: [providerOrigin],
    },
    callback: { allowed_public_origins: [providerOrigin] },
    tools: [],
  });
}

async function buildUiAssets(directory, { ledger, sourceDirectory } = {}) {
  const configured = sourceDirectory || process.env.ZODE_UI_ASSETS_DIRECTORY;
  if (configured) {
    const source = path.resolve(configured);
    if (source !== path.resolve(directory)) {
      ensureDirectory(path.dirname(directory));
      try {
        fs.cpSync(source, directory, { recursive: true, force: false, errorOnExist: true });
      } catch (error) {
        throw new HarnessFailure('UI_ASSETS_DIRECTORY_UNWIRED', 'configured UI release tree could not be materialized beside the Server config', {
          source,
          destination: directory,
          cause: error instanceof Error ? error.message : String(error),
        });
      }
    } else {
      ensureDirectory(directory);
    }
  } else {
    ensureDirectory(directory);
    try {
      await execFileAsync('vp', ['build', '--outDir', directory], {
        cwd: path.join(ROOT, 'web'),
        env: defaultEnv(),
        timeout: 120_000,
        maxBuffer: 4 * 1024 * 1024,
      });
    } catch (error) {
      throw new HarnessFailure('UI_BUILD_FAILURE', 'Vite Plus did not produce the test-owned UI release tree', {
        directory,
        cause: error instanceof Error ? error.message : String(error),
      });
    }
  }
  const indexPath = path.join(directory, 'index.html');
  if (!fs.existsSync(indexPath) || !fs.statSync(indexPath).isFile()) {
    throw new HarnessFailure('UI_BUILD_FAILURE', 'UI release tree is missing index.html', { directory });
  }
  if (ledger) {
    const queue = [directory];
    let files = 0;
    while (queue.length) {
      const current = queue.shift();
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const target = path.join(current, entry.name);
        if (entry.isSymbolicLink()) throw new HarnessFailure('UI_BUILD_FAILURE', 'UI release tree contains a symlink', { directory });
        if (entry.isDirectory()) {
          queue.push(target);
          continue;
        }
        if (!entry.isFile() || ++files > 4_096) throw new HarnessFailure('UI_BUILD_FAILURE', 'UI release tree exceeded its file bound', { directory });
        const stat = fs.statSync(target);
        if (stat.size > MAX_RECORDING_RESPONSE_BYTES) throw new HarnessFailure('UI_BUILD_FAILURE', 'UI release asset exceeded its size bound', { directory });
        const leak = ledger.find(fs.readFileSync(target));
        if (leak) throw new SecretLeakFailure('UI release asset', leak.label);
      }
    }
  }
  return directory;
}

function serverConfig({ root, issuer, jwksUrl, managementOrigin, callbackOrigin, uiMode = 'api_only', uiAssetsDirectory, includeServerOrigins = false, authorityId }) {
  const management = loopbackOrigin(managementOrigin, 'management_origin');
  const callback = loopbackOrigin(callbackOrigin, 'callback_origin');
  const serverAuthorityId = resolveAuthorityId(authorityId, 'web-e2e-server');
  if (management === callback) {
    throw new HarnessFailure('ORIGIN_INVALID', 'management_origin and callback_origin must be distinct');
  }
  if (uiMode !== 'api_only' && uiMode !== 'assets') {
    throw new HarnessFailure('UI_MODE_INVALID', 'browser harness Server ui_mode must be assets or api_only');
  }
  if (uiMode === 'assets' && (!uiAssetsDirectory || typeof uiAssetsDirectory !== 'string')) {
    throw new HarnessFailure('UI_ASSETS_DIRECTORY_UNWIRED', 'assets mode requires the built UI release directory');
  }
  if (uiMode === 'api_only' && uiAssetsDirectory !== undefined) {
    throw new HarnessFailure('UI_ASSETS_DIRECTORY_UNWIRED', 'api_only mode forbids a UI assets directory');
  }
  const secretDirectory = ensureDirectory(path.join(root, 'server-secrets'));
  const subjectKey = path.join(root, 'subject.key');
  fs.writeFileSync(subjectKey, Buffer.alloc(32, 0x42), { flag: 'wx', mode: 0o600 });
  try { fs.chmodSync(subjectKey, 0o600); } catch {}
  const config = {
    schema: 'zode.server-config.v1',
    listen: '127.0.0.1:0',
    server_authority_id: serverAuthorityId,
    deployment: 'server_only',
    ui_mode: uiMode,
    ...(uiMode === 'assets' ? { ui_assets_directory: uiAssetsDirectory } : {}),
    control_database: path.join(root, 'server.sqlite3'),
    secret_directory: secretDirectory,
    access: {
      issuer,
      audiences: ['zode-web-e2e-audience'],
      jwks_url: jwksUrl,
      subject_key_file: subjectKey,
      subject_key_version: 1,
    },
  };
  // The current Server config schema does not yet own the top-level origin
  // fields. Keep the real Access edges canonical while allowing a consumer
  // running a Server that has adopted that schema extension to opt in
  // explicitly; never probe by spawning a second child after a config error.
  if (includeServerOrigins) {
    config.management_origin = management;
    config.callback_origin = callback;
  }
  return writeJsonPrivate(path.join(root, 'server-config.json'), config);
}

function serverLogDir(runRoot, generation) {
  return path.join(runRoot, 'logs', `server-generation-${generation}`);
}

function startServerProcess({ runRoot, generation, startSpec }) {
  return RealProcess.start({
    ...startSpec,
    logDir: serverLogDir(runRoot, generation),
  });
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: options.signal || AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { body = undefined; }
  return { response, status: response.status, body, text };
}

class WebE2EHarness {
  constructor({ runRoot, ledger, journal, fakeProvider, providerProxy, access, endpoint, server, edge, callbackEdge, managementOrigin, callbackOrigin, authorityId, serverStartSpec, serverGeneration, controllerSecret, providerSecret, uiMode, uiAssetsDirectory }) {
    this.runRoot = runRoot;
    this.ledger = ledger;
    this.journal = journal;
    this.fakeProvider = fakeProvider;
    this.providerProxy = providerProxy;
    this.access = access;
    this.endpoint = endpoint;
    this.server = server;
    this.edge = edge;
    this.callbackEdge = callbackEdge;
    this.managementOrigin = managementOrigin;
    this.callbackOrigin = callbackOrigin;
    this.authorityId = authorityId;
    this.serverStartSpec = serverStartSpec;
    this.serverGeneration = serverGeneration;
    this.controllerSecret = controllerSecret;
    this.providerSecret = providerSecret;
    this.uiMode = uiMode;
    this.uiAssetsDirectory = uiAssetsDirectory;
    this.closed = false;
  }

  get managementUrl() { return this.edge.baseUrl; }

  get callbackUrl() { return this.callbackEdge.baseUrl; }

  beginCaptureSet(options = {}) {
    const captureSetId = this.journal.beginCaptureSet(options);
    this.captureSetId = captureSetId;
    return captureSetId;
  }

  flushCaptureSet(captureSetId) {
    return this.journal.flushCaptureSet(captureSetId);
  }

  async promoteCaptureSet(captureSetId, options = {}) {
    return this.journal.promoteCaptureSet(captureSetId, {
      ...options,
      replay: options.replay || (async (envelope) => ({
        ok: true,
        results: await this.journal.replay(envelope, {
          baseUrl: this.managementUrl,
          boundaryBaseUrls: {
            'access-jwks-fixture': this.access.jwksServer.baseUrl,
            'provider-recording-proxy': this.providerProxy.baseUrl,
            'callback-public-edge': this.callbackUrl,
          },
        }),
      })),
    });
  }

  async serverReady() {
    const result = await fetchJson(`${this.managementUrl}/v1/system`, {
      headers: { accept: 'application/json' },
    });
    if (result.status !== 200 || result.body?.schema !== 'zode.system.v1') {
      throw new ProductBehaviorFailure(
        'SERVER_READY_BEHAVIOR_FAILURE',
        'real Server public readiness barrier did not succeed',
        { status: result.status },
      );
    }
    return result.body;
  }

  async restartServer() {
    if (this.closed) throw new HarnessFailure('HARNESS_CLOSED', 'cannot restart a closed WebE2EHarness');
    const previousEdge = this.edge;
    const previousCallbackEdge = this.callbackEdge;
    const previousServer = this.server;
    const nextGeneration = this.serverGeneration + 1;
    this.serverGeneration = nextGeneration;
    let stopError;
    try {
      await previousEdge?.close();
    } catch (error) {
      stopError ||= error;
    }
    try {
      await previousCallbackEdge?.close();
    } catch (error) {
      stopError ||= error;
    }
    try {
      await previousServer?.stop();
    } catch (error) {
      stopError ||= error;
    }
    if (stopError) throw stopError;

    let restartedServer;
    let restartedEdge;
    let restartedCallbackEdge;
    try {
      restartedServer = await startServerProcess({
        runRoot: this.runRoot,
        generation: nextGeneration,
        startSpec: this.serverStartSpec,
      });
      restartedEdge = await this.access.startEdge(restartedServer.baseUrl, { canonicalOrigin: this.managementOrigin });
      restartedCallbackEdge = await this.access.startCallbackEdge(restartedServer.baseUrl, { canonicalOrigin: this.callbackOrigin });
      this.server = restartedServer;
      this.edge = restartedEdge;
      this.callbackEdge = restartedCallbackEdge;
      await this.serverReady();
      return this.server;
    } catch (error) {
      try { await restartedEdge?.close(); } catch {}
      try { await restartedCallbackEdge?.close(); } catch {}
      try { await restartedServer?.stop(); } catch {}
      throw error;
    }
  }

  async endpointIdentity() {
    const result = await fetchJson(`${this.endpoint.baseUrl}/v1/identity`, {
      headers: {
        authorization: `Bearer ${this.controllerSecret}`,
        'zode-subject': 'web-e2e-subject',
      },
    });
    if (result.status !== 200 || result.body?.schema !== 'zode.identity.v1') {
      throw new ProductBehaviorFailure('ENDPOINT_IDENTITY_BEHAVIOR_FAILURE', 'real Endpoint identity barrier did not succeed', { status: result.status });
    }
    return result.body;
  }

  async captureAndReplayFailure(error, e2eName) {
    if (!(error instanceof HarnessFailure)) return { error };
    const requestPath = error.details?.path;
    const responseStatus = error.details?.status;
    if (typeof requestPath !== 'string' || typeof responseStatus !== 'number') {
      return { error, record: undefined };
    }
    const record = this.journal.first({
      boundary: 'management-access-edge',
      requestPath,
      responseStatus,
    });
    if (!record) return { error, record: undefined };
    const promoted = await this.journal.promoteCaptureSet(record.captureSetId, {
      e2eName,
      classification: error.classification,
      firstObserved: 'safe public response captured from the first real browser exchange',
      firstFailureRecordingId: record.recordingId,
      replay: async (envelope) => {
        const replay = await this.journal.replay(envelope, {
          baseUrl: this.managementUrl,
          boundaryBaseUrls: {
            'access-jwks-fixture': this.access.jwksServer.baseUrl,
            'provider-recording-proxy': this.providerProxy.baseUrl,
            'callback-public-edge': this.callbackUrl,
          },
        });
        return { ok: true, results: replay };
      },
    });
    return { error, record, ...promoted, replay: promoted.replay?.results || promoted.replay };
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    const closers = [
      this.edge,
      this.callbackEdge,
      this.access.jwksServer,
      this.server,
      this.endpoint,
      this.providerProxy,
      this.fakeProvider,
    ];
    let firstError;
    for (const resource of closers) {
      if (!resource) continue;
      try {
        if (typeof resource.stop === 'function') await resource.stop();
        else if (typeof resource.close === 'function') await resource.close();
      } catch (error) {
        firstError ||= error;
      }
    }
    try {
      if (this.journal.fatalError) this.journal.assertFlushed();
      else await this.journal.waitForIdle();
    } catch (error) {
      firstError ||= error;
    }
    ensureDirectory(path.join(this.runRoot, 'logs'));
    if (firstError) throw firstError;
  }
}

async function createWebE2EHarness(options = {}) {
  const runId = `${Date.now()}-${randomUUID()}`;
  const runRoot = ensureDirectory(path.join(ROOT, 'target', 'web-e2e-runs', runId));
  const quarantineRoot = ensureDirectory(path.join(ROOT, 'target', 'test-recordings', 'quarantine', runId));
  const ledger = new SecretLedger();
  const controllerSecret = `web-e2e-controller-secret-${runId}`;
  const providerSecret = `web-e2e-provider-secret-${runId}`;
  const authorityId = options.authorityId === undefined
    ? undefined
    : resolveAuthorityId(options.authorityId, 'web-e2e-controller');
  const managementOrigin = loopbackOrigin(options.managementOrigin || 'http://127.0.0.1', 'management_origin');
  const callbackOrigin = loopbackOrigin(options.callbackOrigin || 'http://127.0.0.2', 'callback_origin');
  if (managementOrigin === callbackOrigin) {
    throw new HarnessFailure('ORIGIN_INVALID', 'management_origin and callback_origin must be distinct');
  }
  ledger.add('controller_secret', controllerSecret);
  ledger.add('provider_secret', providerSecret);
  ledger.add('access_subject', 'web-e2e-human-subject');
  ledger.add('access_email', 'web-e2e-human@example.invalid');
  ledger.add('service_client', 'web-e2e-service-client');
  const journal = new RecordingJournal({ rootDir: quarantineRoot, ledger });
  let fakeProvider;
  let providerProxy;
  let access;
  let endpoint;
  let server;
  let edge;
  let callbackEdge;
  try {
    fakeProvider = await startFakeProvider({ ledger });
    providerProxy = await startRecordingProxy({ targetBaseUrl: fakeProvider.baseUrl, journal, ledger });
    access = await startAccessFixture({ ledger, journal, managementOrigin, callbackOrigin });
    const endpointRoot = ensureDirectory(path.join(runRoot, 'endpoint'));
    const serverRoot = ensureDirectory(path.join(runRoot, 'server'));
    const endpointConfigPath = endpointConfig({
      root: endpointRoot,
      database: path.join(endpointRoot, 'endpoint.sqlite3'),
      providerOrigin: providerProxy.baseUrl,
      controllerSecret,
      authorityId,
    });
    const uiMode = options.uiMode || process.env.ZODE_WEB_E2E_UI_MODE
      || (process.env.ZODE_UI_ASSETS_DIRECTORY ? 'assets' : 'api_only');
    const uiAssetsDirectory = uiMode === 'assets'
      ? await buildUiAssets(path.join(serverRoot, 'ui'), {
        ledger,
        sourceDirectory: options.uiAssetsDirectory || process.env.ZODE_UI_ASSETS_DIRECTORY,
      })
      : undefined;
    const serverConfigPath = serverConfig({
      root: serverRoot,
      issuer: access.issuer,
      jwksUrl: access.jwksUrl,
      managementOrigin,
      callbackOrigin,
      uiMode,
      uiAssetsDirectory,
      includeServerOrigins: options.includeServerOrigins === true,
      authorityId,
    });
    const startupCaptureRoot = path.join(quarantineRoot, 'startup');
    const startupE2eName = options.e2eName || 'web-e2e-harness-run';
    const env = defaultEnv();
    const endpointBinary = process.env.ZODE_ENDPOINT_BIN || path.join(ROOT, 'target', 'debug', 'zode');
    const serverBinary = process.env.ZODE_SERVER_BIN || path.join(ROOT, 'server', 'target', 'debug', 'zode-server');
    const serverStartSpec = {
      name: 'server',
      binary: serverBinary,
      args: ['--config', serverConfigPath],
      cwd: ROOT,
      env,
      readyPrefix: 'ZODE_SERVER_READY ',
      ledger,
      startupCaptureRoot,
      startupConfigBytes: redactBuffer(fs.readFileSync(serverConfigPath), ledger),
      e2eName: startupE2eName,
    };
    endpoint = await RealProcess.start({
      name: 'endpoint',
      binary: endpointBinary,
      args: ['--config', endpointConfigPath],
      cwd: ROOT,
      env,
      readyPrefix: 'ZODE_READY ',
      ledger,
      logDir: path.join(runRoot, 'logs'),
      startupCaptureRoot,
      startupConfigBytes: redactBuffer(fs.readFileSync(endpointConfigPath), ledger),
      e2eName: startupE2eName,
    });
    const serverGeneration = 1;
    server = await startServerProcess({
      runRoot,
      generation: serverGeneration,
      startSpec: serverStartSpec,
    });
    edge = await access.startEdge(server.baseUrl, { canonicalOrigin: managementOrigin });
    callbackEdge = await access.startCallbackEdge(server.baseUrl, { canonicalOrigin: callbackOrigin });
    const harness = new WebE2EHarness({
      runRoot,
      ledger,
      journal,
      fakeProvider,
      providerProxy,
      access,
      endpoint,
      server,
      edge,
      callbackEdge,
      managementOrigin,
      callbackOrigin,
      authorityId,
      serverStartSpec,
      serverGeneration,
      controllerSecret,
      providerSecret,
      uiMode,
      uiAssetsDirectory,
    });
    // Positive public barriers are part of harness construction.  A stdout
    // line alone is not evidence that the management route and endpoint are
    // usable through their real boundaries.
    await harness.serverReady();
    await harness.endpointIdentity();
    return harness;
  } catch (error) {
    for (const resource of [edge, callbackEdge, server, endpoint, access?.edge, access?.callbackEdge, access?.jwksServer, providerProxy, fakeProvider]) {
      try {
        if (resource?.stop) await resource.stop();
        else if (resource?.close) await resource.close();
      } catch {}
    }
    if (error instanceof HarnessFailure) throw error;
    throw new HarnessFailure('HARNESS_STARTUP_FAILURE', 'real-process harness setup failed');
  }
}

async function collectBrowserSse(page, url, { lastEventId, frameCount = 1, timeoutMs = HTTP_TIMEOUT_MS } = {}) {
  return page.evaluate(async ({ url: targetUrl, lastEventId: cursor, frameCount: count, timeout }) => {
    const headers = { accept: 'text/event-stream' };
    if (cursor) headers['last-event-id'] = cursor;
    const response = await fetch(targetUrl, { headers });
    if (!response.ok) return { status: response.status, frames: [] };
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const frames = [];
    let pending = '';
    const deadline = new Promise((_, reject) => setTimeout(() => reject(new Error('SSE barrier timed out')), timeout));
    const read = (async () => {
      while (frames.length < count) {
        const next = await reader.read();
        if (next.done) break;
        pending += decoder.decode(next.value, { stream: true });
        let boundary;
        while ((boundary = pending.indexOf('\n\n')) >= 0) {
          const block = pending.slice(0, boundary);
          pending = pending.slice(boundary + 2);
          const id = block.match(/^id:\s?(.*)$/m)?.[1] || '';
          const data = block.match(/^data:\s?(.*)$/m)?.[1] || '';
          frames.push({ id, data });
          if (frames.length >= count) break;
        }
      }
      await reader.cancel();
      return { status: response.status, frames };
    })();
    return Promise.race([read, deadline]);
  }, { url, lastEventId, frameCount, timeoutMs });
}

module.exports = {
  Barrier,
  buildUiAssets,
  HarnessFailure,
  ProductBehaviorFailure,
  ProductRouteMissing,
  RealProcess,
  RecordingJournal,
  requestRaw,
  serverConfig,
  SecretLedger,
  SecretLeakFailure,
  StartupCapture,
  WebE2EHarness,
  collectBrowserSse,
  createWebE2EHarness,
  proxyHttp,
  startAccessFixture,
  startHttpServer,
};
