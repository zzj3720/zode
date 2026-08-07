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
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const ROOT = path.resolve(__dirname, '../../..');
const READY_TIMEOUT_MS = 15_000;
const HTTP_TIMEOUT_MS = 8_000;

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

  add(label, value) {
    if (typeof value !== 'string' || value.length === 0) return;
    this.entries.set(`${label}:${this.entries.size}`, { label, value });
  }

  find(value) {
    if (value === undefined || value === null) return undefined;
    const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
    return [...this.entries.values()]
      .filter((entry) => entry.value && text.includes(entry.value))
      .sort((left, right) => right.value.length - left.value.length)[0];
  }

  redact(value) {
    let text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value ?? '');
    for (const entry of [...this.entries.values()].sort((left, right) => right.value.length - left.value.length)) {
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

function writePrivateFile(filePath, content) {
  ensureDirectory(path.dirname(filePath));
  fs.writeFileSync(filePath, content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {}
  return filePath;
}

function writeJsonPrivate(filePath, value) {
  return writePrivateFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
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
  const server = http.createServer(handler);
  server.on('clientError', (error, socket) => socket.destroy(error));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('fixture did not receive a TCP address');
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
    async close() {
      if (!server.listening) return;
      server.closeAllConnections?.();
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

function readRequestBody(request, maxBytes = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    request.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new HarnessFailure('BOUND_EXCEEDED', 'fixture request exceeded its bounded body size'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
    request.on('aborted', () => reject(new Error('fixture request was aborted')));
  });
}

function publicHeaders(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers || {})) {
    if (!['accept', 'content-type', 'cache-control', 'last-event-id', 'origin', 'user-agent'].includes(name.toLowerCase())) continue;
    result[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return result;
}

function redactedPath(rawPath, ledger) {
  try {
    const value = new URL(rawPath, 'http://fixture.invalid');
    for (const key of [...value.searchParams.keys()]) {
      if (['ticket', 'code', 'state', 'token', 'secret', 'authorization'].includes(key.toLowerCase())) {
        value.searchParams.set(key, `<secret:${key}>`);
      }
    }
    return ledger.redact(`${value.pathname}${value.search}`);
  } catch {
    return ledger.redact(rawPath);
  }
}

function safeBody(body, ledger) {
  const text = ledger.redact(body);
  let canonical;
  try {
    canonical = JSON.parse(text);
  } catch {}
  return {
    raw_base64: Buffer.from(text).toString('base64'),
    ...(canonical === undefined ? {} : { canonical_json: canonical }),
    sha256: sha256(text),
  };
}

class RecordingJournal {
  constructor({ rootDir, ledger }) {
    this.rootDir = ensureDirectory(rootDir);
    this.promotedDir = ensureDirectory(path.join(rootDir, 'promoted'));
    this.ledger = ledger;
    this.records = [];
    this.sequence = 0;
  }

  record({ boundary, method, requestPath, requestHeaders, requestBody, responseStatus, responseHeaders, responseChunks, outcome = 'completed' }) {
    const id = `${String(++this.sequence).padStart(6, '0')}-${randomUUID()}`;
    const raw = {
      schema: 'zode.http-incident-recording.v1',
      recording_id: id,
      boundary,
      method,
      path: requestPath,
      request_headers: requestHeaders,
      request_body_base64: Buffer.from(requestBody || '').toString('base64'),
      response: {
        status: responseStatus,
        headers: responseHeaders || {},
        chunks: (responseChunks || []).map((chunk) => ({
          offset_us: chunk.offsetUs,
          data_base64: Buffer.from(chunk.data).toString('base64'),
        })),
        outcome,
      },
    };
    const rawPath = path.join(this.rootDir, `${id}.raw.json`);
    fs.writeFileSync(rawPath, `${JSON.stringify(raw, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    try {
      fs.chmodSync(rawPath, 0o600);
    } catch {}
    const record = { ...raw, recordingId: id, rawPath };
    this.records.push(record);
    return record;
  }

  first({ boundary, requestPath, responseStatus } = {}) {
    return this.records.find((record) =>
      (boundary === undefined || record.boundary === boundary)
      && (requestPath === undefined || record.path === requestPath)
      && (responseStatus === undefined || record.response.status === responseStatus));
  }

  promote(record, { e2eName, classification, firstObserved }) {
    if (!record) throw new HarnessFailure('RECORDING_MISSING', 'first failing exchange was not retained');
    const safeExchange = {
      sequence: record.recordingId,
      method: record.method,
      path: redactedPath(record.path, this.ledger),
      request_headers: publicHeaders(record.request_headers),
      request_body: safeBody(Buffer.from(record.request_body_base64, 'base64'), this.ledger),
      response: {
        status: record.response.status,
        headers: publicHeaders(record.response.headers),
        chunks: record.response.chunks.map((chunk) => ({
          offset_us: chunk.offset_us,
          data_base64: Buffer.from(this.ledger.redact(Buffer.from(chunk.data_base64, 'base64'))).toString('base64'),
        })),
        outcome: record.response.outcome,
      },
    };
    const envelopeWithoutDigest = {
      schema: 'zode.http-incident-cassette.v1',
      recording_id: record.recordingId,
      e2e_name: e2eName,
      boundary: record.boundary,
      first_observed: firstObserved,
      classification,
      exchanges: [safeExchange],
      synthetic_secret_slots: [...this.ledger.entries.values()].map((entry) => `<secret:${entry.label}>`),
    };
    const envelope = {
      ...envelopeWithoutDigest,
      integrity_sha256: sha256(JSON.stringify(envelopeWithoutDigest)),
    };
    const cassettePath = path.join(this.promotedDir, `${record.recordingId}.v1.json`);
    fs.writeFileSync(cassettePath, `${JSON.stringify(envelope, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    try {
      fs.chmodSync(cassettePath, 0o444);
    } catch {}
    if (this.ledger.find(fs.readFileSync(cassettePath))) {
      throw new SecretLeakFailure('promoted cassette', this.ledger.find(fs.readFileSync(cassettePath)).label);
    }
    return { cassettePath, envelope };
  }

  async replay(cassettePath, { baseUrl, headers = {} }) {
    const cassette = JSON.parse(fs.readFileSync(cassettePath, 'utf8'));
    const { integrity_sha256: integrity, ...unsigned } = cassette;
    if (integrity !== sha256(JSON.stringify(unsigned))) {
      throw new HarnessFailure('CASSETTE_INTEGRITY_FAILURE', 'secret-safe cassette integrity verification failed');
    }
    const results = [];
    for (const exchange of cassette.exchanges) {
      const requestBody = Buffer.from(this.ledger.restore(Buffer.from(exchange.request_body.raw_base64, 'base64').toString('utf8')));
      const response = await fetch(new URL(this.ledger.restore(exchange.path), baseUrl), {
        method: exchange.method,
        headers: { ...exchange.request_headers, ...headers },
        body: requestBody.length ? requestBody : undefined,
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      const body = Buffer.from(await response.arrayBuffer());
      const expected = Buffer.concat(exchange.response.chunks.map((chunk) => Buffer.from(chunk.data_base64, 'base64')));
      const actual = Buffer.from(this.ledger.redact(body));
      if (response.status !== exchange.response.status || !actual.equals(expected)) {
        throw new HarnessFailure('REPLAY_MISMATCH', 'secret-safe cassette replay did not reproduce the public exchange', {
          expectedStatus: exchange.response.status,
          actualStatus: response.status,
          path: exchange.path,
        });
      }
      results.push({ status: response.status, path: exchange.path });
    }
    return results;
  }
}

class RealProcess {
  constructor({ name, child, baseUrl, output, ledger, logDir }) {
    this.name = name;
    this.child = child;
    this.baseUrl = baseUrl;
    this.output = output;
    this.ledger = ledger;
    this.logDir = logDir;
    this.exitPromise = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
    this.stopped = false;
  }

  static async start({ name, binary, args, cwd, env, readyPrefix, ledger, logDir }) {
    if (!binary || !fs.existsSync(binary)) {
      throw new HarnessFailure('HARNESS_BINARY_MISSING', `${name} binary is missing`, { name, binary });
    }
    try {
      fs.accessSync(binary, fs.constants.X_OK);
    } catch {
      throw new HarnessFailure('HARNESS_BINARY_NOT_EXECUTABLE', `${name} binary is not executable`, { name, binary });
    }
    const output = { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), lines: [] };
    const child = spawn(binary, args, {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const process = new RealProcess({ name, child, baseUrl: undefined, output, ledger, logDir });
    const lineReady = new Promise((resolve, reject) => {
      let pending = '';
      const onData = (chunk) => {
        output.stdout = Buffer.concat([output.stdout, chunk]);
        pending += chunk.toString('utf8');
        let index;
        while ((index = pending.indexOf('\n')) >= 0) {
          const line = pending.slice(0, index).replace(/\r$/, '');
          pending = pending.slice(index + 1);
          output.lines.push(line);
          if (line.startsWith(readyPrefix)) resolve(line.slice(readyPrefix.length).trim());
        }
      };
      child.stdout.on('data', onData);
      child.once('error', reject);
      child.once('exit', (code, signal) => {
        if (!process.baseUrl) reject(new HarnessFailure('PROCESS_NOT_READY', `${name} exited before readiness`, { name, code, signal }));
      });
    });
    child.stderr.on('data', (chunk) => { output.stderr = Buffer.concat([output.stderr, chunk]); });
    const baseUrl = await withTimeout(lineReady, READY_TIMEOUT_MS, `${name} readiness timed out`)
      .catch(async (error) => {
        await process.stop();
        throw error instanceof HarnessFailure
          ? error
          : new HarnessFailure('PROCESS_NOT_READY', `${name} did not become ready`, { name });
      });
    if (!/^https?:\/\/[^\s]+$/.test(baseUrl)) {
      await process.stop();
      throw new HarnessFailure('PROCESS_READY_LINE_INVALID', `${name} readiness line did not contain a URL`, { name });
    }
    process.baseUrl = baseUrl;
    return process;
  }

  async stop() {
    if (this.stopped) return;
    this.stopped = true;
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill('SIGTERM');
      try {
        await withTimeout(this.exitPromise, 3_000, `${this.name} did not stop after SIGTERM`);
      } catch {
        this.child.kill('SIGKILL');
        await withTimeout(this.exitPromise, 3_000, `${this.name} did not stop after SIGKILL`).catch(() => {});
      }
    } else {
      await this.exitPromise;
    }
    ensureDirectory(this.logDir);
    const stdoutPath = path.join(this.logDir, `${this.name}.stdout.log`);
    const stderrPath = path.join(this.logDir, `${this.name}.stderr.log`);
    fs.writeFileSync(stdoutPath, this.output.stdout, { flag: 'wx', mode: 0o600 });
    fs.writeFileSync(stderrPath, this.output.stderr, { flag: 'wx', mode: 0o600 });
    const leak = this.ledger.find(Buffer.concat([this.output.stdout, this.output.stderr]));
    if (leak) throw new SecretLeakFailure(`${this.name} process output`, leak.label);
  }
}

async function proxyHttp({ targetBaseUrl, request, response, extraHeaders, boundary, journal, ledger }) {
  const requestBody = await readRequestBody(request);
  const started = process.hrtime.bigint();
  const target = new URL(request.url, targetBaseUrl);
  const headers = { ...request.headers, ...extraHeaders };
  delete headers.host;
  delete headers.connection;
  delete headers['content-length'];
  delete headers['accept-encoding'];
  headers.host = target.host;
  headers['accept-encoding'] = 'identity';
  if (requestBody.length) headers['content-length'] = String(requestBody.length);
  const responseChunks = [];
  let responseStatus;
  let responseHeaders = {};
  let outcome = 'completed';
  await new Promise((resolve) => {
    const upstream = http.request(target, { method: request.method, headers }, (upstreamResponse) => {
      responseStatus = upstreamResponse.statusCode || 502;
      responseHeaders = upstreamResponse.headers;
      response.writeHead(responseStatus, responseHeaders);
      upstreamResponse.on('data', (chunk) => {
        responseChunks.push({
          offsetUs: Number(process.hrtime.bigint() - started) / 1_000,
          data: Buffer.from(chunk),
        });
        response.write(chunk);
      });
      upstreamResponse.on('end', () => {
        response.end();
        resolve();
      });
      upstreamResponse.on('aborted', () => {
        outcome = 'disconnected';
        response.end();
        resolve();
      });
    });
    upstream.on('error', () => {
      outcome = 'transport_error';
      responseStatus = 502;
      responseHeaders = { 'content-type': 'application/json' };
      const body = Buffer.from(JSON.stringify({ error: { code: 'upstream_unavailable', retryable: true } }));
      responseChunks.push({ offsetUs: Number(process.hrtime.bigint() - started) / 1_000, data: body });
      if (!response.headersSent) response.writeHead(responseStatus, responseHeaders);
      response.end(body);
      resolve();
    });
    upstream.end(requestBody);
  });
  const record = journal.record({
    boundary,
    method: request.method,
    requestPath: request.url,
    requestHeaders: headers,
    requestBody,
    responseStatus,
    responseHeaders,
    responseChunks,
    outcome,
  });
  if (ledger.find(JSON.stringify(responseHeaders))) throw new SecretLeakFailure(`${boundary} response headers`, ledger.find(JSON.stringify(responseHeaders)).label);
  return record;
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

async function startRecordingProxy({ targetBaseUrl, journal, ledger }) {
  const fixture = await startHttpServer((request, response) => proxyHttp({
    targetBaseUrl,
    request,
    response,
    extraHeaders: {},
    boundary: 'provider-recording-proxy',
    journal,
    ledger,
  }).catch(() => {
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

async function startAccessFixture({ ledger, journal }) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const kid = `web-e2e-${randomUUID()}`;
  const requests = [];
  const requestBarrier = new Barrier('JWKS request');
  const jwksServer = await startHttpServer(async (request, response) => {
    if (request.method !== 'GET' || request.url !== '/jwks') {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: { code: 'not_found' } }));
      return;
    }
    requests.push({ method: request.method, path: request.url });
    requestBarrier.notify(requests[requests.length - 1]);
    const body = JSON.stringify({ keys: [{ ...jwk, kid, use: 'sig', alg: 'RS256' }] });
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(body);
    journal.record({
      boundary: 'access-jwks-fixture',
      method: request.method,
      requestPath: request.url,
      requestHeaders: request.headers,
      requestBody: Buffer.alloc(0),
      responseStatus: 200,
      responseHeaders: { 'content-type': 'application/json' },
      responseChunks: [{ offsetUs: 0, data: Buffer.from(body) }],
    });
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
  access.startEdge = async (targetBaseUrl) => {
    const edge = await startHttpServer((request, response) => {
      const assertion = issue();
      access.forwardedAssertions = (access.forwardedAssertions || 0) + 1;
      return proxyHttp({
        targetBaseUrl,
        request,
        response,
        extraHeaders: { 'cf-access-jwt-assertion': assertion },
        boundary: 'management-access-edge',
        journal,
        ledger,
      }).catch(() => {
        if (!response.writableEnded) {
          response.writeHead(502, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ error: { code: 'management_unavailable', retryable: true } }));
        }
      });
    });
    access.edge = edge;
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

function endpointConfig({ root, database, providerOrigin, controllerSecret }) {
  const credentials = ensureDirectory(path.join(root, 'credentials'));
  const blobs = ensureDirectory(path.join(root, 'blobs'));
  const secretFile = writePrivateFile(path.join(root, 'controller.secret'), controllerSecret);
  return writeJsonPrivate(path.join(root, 'endpoint-config.json'), {
    schema: 'zode.config.v1',
    listen: '127.0.0.1:0',
    runtime_store: { kind: 'sqlite', path: database },
    credential_replica_store: { kind: 'files', directory: credentials },
    blob_store: { kind: 'files', directory: blobs },
    controller_auth: [{
      authority_id: 'web-e2e-controller',
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

function serverConfig({ root, issuer, jwksUrl }) {
  const secretDirectory = ensureDirectory(path.join(root, 'server-secrets'));
  const subjectKey = path.join(root, 'subject.key');
  fs.writeFileSync(subjectKey, Buffer.alloc(32, 0x42), { flag: 'wx', mode: 0o600 });
  try { fs.chmodSync(subjectKey, 0o600); } catch {}
  return writeJsonPrivate(path.join(root, 'server-config.json'), {
    schema: 'zode.server-config.v1',
    listen: '127.0.0.1:0',
    server_authority_id: 'web-e2e-server',
    deployment: 'server_only',
    control_database: path.join(root, 'server.sqlite3'),
    secret_directory: secretDirectory,
    access: {
      issuer,
      audiences: ['zode-web-e2e-audience'],
      jwks_url: jwksUrl,
      subject_key_file: subjectKey,
      subject_key_version: 1,
    },
  });
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
  constructor({ runRoot, ledger, journal, fakeProvider, providerProxy, access, endpoint, server, edge, serverStartSpec, serverGeneration, controllerSecret, providerSecret }) {
    this.runRoot = runRoot;
    this.ledger = ledger;
    this.journal = journal;
    this.fakeProvider = fakeProvider;
    this.providerProxy = providerProxy;
    this.access = access;
    this.endpoint = endpoint;
    this.server = server;
    this.edge = edge;
    this.serverStartSpec = serverStartSpec;
    this.serverGeneration = serverGeneration;
    this.controllerSecret = controllerSecret;
    this.providerSecret = providerSecret;
    this.closed = false;
  }

  get managementUrl() { return this.edge.baseUrl; }

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
      await previousServer?.stop();
    } catch (error) {
      stopError ||= error;
    }
    if (stopError) throw stopError;

    let restartedServer;
    let restartedEdge;
    try {
      restartedServer = await startServerProcess({
        runRoot: this.runRoot,
        generation: nextGeneration,
        startSpec: this.serverStartSpec,
      });
      restartedEdge = await this.access.startEdge(restartedServer.baseUrl);
      this.server = restartedServer;
      this.edge = restartedEdge;
      await this.serverReady();
      return this.server;
    } catch (error) {
      try { await restartedEdge?.close(); } catch {}
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
    const promoted = this.journal.promote(record, {
      e2eName,
      classification: error.classification,
      firstObserved: 'safe public response captured from the first real browser exchange',
    });
    const replay = await this.journal.replay(promoted.cassettePath, {
      baseUrl: this.managementUrl,
      headers: { accept: 'text/html' },
    });
    return { error, record, ...promoted, replay };
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    const closers = [
      this.edge,
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
    ensureDirectory(path.join(this.runRoot, 'logs'));
    if (firstError) throw firstError;
  }
}

async function createWebE2EHarness() {
  const runId = `${Date.now()}-${randomUUID()}`;
  const runRoot = ensureDirectory(path.join(ROOT, 'target', 'web-e2e-runs', runId));
  const quarantineRoot = ensureDirectory(path.join(ROOT, 'target', 'test-recordings', 'quarantine', runId));
  const ledger = new SecretLedger();
  const controllerSecret = `web-e2e-controller-secret-${runId}`;
  const providerSecret = `web-e2e-provider-secret-${runId}`;
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
  try {
    fakeProvider = await startFakeProvider({ ledger });
    providerProxy = await startRecordingProxy({ targetBaseUrl: fakeProvider.baseUrl, journal, ledger });
    access = await startAccessFixture({ ledger, journal });
    const endpointRoot = ensureDirectory(path.join(runRoot, 'endpoint'));
    const serverRoot = ensureDirectory(path.join(runRoot, 'server'));
    const endpointConfigPath = endpointConfig({
      root: endpointRoot,
      database: path.join(endpointRoot, 'endpoint.sqlite3'),
      providerOrigin: providerProxy.baseUrl,
      controllerSecret,
    });
    const serverConfigPath = serverConfig({
      root: serverRoot,
      issuer: access.issuer,
      jwksUrl: access.jwksUrl,
    });
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
    });
    const serverGeneration = 1;
    server = await startServerProcess({
      runRoot,
      generation: serverGeneration,
      startSpec: serverStartSpec,
    });
    edge = await access.startEdge(server.baseUrl);
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
      serverStartSpec,
      serverGeneration,
      controllerSecret,
      providerSecret,
    });
    return harness;
  } catch (error) {
    for (const resource of [edge, server, endpoint, access?.edge, access?.jwksServer, providerProxy, fakeProvider]) {
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
  HarnessFailure,
  ProductBehaviorFailure,
  ProductRouteMissing,
  RecordingJournal,
  SecretLeakFailure,
  WebE2EHarness,
  collectBrowserSse,
  createWebE2EHarness,
};
