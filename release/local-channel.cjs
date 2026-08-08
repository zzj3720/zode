#!/usr/bin/env node
'use strict';

/*
 * Persistent local test-channel entry.  It keeps an immutable artifact and
 * private local Access-edge key under one stable root, starts the ordinary
 * Server/Endpoint through release/channel.cjs, and prints one browser URL.
 * This is an operator/test-channel helper only; it does not add a product
 * release API and never accepts recorder/replay controls.
 */
const { generateKeyPairSync, randomUUID, sign } = require('node:crypto');
const {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const repository = path.resolve(__dirname, '..');
const channelEntry = path.join(__dirname, 'channel.cjs');
const edgeEntry = path.join(__dirname, 'local-edge.cjs');
const COMMAND_TIMEOUT_MS = 300_000;
const EDGE_TIMEOUT_MS = 15_000;
const EDGE_SCHEMA = 'zode.local-channel.v1';
const RUNTIME_SCHEMA = 'zode.local-channel-runtime.v1';
const commonProviderVariables = [
  'ZODE_RELEASE_LIVE_PROVIDER_BASE_URL',
  'ZODE_RELEASE_LIVE_PROVIDER_API_KEY',
  'ZODE_E2E_LIVE_PROVIDER_API_KEY',
  'DEEPSEEK_API_KEY',
  'OPENCODE_GO_API_KEY',
  'OPENCODE_API_KEY',
  'OPENAI_API_KEY',
  'OPENROUTER_API_KEY',
  'ANTHROPIC_API_KEY',
  'GOOGLE_API_KEY',
  'GEMINI_API_KEY',
  'MISTRAL_API_KEY',
  'TOGETHER_API_KEY',
  'XAI_API_KEY',
  'GROQ_API_KEY',
  'COHERE_API_KEY',
];

class LocalChannelError extends Error {
  constructor(code, message, details = {}, status = 1) {
    super(message);
    this.code = code;
    this.details = details;
    this.status = status;
  }
}

function fail(code, message, details = {}, status = 1) {
  throw new LocalChannelError(code, message, details, status);
}

function statOrNull(value) {
  try { return lstatSync(value); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function ensureDirectory(value) {
  const root = path.resolve(value);
  const existing = statOrNull(root);
  if (existing?.isSymbolicLink()) fail('local_channel_root_invalid', 'channel root must not be a symlink', { path: root });
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const checked = lstatSync(root);
  if (!checked.isDirectory() || checked.isSymbolicLink()) fail('local_channel_root_invalid', 'channel root must be a private directory', { path: root });
  chmodSync(root, 0o700);
  return root;
}

function privateFile(value, bytes) {
  const existing = statOrNull(value);
  if (existing) {
    if (!existing.isFile() || existing.isSymbolicLink() || (existing.mode & 0o077) !== 0) {
      fail('local_channel_state_invalid', 'local channel private file is not restricted', { path: value });
    }
    return;
  }
  const fd = openSync(value, 'wx', 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(value, 0o600);
}

function writeJsonAtomic(value, payload, mode = 0o600) {
  const temp = `${value}.next-${randomUUID()}`;
  const fd = openSync(temp, 'wx', mode);
  try { writeFileSync(fd, `${JSON.stringify(payload, null, 2)}\n`); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(temp, mode);
  renameSync(temp, value);
}

function jsonFromLastLine(stdout) {
  for (const line of String(stdout || '').trim().split(/\r?\n/).reverse()) {
    try { return JSON.parse(line); } catch { /* readiness output precedes JSON */ }
  }
  return null;
}

function runChannel(args, env) {
  const result = spawnSync(process.execPath, [channelEntry, ...args], {
    cwd: repository,
    env,
    encoding: 'utf8',
    timeout: COMMAND_TIMEOUT_MS,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error?.code === 'ETIMEDOUT') fail('local_channel_timeout', 'channel operation exceeded its bound', { args });
  if (result.error) fail('local_channel_spawn_failed', 'channel operation could not start', { error: String(result.error) });
  return { status: result.status ?? 1, stdout: result.stdout || '', stderr: result.stderr || '', payload: jsonFromLastLine(result.stdout) };
}

function base64Url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function loadPrivateKey(config) {
  const keyPath = path.resolve(config.key_path);
  if (!keyPath.startsWith(`${config.channel_root}${path.sep}`)) fail('local_channel_state_invalid', 'Access key escaped channel root');
  const stat = statOrNull(keyPath);
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) fail('local_channel_state_invalid', 'Access key is not private', { path: keyPath });
  return readFileSync(keyPath, 'utf8');
}

function assertion(config) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url({ alg: 'RS256', kid: config.key_id, typ: 'JWT' });
  const claims = base64Url({
    iss: config.issuer,
    aud: [config.audience],
    sub: 'zode-local-channel-user',
    iat: now,
    nbf: now - 1,
    exp: now + 600,
    type: 'app',
  });
  const signature = sign('RSA-SHA256', Buffer.from(`${header}.${claims}`), loadPrivateKey(config)).toString('base64url');
  return `${header}.${claims}.${signature}`;
}

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

async function createConfig(root) {
  const statePath = path.join(root, 'local-channel.json');
  const existing = statOrNull(statePath);
  if (existing) {
    if (!existing.isFile() || existing.isSymbolicLink() || (existing.mode & 0o077) !== 0) fail('local_channel_state_invalid', 'channel state is not private', { path: statePath });
    let value;
    try { value = JSON.parse(readFileSync(statePath, 'utf8')); } catch (error) { fail('local_channel_state_invalid', 'channel state is not valid JSON', { error: String(error) }); }
    if (value?.schema !== EDGE_SCHEMA || value.channel_root !== root || typeof value.key_path !== 'string') fail('local_channel_state_invalid', 'channel state schema is invalid');
    validateLocalConfig(value);
    loadPrivateKey(value);
    return { ...value, state_path: statePath };
  }
  const edgePort = await reservePort();
  const serverPort = await reservePort();
  const endpointPort = await reservePort();
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyPath = path.join(root, 'access-private.pem');
  privateFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const config = {
    schema: EDGE_SCHEMA,
    channel_root: root,
    edge_host: '127.0.0.1',
    edge_port: edgePort,
    server_origin: `http://127.0.0.1:${serverPort}`,
    endpoint_listen: `127.0.0.1:${endpointPort}`,
    issuer: `http://127.0.0.1:${edgePort}`,
    audience: 'zode-local-channel',
    key_id: `zode-local-${randomUUID()}`,
    key_path: keyPath,
  };
  validateLocalConfig(config);
  writeJsonAtomic(statePath, config);
  return { ...config, state_path: statePath };
}

function runtimePath(config) { return path.join(config.channel_root, 'runtime.json'); }

function isLoopbackHost(value) {
  return value === '127.0.0.1' || value === '::1' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(value);
}

function validateLocalConfig(config) {
  if (!config || config.schema !== EDGE_SCHEMA) fail('local_channel_state_invalid', 'local channel state schema is invalid');
  if (config.edge_host !== '127.0.0.1' || !Number.isInteger(config.edge_port) || config.edge_port < 1 || config.edge_port > 65535) {
    fail('local_channel_state_invalid', 'local Access edge must bind a loopback address');
  }
  let serverOrigin;
  try { serverOrigin = new URL(config.server_origin); } catch { fail('local_channel_state_invalid', 'local Server origin is not a URL'); }
  if (serverOrigin.protocol !== 'http:' || !isLoopbackHost(serverOrigin.hostname) || !serverOrigin.port) {
    fail('local_channel_state_invalid', 'local Server origin must be an HTTP loopback address');
  }
  let endpointOrigin;
  try { endpointOrigin = new URL(`http://${config.endpoint_listen}`); } catch { fail('local_channel_state_invalid', 'local Endpoint listen address is invalid'); }
  if (!isLoopbackHost(endpointOrigin.hostname) || !endpointOrigin.port) {
    fail('local_channel_state_invalid', 'local Endpoint must bind a loopback address');
  }
  let issuer;
  try { issuer = new URL(config.issuer); } catch { fail('local_channel_state_invalid', 'local Access issuer is not a URL'); }
  if (issuer.protocol !== 'http:' || !isLoopbackHost(issuer.hostname) || !issuer.port) {
    fail('local_channel_state_invalid', 'local Access issuer must be an HTTP loopback address');
  }
  if (issuer.hostname !== config.edge_host || Number(issuer.port) !== config.edge_port) {
    fail('local_channel_state_invalid', 'local Access issuer must match the loopback edge address');
  }
  return config;
}

function readRuntime(config) {
  const value = statOrNull(runtimePath(config));
  if (!value) return null;
  if (!value.isFile() || value.isSymbolicLink() || (value.mode & 0o077) !== 0) fail('local_channel_state_invalid', 'runtime state is not private');
  try { return JSON.parse(readFileSync(runtimePath(config), 'utf8')); } catch (error) { fail('local_channel_state_invalid', 'runtime state is not valid JSON', { error: String(error) }); }
}

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error?.code === 'EPERM'; }
}

function edgeCommand(pid) {
  const output = spawnSync('/bin/ps', ['-p', String(pid), '-o', 'command='], { encoding: 'utf8' });
  const command = String(output.stdout || '').trim();
  return command === '<defunct>' ? '' : command;
}

function runtimeExecutable(runtime) {
  if (typeof runtime?.executable_path !== 'string' || !path.isAbsolute(runtime.executable_path)) {
    return process.execPath;
  }
  const executable = realpathSync(runtime.executable_path);
  const stat = statOrNull(executable);
  if (!stat || !stat.isFile() || (stat.mode & 0o111) === 0) {
    fail('local_channel_state_invalid', 'runtime edge executable is not a regular executable', { path: executable });
  }
  return executable;
}

function exactEdgeCommand(config, pid, executable = process.execPath) {
  const command = edgeCommand(pid);
  const expected = `${edgeEntry} --state ${config.state_path}`;
  // A detached child can briefly remain as a zombie after its parent exits;
  // `kill(pid, 0)` still succeeds for that window, while `ps` has no command.
  // Treat that as already reaped, but never accept a different live command.
  return command === `${executable} ${expected}`;
}

function edgeReady(config) {
  return new Promise((resolve) => {
    const request = http.get({ hostname: config.edge_host, port: config.edge_port, path: '/__zode_local_edge_ready', timeout: 1_000 }, (response) => {
      response.resume();
      response.once('end', () => resolve(response.statusCode === 200));
    });
    request.once('error', () => resolve(false));
    request.once('timeout', () => { request.destroy(); resolve(false); });
  });
}

async function ensureEdge(config) {
  const current = readRuntime(config);
  if (current?.edge_pid && pidAlive(current.edge_pid)) {
    if (!edgeCommand(current.edge_pid)) {
      try { unlinkSync(runtimePath(config)); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
    } else if (!exactEdgeCommand(config, current.edge_pid, runtimeExecutable(current))) {
      fail('local_channel_edge_identity', 'recorded local edge PID does not match its private state command', { pid: current.edge_pid });
    } else {
      if (await edgeReady(config)) return current;
      fail('local_channel_edge_unready', 'recorded local edge process is alive but its readiness endpoint is unavailable');
    }
  }
  const logPath = path.join(config.channel_root, 'local-edge.log');
  const logFd = openSync(logPath, 'a', 0o600);
  chmodSync(logPath, 0o600);
  let child;
  try {
    child = spawn(process.execPath, [edgeEntry, '--state', config.state_path], {
      cwd: repository,
      detached: true,
      env: { PATH: process.env.PATH || '/usr/bin:/bin' },
      stdio: ['ignore', logFd, logFd],
    });
  } finally {
    closeSync(logFd);
  }
  if (!child.pid) fail('local_channel_edge_start_failed', 'local Access edge did not expose a PID');
  child.unref();
  const deadline = Date.now() + EDGE_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await edgeReady(config)) {
      const runtime = {
        schema: RUNTIME_SCHEMA,
        edge_pid: child.pid,
        started_at_unix_ms: Date.now(),
        executable_path: realpathSync(process.execPath),
        url: `${config.issuer}/`,
      };
      writeJsonAtomic(runtimePath(config), runtime);
      return runtime;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (pidAlive(child.pid) && exactEdgeCommand(config, child.pid)) process.kill(-child.pid, 'SIGTERM');
  fail('local_channel_edge_start_failed', 'local Access edge did not become ready', { log: logPath });
}

function stopEdge(config) {
  const runtime = readRuntime(config);
  if (!runtime?.edge_pid) return { stopped: true, edge_pid: null };
  const pid = runtime.edge_pid;
  const command = edgeCommand(pid);
  if (pidAlive(pid) && command) {
    if (!exactEdgeCommand(config, pid, runtimeExecutable(runtime))) fail('local_channel_edge_identity', 'refusing to signal an unrelated process in local channel state', { pid });
    try { process.kill(-pid, 'SIGTERM'); } catch (error) { if (error?.code !== 'ESRCH') throw error; }
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && pidAlive(pid) && edgeCommand(pid)) {
      // Poll slowly enough not to starve the detached child while retaining a
      // bounded stop admission.
      const waitUntil = Date.now() + 50;
      while (Date.now() < waitUntil) { /* bounded wait */ }
    }
    if (pidAlive(pid) && edgeCommand(pid)) {
      if (!exactEdgeCommand(config, pid, runtimeExecutable(runtime))) fail('local_channel_edge_identity', 'local edge command changed before forced stop', { pid, command: edgeCommand(pid) });
      try { process.kill(-pid, 'SIGKILL'); } catch (error) { if (error?.code !== 'ESRCH') throw error; }
    }
  }
  try { unlinkSync(runtimePath(config)); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  return { stopped: true, edge_pid: pid };
}

function channelEnv(config) {
  const env = { ...process.env };
  for (const key of commonProviderVariables) delete env[key];
  env.ZODE_RELEASE_ACCESS_ISSUER = config.issuer;
  env.ZODE_RELEASE_ACCESS_JWKS_URL = `${config.issuer}/jwks`;
  env.ZODE_RELEASE_ACCESS_AUDIENCE = config.audience;
  env.ZODE_RELEASE_ACCESS_ASSERTION = assertion(config);
  env.ZODE_RELEASE_SERVER_LISTEN = `127.0.0.1:${new URL(config.server_origin).port}`;
  env.ZODE_RELEASE_ENDPOINT_LISTEN = config.endpoint_listen;
  return env;
}

function currentExists(root) {
  const pathValue = path.join(root, 'current');
  try { return Boolean(lstatSync(pathValue)); } catch (error) { return error?.code !== 'ENOENT'; }
}

function installedArtifactForStart(root) {
  const releases = path.join(root, 'releases');
  const stat = statOrNull(releases);
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) return null;
  const entries = readdirSync(releases).filter((name) => !name.startsWith('.'))
    .map((name) => path.join(releases, name))
    .filter((value) => statOrNull(value)?.isDirectory());
  if (entries.length !== 1) {
    if (entries.length === 0) return null;
    fail('local_channel_usage', 'empty channel has more than one installed artifact; pass --artifact explicitly', { release_root: root }, 2);
  }
  return entries[0];
}

function parseArgs(argv) {
  const operation = argv.shift();
  if (!operation || operation === '--help' || operation === '-h') return { help: true };
  if (!['install', 'start', 'stop', 'status', 'update', 'open'].includes(operation)) fail('local_channel_usage', 'unknown persistent-channel operation', { operation }, 2);
  const values = {};
  while (argv.length) {
    const key = argv.shift();
    if (!key.startsWith('--')) fail('local_channel_usage', 'options require --name value', { option: key }, 2);
    const name = key.slice(2).replaceAll('-', '_');
    if (!['artifact', 'channel_root'].includes(name)) fail('local_channel_usage', 'unknown persistent-channel option', { option: key }, 2);
    if (!argv.length) fail('local_channel_usage', 'options require --name value', { option: key }, 2);
    values[name] = argv.shift();
  }
  return { operation, values };
}

function rootFor(values) {
  const raw = values.channel_root || process.env.ZODE_LOCAL_CHANNEL_ROOT || path.join(os.homedir(), '.zode', 'test-channel');
  return ensureDirectory(raw);
}

function emit(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }

async function main(options) {
  if (options.help) {
    process.stdout.write([
      'usage:',
      '  node release/local-channel.cjs install --artifact DIR [--channel-root DIR]',
      '  node release/local-channel.cjs start [--channel-root DIR]',
      '  node release/local-channel.cjs stop [--channel-root DIR]',
      '  node release/local-channel.cjs status [--channel-root DIR]',
      '  node release/local-channel.cjs update --artifact DIR [--channel-root DIR]',
      '  node release/local-channel.cjs open [--channel-root DIR]',
      '',
      `default channel root: ${path.join(os.homedir(), '.zode', 'test-channel')}`,
      'start prints the persistent browser URL; stop preserves the artifact, data, and URL configuration.',
    ].join('\n') + '\n');
    return 0;
  }
  const root = rootFor(options.values);
  const config = await createConfig(root);
  const env = channelEnv(config);
  if (options.operation === 'install') {
    const artifact = options.values.artifact;
    if (!artifact) fail('local_channel_usage', 'install requires --artifact', {}, 2);
    const result = runChannel(['install', '--artifact', path.resolve(artifact), '--release-root', root], env);
    emit({ ok: result.status === 0 && result.payload?.ok === true, operation: 'install', channel_root: root, ...(result.payload || {}) });
    return result.status;
  }
  if (options.operation === 'start') {
    const runtime = await ensureEdge(config);
    const artifact = options.values.artifact ? path.resolve(options.values.artifact) : null;
    const args = ['start', '--release-root', root];
    if (!currentExists(root)) {
      const bootstrapArtifact = artifact || installedArtifactForStart(root);
      if (bootstrapArtifact) args.push('--artifact', bootstrapArtifact);
    }
    const result = runChannel(args, env);
    if (result.status !== 0 || result.payload?.ok !== true) {
      stopEdge(config);
      emit({ ok: false, operation: 'start', channel_root: root, ...(result.payload || {}) });
      return result.status || 1;
    }
    emit({ ok: true, operation: 'start', channel_root: root, url: `${config.issuer}/`, edge_pid: runtime.edge_pid, ...result.payload });
    return 0;
  }
  if (options.operation === 'stop') {
    const result = runChannel(['stop', '--release-root', root], env);
    const edge = stopEdge(config);
    emit({ ok: result.status === 0 && result.payload?.ok === true, operation: 'stop', channel_root: root, edge, ...(result.payload || {}) });
    return result.status;
  }
  if (options.operation === 'status') {
    const runtime = readRuntime(config);
    if (!runtime?.edge_pid || !pidAlive(runtime.edge_pid)) {
      emit({ ok: true, operation: 'status', channel_root: root, running: false, url: `${config.issuer}/` });
      return 0;
    }
    if (!exactEdgeCommand(config, runtime.edge_pid, runtimeExecutable(runtime))) fail('local_channel_edge_identity', 'runtime edge PID does not match its command');
    const result = runChannel(['health', '--release-root', root], env);
    emit({ ok: result.status === 0, operation: 'status', channel_root: root, running: true, url: `${config.issuer}/`, health: result.payload || null });
    return result.status;
  }
  if (options.operation === 'update') {
    const artifact = options.values.artifact;
    if (!artifact) fail('local_channel_usage', 'update requires --artifact', {}, 2);
    const priorRuntime = readRuntime(config);
    const priorEdge = Boolean(priorRuntime?.edge_pid && pidAlive(priorRuntime.edge_pid) && exactEdgeCommand(config, priorRuntime.edge_pid, runtimeExecutable(priorRuntime)));
    let keepEdge = priorEdge;
    try {
      await ensureEdge(config);
      const result = runChannel(['update', '--artifact', path.resolve(artifact), '--release-root', root], env);
      keepEdge = priorEdge || (result.status === 0 && result.payload?.ok === true);
      emit({ ok: result.status === 0 && result.payload?.ok === true, operation: 'update', channel_root: root, url: `${config.issuer}/`, ...(result.payload || {}) });
      return result.status;
    } finally {
      if (!keepEdge) stopEdge(config);
    }
  }
  if (options.operation === 'open') {
    let keepEdge = false;
    try {
      const runtime = await ensureEdge(config);
      const result = runChannel(['health', '--release-root', root], env);
      if (result.status !== 0) fail('local_channel_not_running', 'start the local channel before opening its UI', { channel_root: root });
      const url = `${config.issuer}/`;
      const openCommand = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
      const opened = spawnSync(openCommand, [url], { stdio: 'ignore' });
      keepEdge = opened.status === 0;
      emit({ ok: keepEdge, operation: 'open', channel_root: root, url, edge_pid: runtime.edge_pid });
      return opened.status ?? 1;
    } finally {
      if (!keepEdge) stopEdge(config);
    }
  }
  fail('local_channel_usage', 'unsupported persistent-channel operation', { operation: options.operation }, 2);
}

main(parseArgs(process.argv.slice(2))).then((status) => { process.exitCode = status; }).catch((error) => {
  emit({ ok: false, error: error instanceof LocalChannelError ? { code: error.code, message: error.message, details: error.details } : { code: 'local_channel_error', message: String(error), details: {} } });
  process.exitCode = error instanceof LocalChannelError ? error.status : 1;
});
