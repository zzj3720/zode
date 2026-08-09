import { expect, test, type Browser, type BrowserContext, type Locator, type Page } from '@playwright/test';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import {
  createServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server as HttpServer,
  type ServerResponse,
} from 'node:http';
import { readFileSync } from 'node:fs';
import { chmod, cp, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import type { Readable } from 'node:stream';

type Scenario = {
  schema: string;
  provider: string;
  model: string;
  firstFailureOwner: string;
  actors: {
    primary: string;
    secondary: string;
  };
  actorAssertions: {
    sameProvider: boolean;
    profileCount: number;
    replicaReadStatus: number;
    selectedSharing: 'declared_endpoint_only';
  };
  seamMatrix: SeamMatrix;
  profiles: Array<{
    label: string;
    kind: 'oauth' | 'api_key';
    endpointLabel: string;
    notSharedEndpointLabel: string;
    sharing: 'selected';
    default: boolean;
  }>;
  uiSemantics: {
    deploymentSharedText: string;
    forbiddenOwnershipTerms: string[];
  };
  distributionStatuses: string[];
  securityAssertions: string[];
  llm: {
    requestsExpected: number;
    recorderSchema: string;
    quarantineRoot: string;
    firstFailureRule: string;
  };
};

type RouteContract = {
  method: string;
  path: string;
  status: number;
};

type ProbeRouteContract = {
  method: string;
  path: string;
  onlineStatus: number;
  offlineStatus: number;
};

type SeamMatrix = {
  firstFailure: RouteContract & {
    recordedStatus: number;
    classification: 'shallow_non_evidence';
  };
  bootstrap: {
    system: RouteContract;
    endpoints: RouteContract;
    providers: RouteContract;
  };
  endpointCatalog: {
    create: RouteContract;
    read: RouteContract;
    identity: RouteContract;
    capabilities: RouteContract;
    probe: ProbeRouteContract;
  };
  providerDescriptor: RouteContract;
  profileList: RouteContract;
  profileCreate: RouteContract;
  defaultProfile: RouteContract;
  sharing: RouteContract;
  replicas: RouteContract;
  replicaInstall: RouteContract;
  replicaTombstone: RouteContract;
  sessionCreate: RouteContract;
};

const scenario = JSON.parse(
  readFileSync(
    new URL('../fixtures/provider_profiles_distribution/scenario.json', import.meta.url),
    'utf8',
  ),
) as Scenario;
const seamMatrix = scenario.seamMatrix;

const READY_TIMEOUT_MS = 20_000;
const ACTION_TIMEOUT_MS = 15_000;
const CHILD_STOP_TIMEOUT_MS = 5_000;
const TEST_AUDIENCE = 'zode-web-provider-profiles-e2e';
const SERVER_AUTHORITY = 'web-provider-profiles-server-e2e';
const SPEC_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SPEC_DIR, '../../..');
const FIRST_FAILURE_CASSETTE_PATH = resolve(
  SPEC_DIR,
  '../fixtures/provider_profiles_distribution/provider-profiles-first-browser-failure.v1.json',
);
const FIRST_FAILURE_OWNER = scenario.firstFailureOwner;
const OAUTH_PROVIDER_FIXTURE = resolve(
  SPEC_DIR,
  '../fixtures/oauth_refresh_relogin/provider_oauth_fixture.mjs',
);
const OAUTH_SECRET_MARKERS = [
  'fixture-access-token-oauth-1',
  'fixture-refresh-token-oauth-1',
] as const;

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function resolveRoute(contract: RouteContract, replacements: Record<string, string> = {}): RouteContract {
  const path = contract.path.replace(/\{([^}]+)\}/g, (_match, name: string) => {
    const value = replacements[name];
    if (!value) throw new Error(`route contract placeholder {${name}} was not resolved`);
    return value;
  });
  return { method: contract.method, path, status: contract.status };
}

function responseMatches(response: import('@playwright/test').Response, contract: RouteContract): boolean {
  return response.request().method() === contract.method && new URL(response.url()).pathname === contract.path;
}

async function expectResponseAfter(
  page: Page,
  contract: RouteContract,
  action: () => Promise<void>,
  label: string,
): Promise<import('@playwright/test').Response> {
  const responsePromise = page.waitForResponse((response) => responseMatches(response, contract));
  await action();
  const response = await responsePromise;
  expect(response.request().method(), `${label} method`).toBe(contract.method);
  expect(new URL(response.url()).pathname, `${label} path`).toBe(contract.path);
  if (contract.path === '/v1/providers' && response.status() === 404) {
    throw new ShallowNonEvidence404(label);
  }
  expect(response.status(), `${label} status`).toBe(contract.status);
  return response;
}

type BrowserRouteObservation = {
  method: string;
  path: string;
  status: number;
};

class BrowserRouteLedger {
  readonly responses: BrowserRouteObservation[] = [];

  constructor(page: Page) {
    page.on('response', (response) => {
      const path = new URL(response.url()).pathname;
      if (!path.startsWith('/v1/')) return;
      this.responses.push({ method: response.request().method(), path, status: response.status() });
    });
  }

  mark(): number {
    return this.responses.length;
  }

  private matches(contract: RouteContract, after: number): BrowserRouteObservation[] {
    return this.responses.slice(after).filter(
      (response) => response.method === contract.method && response.path === contract.path,
    );
  }

  async expectNext(contract: RouteContract, label: string, after = 0): Promise<void> {
    await expect
      .poll(() => this.matches(contract, after).length, { timeout: ACTION_TIMEOUT_MS })
      .toBeGreaterThan(0);
    const response = this.matches(contract, after)[0];
    expect(response.method, `${label} method`).toBe(contract.method);
    expect(response.path, `${label} path`).toBe(contract.path);
    if (contract.path === '/v1/providers' && response.status === 404) {
      throw new ShallowNonEvidence404(label);
    }
    expect(response.status, `${label} status`).toBe(contract.status);
  }

  async expectAll(contract: RouteContract, label: string): Promise<void> {
    await expect
      .poll(() => this.responses.filter(
        (response) => response.method === contract.method && response.path === contract.path,
      ).length, { timeout: ACTION_TIMEOUT_MS })
      .toBeGreaterThan(0);
    for (const response of this.responses.filter(
      (item) => item.method === contract.method && item.path === contract.path,
    )) {
      expect(response.method, `${label} method`).toBe(contract.method);
      expect(response.path, `${label} path`).toBe(contract.path);
      if (contract.path === '/v1/providers' && response.status === 404) {
        throw new ShallowNonEvidence404(label);
      }
      expect(response.status, `${label} status`).toBe(contract.status);
    }
  }
}

const browserRouteLedgers = new WeakMap<Page, BrowserRouteLedger>();

function browserRouteLedger(page: Page): BrowserRouteLedger {
  let ledger = browserRouteLedgers.get(page);
  if (!ledger) {
    ledger = new BrowserRouteLedger(page);
    browserRouteLedgers.set(page, ledger);
  }
  return ledger;
}

class ShallowNonEvidence404 extends Error {
  readonly nonEvidence = true;

  constructor(label: string) {
    super(`NON_EVIDENCE_SHALLOW_404: ${label} is the retained route-absence exchange, not a behavioral first failure`);
    this.name = 'ShallowNonEvidence404';
  }
}

function base64Url(value: Buffer | string): string {
  return Buffer.from(value).toString('base64url');
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function readRequestBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer | string) => chunks.push(Buffer.from(chunk)));
    request.on('end', () => resolveBody(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function safeForwardHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || ['connection', 'content-length', 'host'].includes(name)) continue;
    if (Array.isArray(value)) {
      result[name] = value.join(', ');
    } else if (typeof value === 'string') {
      result[name] = value;
    }
  }
  return result;
}

async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, JSON.stringify(value, null, 2), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function listen(server: HttpServer): Promise<string> {
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolveListen());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('fixture did not expose a TCP address');
  return `http://127.0.0.1:${address.port}`;
}

async function reserveLoopbackPort(): Promise<number> {
  const server = createServer();
  await listen(server);
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('fixture did not expose a TCP address');
  const port = address.port;
  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((error) => (error ? rejectClose(error) : resolveClose()));
  });
  return port;
}

async function materializeUiAssets(root: string): Promise<string> {
  const source = process.env.ZODE_UI_ASSETS_DIRECTORY ?? resolve(REPO_ROOT, 'target/ci/product-ui');
  const destination = join(root, 'ui');
  await cp(source, destination, { recursive: true, force: false, errorOnExist: true });
  return destination;
}

class AccessFixture {
  readonly privateKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  readonly publicKey = createPublicKey(this.privateKey);
  readonly kid = 'web-provider-profiles-key';
  readonly server = createServer((request: IncomingMessage, response: ServerResponse) => {
    if (request.url !== '/jwks') {
      response.statusCode = 404;
      response.end();
      return;
    }
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify({
        keys: [
          {
            ...this.publicKey.export({ format: 'jwk' }),
            kid: this.kid,
            use: 'sig',
            alg: 'RS256',
          },
        ],
      }),
    );
  });
  baseUrl = '';

  async start(): Promise<void> {
    this.baseUrl = await listen(this.server);
  }

  token(subject: string): string {
    const now = Math.floor(Date.now() / 1000);
    const header = base64Url(JSON.stringify({ alg: 'RS256', kid: this.kid, typ: 'JWT' }));
    const payload = base64Url(
      JSON.stringify({
        iss: `${this.baseUrl}/`,
        aud: [TEST_AUDIENCE],
        sub: subject,
        type: 'app',
        iat: now,
        nbf: now - 1,
        exp: now + 300,
      }),
    );
    const signingInput = `${header}.${payload}`;
    const signature = sign('RSA-SHA256', Buffer.from(signingInput), this.privateKey);
    return `${signingInput}.${base64Url(signature)}`;
  }

  async stop(): Promise<void> {
    if (this.server.listening) {
      this.server.close();
      await once(this.server, 'close');
    }
  }
}

class AccessEdge {
  readonly server = createServer((request: IncomingMessage, response: ServerResponse) => void this.forward(request, response));
  baseUrl = '';

  constructor(
    private readonly targetOrigin: string,
    private readonly access: AccessFixture,
    private readonly actor: string,
  ) {}

  async start(): Promise<void> {
    this.baseUrl = await listen(this.server);
  }

  private async forward(request: IncomingMessage, response: ServerResponse): Promise<void> {
    let body: Buffer;
    try {
      body = await readRequestBody(request);
    } catch {
      response.statusCode = 400;
      response.end();
      return;
    }
    const target = new URL(request.url ?? '/', this.targetOrigin);
    const headers = safeForwardHeaders(request.headers);
    headers.host = new URL(this.targetOrigin).host;
    headers['cf-access-jwt-assertion'] = this.access.token(this.actor);
    if (body.length > 0) headers['content-length'] = String(body.length);
    const upstream = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: request.method,
        headers,
      },
      (upstreamResponse: IncomingMessage) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      },
    );
    upstream.once('error', () => {
      if (!response.headersSent) response.writeHead(502, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: { code: 'management_unavailable', retryable: true } }));
    });
    upstream.end(body);
  }

  async stop(): Promise<void> {
    if (this.server.listening) {
      this.server.closeAllConnections?.();
      await new Promise<void>((resolveClose) => this.server.close(() => resolveClose()));
    }
  }
}

type RecordedLlmExchange = {
  method: string;
  path: string;
  body: string;
  headers: Record<string, string>;
  receivedAtMs: number;
};

class LlmRecorder {
  readonly server = createServer((request: IncomingMessage, response: ServerResponse) => void this.handle(request, response));
  readonly exchanges: RecordedLlmExchange[] = [];
  readonly secretMarkers: string[];
  private quarantineFlushed = false;
  baseUrl = '';

  constructor(secretMarkers: string[], readonly owner: string) {
    this.secretMarkers = secretMarkers;
  }

  async start(): Promise<void> {
    this.baseUrl = await listen(this.server);
  }

  private redact(value: string): string {
    return this.secretMarkers.reduce(
      (redacted, marker, index) => redacted.split(marker).join(`{{SLOT_SECRET_${index + 1}}}`),
      value,
    );
  }

  private async handle(
    request: import('node:http').IncomingMessage,
    response: import('node:http').ServerResponse,
  ): Promise<void> {
    const body = await readRequestBody(request);
    const headers: Record<string, string> = {};
    for (const name of ['content-type', 'accept']) {
      const value = request.headers[name];
      if (value) headers[name] = Array.isArray(value) ? value.join(', ') : value;
    }
    this.exchanges.push({
      method: request.method ?? 'GET',
      path: request.url ?? '/',
      body: this.redact(body.toString('utf8')),
      headers,
      receivedAtMs: Date.now(),
    });
    response.statusCode = 500;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ error: { code: 'fixture_provider_not_expected', retryable: false } }));
  }

  async flushQuarantine(runId: string): Promise<string | null> {
    if (this.exchanges.length === 0) {
      this.quarantineFlushed = true;
      return null;
    }
    const root = resolve(
      process.env.ZODE_TEST_RECORDING_ROOT ?? join(process.cwd(), scenario.llm.quarantineRoot),
    );
    const runRoot = await mkdtemp(join(root, `${runId}-`)).catch(async (error: unknown) => {
      const code =
        typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string'
          ? error.code
          : undefined;
      if (code !== 'ENOENT') throw error;
      await mkdir(root, { recursive: true, mode: 0o700 });
      return mkdtemp(join(root, `${runId}-`));
    });
    await chmod(runRoot, 0o700);
    const path = join(runRoot, 'llm-http-recording.json');
    await writePrivateJson(path, {
      schema: scenario.llm.recorderSchema,
      recording_id: `${runId}-${Date.now()}`,
      owning_e2e: this.owner,
      boundary: 'provider_model',
      secret_slots: this.secretMarkers.map((_, index) => `SLOT_SECRET_${index + 1}`),
      exchanges: this.exchanges.map((exchange, sequence) => ({ sequence, ...exchange, body_sha256: sha256(exchange.body) })),
    });
    this.quarantineFlushed = true;
    return path;
  }

  async stop(): Promise<void> {
    const flushError =
      this.exchanges.length > 0 && !this.quarantineFlushed
        ? new Error('unexpected LLM exchanges were not flushed to quarantine')
        : undefined;
    if (this.server.listening) {
      this.server.close();
      await once(this.server, 'close');
    }
    if (flushError) throw flushError;
  }
}

type RunningProcess = {
  child: ChildProcessByStdio<null, Readable, Readable>;
  baseUrl: string;
  logs: () => string;
  stop: () => Promise<void>;
};

type EndpointExchange = {
  method: string;
  path: string;
  status?: number;
};

async function spawnReady(
  binary: string,
  args: string[],
  prefix: string,
  environment: Record<string, string> = {},
): Promise<RunningProcess> {
  const child = spawn(binary, args, {
    env: { ...process.env, ...environment },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  let readyUrl: string | null = null;
  let readyResolve: ((url: string) => void) | null = null;
  let readyReject: ((error: Error) => void) | null = null;
  const ready = new Promise<string>((resolveReady, rejectReady) => {
    readyResolve = resolveReady;
    readyReject = rejectReady;
  });
  const exit = new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));
  const lines = createInterface({ input: child.stdout });
    lines.on('line', (line: string) => {
    output += `${line}\n`;
    if (line.startsWith(prefix) && readyResolve) {
      const resolvedUrl = line.slice(prefix.length).trim();
      readyUrl = resolvedUrl;
      readyResolve(resolvedUrl);
      readyResolve = null;
      readyReject = null;
    }
  });
  child.stderr.on('data', (chunk: Buffer | string) => {
    output += chunk.toString();
  });
  child.once('error', (error: Error) => readyReject?.(error));
  const timeout = delay(READY_TIMEOUT_MS).then(() => {
    throw new Error(`process did not reach ${prefix}`);
  });
  try {
    const baseUrl = await Promise.race([ready, timeout]);
    return {
      child,
      baseUrl,
      logs: () => output,
      stop: async () => {
        if (child.exitCode !== null) return;
        child.kill('SIGTERM');
        await Promise.race([
          exit,
          delay(CHILD_STOP_TIMEOUT_MS).then(() => {
            if (child.exitCode === null) child.kill('SIGKILL');
          }),
        ]);
        await exit;
      },
    };
  } catch (error) {
    if (child.exitCode === null) child.kill('SIGKILL');
    await exit;
    throw error;
  } finally {
    void readyUrl;
  }
}

type OAuthFixtureState = {
  authorize_count: number;
};

class OAuthProviderFixture {
  private constructor(private readonly child: RunningProcess) {}

  static async start(): Promise<OAuthProviderFixture> {
    const child = await spawnReady(
      process.execPath,
      [OAUTH_PROVIDER_FIXTURE, '--port', '0'],
      'ZODE_OAUTH_FIXTURE_READY ',
    );
    return new OAuthProviderFixture(child);
  }

  get origin(): string {
    return this.child.baseUrl;
  }

  async state(): Promise<OAuthFixtureState> {
    const response = await fetch(`${this.origin}/control/state`);
    if (!response.ok) throw new Error(`OAuth fixture state failed with HTTP ${response.status}`);
    const value: unknown = await response.json();
    if (
      typeof value !== 'object' ||
      value === null ||
      !('authorize_count' in value) ||
      typeof value.authorize_count !== 'number'
    ) {
      throw new Error('OAuth fixture state had an invalid shape');
    }
    return { authorize_count: value.authorize_count };
  }

  async waitForAuthorize(previousCount: number): Promise<void> {
    await expect
      .poll(async () => (await this.state()).authorize_count, { timeout: ACTION_TIMEOUT_MS })
      .toBeGreaterThan(previousCount);
  }

  async stop(): Promise<void> {
    await this.child.stop();
  }
}

class EndpointProxy {
  readonly server = createServer((request: IncomingMessage, response: ServerResponse) => void this.handle(request, response));
  readonly targetUrl: string;
  readonly held: Array<{
    method: string;
    path: string;
    headers: Record<string, string>;
    body: Buffer;
    response: import('node:http').ServerResponse;
  }> = [];
  readonly requests: EndpointExchange[] = [];
  readonly responses: EndpointExchange[] = [];
  online = true;
  holdReplicaWrites = false;
  baseUrl = '';

  constructor(targetUrl: string) {
    this.targetUrl = targetUrl;
  }

  async start(): Promise<void> {
    this.baseUrl = await listen(this.server);
  }

  private async handle(
    request: import('node:http').IncomingMessage,
    response: import('node:http').ServerResponse,
  ): Promise<void> {
    const body = await readRequestBody(request);
    const method = request.method ?? 'GET';
    const path = request.url ?? '/';
    const headers = safeForwardHeaders(request.headers);
    this.requests.push({ method, path });
    if (!this.online) {
      response.statusCode = 502;
      response.setHeader('content-type', 'application/json');
      this.responses.push({ method, path, status: 502 });
      response.end(JSON.stringify({ error: { code: 'endpoint_unavailable', retryable: true } }));
      return;
    }
    if (this.holdReplicaWrites && method === 'PUT' && path.startsWith('/v1/auth-replicas/')) {
      this.held.push({ method, path, headers, body, response });
      return;
    }
    await this.forward({ method, path, headers, body, response });
  }

  private async forward(exchange: {
    method: string;
    path: string;
    headers: Record<string, string>;
    body: Buffer;
    response: import('node:http').ServerResponse;
  }): Promise<void> {
    if (exchange.response.writableEnded) return;
    try {
      const upstream = await fetch(`${this.targetUrl}${exchange.path}`, {
        method: exchange.method,
        headers: exchange.headers,
        body: exchange.body.length === 0 ? undefined : new Uint8Array(exchange.body),
      });
      this.responses.push({ method: exchange.method, path: exchange.path, status: upstream.status });
      exchange.response.statusCode = upstream.status;
      upstream.headers.forEach((value, key) => exchange.response.setHeader(key, value));
      exchange.response.end(Buffer.from(await upstream.arrayBuffer()));
    } catch {
      this.responses.push({ method: exchange.method, path: exchange.path, status: 502 });
      exchange.response.statusCode = 502;
      exchange.response.end(JSON.stringify({ error: { code: 'endpoint_unavailable', retryable: true } }));
    }
  }

  async releaseReplicaWrites(): Promise<void> {
    this.holdReplicaWrites = false;
    const pending = this.held.splice(0);
    await Promise.all(pending.map((exchange) => this.forward(exchange)));
  }

  async stop(): Promise<void> {
    for (const exchange of this.held.splice(0)) {
      if (!exchange.response.writableEnded) exchange.response.destroy();
    }
    if (this.server.listening) {
      this.server.close();
      await once(this.server, 'close');
    }
  }
}

function endpointExchangeMatches(exchange: EndpointExchange, contract: RouteContract): boolean {
  return exchange.method === contract.method && exchange.path === contract.path;
}

async function expectEndpointRequest(
  proxy: EndpointProxy,
  contract: RouteContract,
  label: string,
  after = 0,
): Promise<void> {
  await expect
    .poll(
      () => proxy.requests.filter((request) => endpointExchangeMatches(request, contract)).length - after,
      { timeout: ACTION_TIMEOUT_MS },
    )
    .toBeGreaterThan(0);
  const request = proxy.requests.filter((item) => endpointExchangeMatches(item, contract))[after];
  if (!request) throw new Error(`${label} request was not observed`);
  expect(request.method, `${label} method`).toBe(contract.method);
  expect(request.path, `${label} path`).toBe(contract.path);
}

async function expectEndpointResponse(
  proxy: EndpointProxy,
  contract: RouteContract,
  label: string,
  after = 0,
): Promise<void> {
  await expect
    .poll(
      () => proxy.responses.filter((response) => endpointExchangeMatches(response, contract)).length - after,
      { timeout: ACTION_TIMEOUT_MS },
    )
    .toBeGreaterThan(0);
  const response = proxy.responses.filter((item) => endpointExchangeMatches(item, contract))[after];
  if (!response) throw new Error(`${label} response was not observed`);
  expect(response.method, `${label} method`).toBe(contract.method);
  expect(response.path, `${label} path`).toBe(contract.path);
  expect(response.status, `${label} status`).toBe(contract.status);
}

function endpointResponseCount(proxy: EndpointProxy, contract: RouteContract): number {
  return proxy.responses.filter((response) => endpointExchangeMatches(response, contract)).length;
}

function endpointRequestCount(proxy: EndpointProxy, contract: RouteContract): number {
  return proxy.requests.filter((request) => endpointExchangeMatches(request, contract)).length;
}

function resolvedProbeContract(endpointId: string, status: number): RouteContract {
  return {
    method: seamMatrix.endpointCatalog.probe.method,
    path: seamMatrix.endpointCatalog.probe.path.replace('{endpoint_id}', endpointId),
    status,
  };
}

async function expectEndpointCatalogBarrier(proxy: EndpointProxy, label: string): Promise<void> {
  await expectEndpointResponse(
    proxy,
    resolveRoute(seamMatrix.endpointCatalog.identity),
    `${label} identity probe`,
  );
  await expectEndpointResponse(
    proxy,
    resolveRoute(seamMatrix.endpointCatalog.capabilities),
    `${label} capabilities probe`,
  );
}

async function writeEndpointConfig(
  root: string,
  database: string,
  providerOrigin: string,
  authority: string,
  controlSecret: string,
): Promise<string> {
  await mkdir(join(root, 'credentials'), { recursive: true, mode: 0o700 });
  await mkdir(join(root, 'blobs'), { recursive: true, mode: 0o700 });
  const secretFile = join(root, 'controller.secret');
  await writeFile(secretFile, controlSecret, { mode: 0o600 });
  await chmod(secretFile, 0o600);
  const configPath = join(root, 'endpoint-config.json');
  await writePrivateJson(configPath, {
    schema: 'zode.config.v1',
    listen: '127.0.0.1:0',
    runtime_store: { kind: 'sqlite', path: database },
    credential_replica_store: { kind: 'files', directory: 'credentials' },
    blob_store: { kind: 'files', directory: 'blobs' },
    controller_auth: [
      { authority_id: authority, revision: 1, kind: 'bearer_secret_file', secret_file: 'controller.secret' },
    ],
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
  return configPath;
}

async function writeServerConfig(
  root: string,
  access: AccessFixture,
  serverPort: number,
  uiAssetsDirectory: string,
): Promise<string> {
  const database = join(root, 'server.sqlite3');
  const secretDirectory = join(root, 'server-secrets');
  const subjectKey = join(root, 'subject.key');
  await mkdir(secretDirectory, { recursive: true, mode: 0o700 });
  await writeFile(subjectKey, Buffer.alloc(32, 0x42), { mode: 0o600 });
  await chmod(subjectKey, 0o600);
  const configPath = join(root, 'server-config.json');
  await writePrivateJson(configPath, {
    schema: 'zode.server-config.v1',
    listen: `127.0.0.1:${serverPort}`,
    management_origin: `http://127.0.0.1:${serverPort}`,
    callback_origin: `http://127.0.0.2:${serverPort}`,
    server_authority_id: SERVER_AUTHORITY,
    deployment: 'server_only',
    ui_mode: 'assets',
    ui_assets_directory: uiAssetsDirectory,
    control_database: database,
    secret_directory: secretDirectory,
    access: {
      issuer: `${access.baseUrl}/`,
      audiences: [TEST_AUDIENCE],
      jwks_url: `${access.baseUrl}/jwks`,
      subject_key_file: subjectKey,
      subject_key_version: 1,
    },
  });
  return configPath;
}

type JsonObject = Record<string, unknown>;

function loadFirstFailureCassette(): JsonObject {
  const cassette = JSON.parse(readFileSync(FIRST_FAILURE_CASSETTE_PATH, 'utf8')) as JsonObject;
  const firstFailure = seamMatrix.firstFailure;
  if (
    cassette.schema !== 'zode.http-incident-recording.v1' ||
    cassette.version !== 1 ||
    cassette.owner !== FIRST_FAILURE_OWNER
  ) {
    throw new Error('provider profile first-failure cassette metadata changed');
  }
  const exchanges = cassette.exchanges;
  if (!Array.isArray(exchanges) || exchanges.length !== 1) {
    throw new Error('provider profile first-failure cassette must retain one exchange');
  }
  const exchange = exchanges[0] as JsonObject;
  const request = exchange.request as JsonObject;
  const response = exchange.recorded_response as JsonObject;
  const firstObserved = cassette.first_observed_outcome as JsonObject;
  const contract = exchange.contract_response as JsonObject;
  if (
    exchange.sequence !== 0 ||
    firstFailure.classification !== 'shallow_non_evidence' ||
    request.method !== firstFailure.method ||
    request.path !== firstFailure.path ||
    response.status !== firstFailure.recordedStatus ||
    response.body_hex !== '' ||
    firstObserved.sequence !== 0 ||
    firstObserved.status !== response.status ||
    firstObserved.safe_error !== 'missing_public_provider_route' ||
    firstObserved.response_fingerprint !== response.fingerprint ||
    request.body_sha256 !== `sha256:${sha256(Buffer.from(String(request.raw_body_hex ?? ''), 'hex'))}` ||
    response.body_sha256 !== `sha256:${sha256(Buffer.from(String(response.body_hex ?? ''), 'hex'))}` ||
    response.fingerprint !== firstObserved.response_fingerprint ||
    contract.status !== firstFailure.status ||
    contract.kind !== 'providers_list'
  ) {
    throw new Error('provider profile first-failure cassette exchange changed');
  }
  if (cassette.secret_slots && (cassette.secret_slots as unknown[]).length !== 0) {
    throw new Error('provider profile bootstrap cassette must not contain secret slots');
  }
  const { whole_digest: wholeDigest, ...withoutDigest } = cassette;
  if (wholeDigest !== `sha256:${sha256(JSON.stringify(withoutDigest))}`) {
    throw new Error('provider profile first-failure cassette integrity digest changed');
  }
  return cassette;
}

async function assertBootstrapRouteIsRepaired(
  page: Page,
  context: BrowserContext,
  environment: ProviderDistributionEnvironment,
  cassette: JsonObject,
): Promise<void> {
  const request = (cassette.exchanges as JsonObject[])[0].request as JsonObject;
  const route = resolveRoute(seamMatrix.bootstrap.providers);
  expect(request.method).toBe(route.method);
  expect(request.path).toBe(route.path);
  const response = await page.goto(`${environment.accessEdges[0].baseUrl}${String(request.path)}`, {
    waitUntil: 'domcontentloaded',
  });
  expect(response?.request().method()).toBe(route.method);
  expect(response ? new URL(response.url()).pathname : '').toBe(route.path);
  const body = await response?.text();
  const expected = (cassette.exchanges as JsonObject[])[0].recorded_response as JsonObject;
  const bodyHex = Buffer.from(body ?? '').toString('hex');
  if (response?.status() === expected.status && bodyHex === expected.body_hex) {
    throw new ShallowNonEvidence404('GET /v1/providers');
  }
  const storage = await context.storageState();
  expect(JSON.stringify(storage)).not.toContain('api-key');
  expect(response?.status()).toBe(route.status);
}

async function replayFirstFailureCassette(
  page: Page,
  environment: ProviderDistributionEnvironment,
  cassette: JsonObject,
): Promise<void> {
  const exchange = (cassette.exchanges as JsonObject[])[0];
  const request = exchange.request as JsonObject;
  const expected = exchange.recorded_response as JsonObject;
  const response = await page.goto(`${environment.accessEdges[0].baseUrl}${String(request.path)}`, {
    waitUntil: 'commit',
  });
  const body = response ? await response.text() : '';
  const reproduced = { status: response?.status() ?? 0, body: Buffer.from(body).toString('hex') };
  const expectedPublicExchange = {
    status: expected.status,
    body: expected.body_hex,
  };
  if (JSON.stringify(reproduced) === JSON.stringify(expectedPublicExchange)) {
    throw new ShallowNonEvidence404('GET /v1/providers cassette replay');
  }
  expect(reproduced).not.toEqual(expectedPublicExchange);
  expect(reproduced.status).toBe(seamMatrix.bootstrap.providers.status);
}

class ProviderDistributionEnvironment {
  readonly root: string;
  readonly access: AccessFixture;
  readonly accessEdges: AccessEdge[] = [];
  readonly oauthProvider: OAuthProviderFixture;
  readonly recorder: LlmRecorder;
  readonly endpointProcesses: RunningProcess[] = [];
  readonly endpointProxies: EndpointProxy[] = [];
  server!: RunningProcess;
  readonly secretMarkers: string[];

  private constructor(
    root: string,
    secretMarkers: string[],
    access: AccessFixture,
    oauthProvider: OAuthProviderFixture,
    recorder: LlmRecorder,
  ) {
    this.root = root;
    this.secretMarkers = secretMarkers;
    this.access = access;
    this.oauthProvider = oauthProvider;
    this.recorder = recorder;
  }

  static async start(
    secretMarkers: string[],
    owner: string,
    controllerSecrets: [string, string],
  ): Promise<ProviderDistributionEnvironment> {
    const serverBinary =
      process.env.ZODE_SERVER_BIN ??
      process.env.CARGO_BIN_EXE_zode_server ??
      join(REPO_ROOT, 'server/target/debug/zode-server');
    const endpointBinary = process.env.ZODE_ENDPOINT_BIN ?? join(REPO_ROOT, 'target/debug/zode');
    const root = await mkdtemp(join(tmpdir(), 'zode-web-provider-profiles-'));
    const access = new AccessFixture();
    await access.start();
    const oauthProvider = await OAuthProviderFixture.start();
    const allSecretMarkers = [...new Set([...secretMarkers, ...OAUTH_SECRET_MARKERS])];
    const recorder = new LlmRecorder(allSecretMarkers, owner);
    await recorder.start();
    const environment = new ProviderDistributionEnvironment(
      root,
      allSecretMarkers,
      access,
      oauthProvider,
      recorder,
    );
    const childEnvironment = {
      ZODE_OAUTH_FIXTURE_ORIGIN: oauthProvider.origin,
      ZODE_WEB_E2E_OAUTH_FIXTURE_ORIGIN: oauthProvider.origin,
    };
    try {
      for (const [index, endpointLabel] of ['Endpoint A', 'Endpoint B'].entries()) {
        const endpointRoot = join(root, `endpoint-${index + 1}`);
        const endpointDatabase = join(endpointRoot, 'endpoint.sqlite3');
        const controlSecret = controllerSecrets[index] as string;
        const configPath = await writeEndpointConfig(
          endpointRoot,
          endpointDatabase,
          recorder.baseUrl,
          SERVER_AUTHORITY,
          controlSecret,
        );
        const endpoint = await spawnReady(
          endpointBinary,
          ['--config', configPath, '--database', endpointDatabase, '--listen', '127.0.0.1:0'],
          'ZODE_READY ',
          childEnvironment,
        );
        environment.endpointProcesses.push(endpoint);
        const proxy = new EndpointProxy(endpoint.baseUrl);
        await proxy.start();
        environment.endpointProxies.push(proxy);
        void endpointLabel;
      }
      const serverPort = await reserveLoopbackPort();
      const uiAssetsDirectory = await materializeUiAssets(root);
      const serverConfig = await writeServerConfig(root, access, serverPort, uiAssetsDirectory);
      environment.server = await spawnReady(
        serverBinary,
        ['--config', serverConfig],
        'ZODE_SERVER_READY ',
        childEnvironment,
      );
      for (const actor of [scenario.actors.primary, scenario.actors.secondary]) {
        const edge = new AccessEdge(environment.server.baseUrl, access, actor);
        await edge.start();
        environment.accessEdges.push(edge);
      }
      return environment;
    } catch (error) {
      await environment.stop();
      throw error;
    }
  }

  async stop(): Promise<void> {
    const errors: unknown[] = [];
    const settle = async (operation: () => Promise<void>): Promise<void> => {
      try {
        await operation();
      } catch (error) {
        errors.push(error);
      }
    };
    await settle(async () => this.server?.stop());
    for (const edge of this.accessEdges.splice(0)) await settle(() => edge.stop());
    for (const proxy of this.endpointProxies.splice(0)) await settle(() => proxy.stop());
    for (const endpoint of this.endpointProcesses.splice(0)) await settle(() => endpoint.stop());
    await settle(async () => {
      await this.recorder.flushQuarantine('provider-profiles-live');
    });
    await settle(() => this.recorder.stop());
    await settle(() => this.oauthProvider.stop());
    await settle(() => this.access.stop());
    if (errors.length > 0) {
      const first = errors[0];
      throw first instanceof Error ? first : new Error(String(first));
    }
  }
}

class SecretSurfaceGuard {
  readonly page: Page;
  readonly context: BrowserContext;
  readonly markers: string[];
  readonly consoleLines: string[] = [];
  readonly pageErrors: string[] = [];
  readonly requestUrlLeaks: string[] = [];
  readonly accessHeaderLeaks: string[] = [];
  readonly responseChecks: Promise<void>[] = [];
  readonly downloads: string[] = [];

  constructor(page: Page, context: BrowserContext, markers: string[]) {
    this.page = page;
    this.context = context;
    this.markers = [...new Set([...markers, ...OAUTH_SECRET_MARKERS])];
    this.attachPage(page);
  }

  attachPage(page: Page): void {
    page.on('console', (message) => this.consoleLines.push(message.text()));
    page.on('pageerror', (error) => this.pageErrors.push(error.message));
    page.on('request', (request) => {
      const url = request.url();
      if (this.markers.some((marker) => url.includes(marker))) this.requestUrlLeaks.push(url);
      if (Object.keys(request.headers()).some((name) => name.toLowerCase() === 'cf-access-jwt-assertion')) {
        this.accessHeaderLeaks.push(url);
      }
    });
    page.on('response', (response) => {
      this.responseChecks.push(
        response
          .text()
          .then((body) => {
            if (this.markers.some((marker) => body.includes(marker))) {
              throw new Error('a Server response body exposed a secret marker');
            }
          })
          .catch((error) => {
            if (error instanceof Error && error.message.includes('exposed a secret marker')) throw error;
          }),
      );
    });
    page.on('download', (download) => this.downloads.push(download.suggestedFilename()));
  }

  async assertClean(page: Page = this.page): Promise<void> {
    await Promise.all(this.responseChecks.splice(0));
    const body = await page.locator('body').innerText();
    const aria = await page.locator('body').ariaSnapshot();
    const dom = await page.locator('html').evaluate((root) => root.outerHTML);
    const storage = await page.evaluate(async () => ({
      localStorage: Object.fromEntries(Object.entries(localStorage)),
      sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
      cookies: document.cookie,
      indexedDbNames:
        'databases' in indexedDB
          ? (await indexedDB.databases()).map((database) => database.name ?? '')
          : [],
    }));
    const allCookies = JSON.stringify(await this.context.cookies());
    const browserUrl = page.url();
    const storageText = `${JSON.stringify(storage)}${allCookies}`;
    for (const marker of this.markers) {
      expect(body).not.toContain(marker);
      expect(aria).not.toContain(marker);
      expect(dom).not.toContain(marker);
      expect(storageText).not.toContain(marker);
      expect(browserUrl).not.toContain(marker);
      expect(this.consoleLines.join('\n')).not.toContain(marker);
      expect(this.pageErrors.join('\n')).not.toContain(marker);
    }
    expect(this.requestUrlLeaks).toEqual([]);
    expect(this.accessHeaderLeaks).toEqual([]);
    expect(this.downloads).toEqual([]);
  }
}

type ActorBrowserSession = {
  context: BrowserContext;
  page: Page;
  guard: SecretSurfaceGuard;
  close: () => Promise<void>;
};

async function openActorBrowserSession(
  browser: Browser,
  edge: AccessEdge,
  markers: string[],
): Promise<ActorBrowserSession> {
  expect(edge.baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  const context = await browser.newContext({ baseURL: edge.baseUrl });
  const page = await context.newPage();
  const guard = new SecretSurfaceGuard(page, context, markers);
  return { context, page, guard, close: () => context.close() };
}

function profileCard(page: Page, label: string): Locator {
  return page.locator('.profile-row').filter({ hasText: label }).first();
}

function distributionRow(card: Locator, endpointLabel: string): Locator {
  return card.getByRole('group', { name: new RegExp(escapeRegex(endpointLabel)) });
}

type ProfileResource = {
  card: Locator;
  profileId: string;
  revision: number;
};

async function expectDistributionStatus(
  page: Page,
  profile: ProfileResource,
  endpointLabel: string,
  status: string,
): Promise<void> {
  const row = distributionRow(profile.card, endpointLabel);
  await expect
    .poll(
      async () => {
        if ((await row.count()) === 0) return '';
        return row.innerText();
      },
      { timeout: ACTION_TIMEOUT_MS },
    )
    .toMatch(new RegExp(`\\b${escapeRegex(status)}\\b`, 'i'));
  await browserRouteLedger(page).expectAll(
    resolveRoute(seamMatrix.replicas, { profile_id: profile.profileId }),
    `replica state for ${profile.profileId}`,
  );
}

function profileOnPage(page: Page, profile: ProfileResource, label: string): ProfileResource {
  return { ...profile, card: profileCard(page, label) };
}

async function assertSharedMultiProfileView(page: Page, profiles: ProfileResource[]): Promise<void> {
  expect(scenario.actorAssertions.sameProvider).toBe(true);
  expect(scenario.actorAssertions.selectedSharing).toBe('declared_endpoint_only');
  expect(scenario.profiles).toHaveLength(scenario.actorAssertions.profileCount);
  expect(profiles).toHaveLength(scenario.actorAssertions.profileCount);
  expect(new Set(profiles.map((profile) => profile.profileId)).size).toBe(scenario.actorAssertions.profileCount);
  expect(new Set(scenario.profiles.map((profile) => profile.kind))).toEqual(new Set(['api_key', 'oauth']));
  expect(scenario.actorAssertions.replicaReadStatus).toBe(seamMatrix.replicas.status);
  const pageText = await page.locator('body').innerText();
  expect(pageText).toMatch(new RegExp(scenario.uiSemantics.deploymentSharedText, 'i'));
  for (const forbidden of scenario.uiSemantics.forbiddenOwnershipTerms) {
    expect(pageText).not.toMatch(new RegExp(`\\b${escapeRegex(forbidden)}\\b`, 'i'));
  }

  const providerCards = page.getByRole('article', {
    name: new RegExp(escapeRegex(scenario.provider)),
  });
  await expect(providerCards).toHaveCount(1);
  await expect(providerCards).toContainText(scenario.model);

  for (const [index, primaryProfile] of profiles.entries()) {
    const expectedProfile = scenario.profiles[index];
    expect(expectedProfile.sharing).toBe('selected');
    expect(expectedProfile.notSharedEndpointLabel).not.toBe(expectedProfile.endpointLabel);
    const profile = profileOnPage(page, primaryProfile, expectedProfile.label);
    await expect(profile.card).toHaveCount(1);
    await expect(profile.card).toContainText(
      expectedProfile.kind === 'oauth' ? /OAuth/i : /API[- ]key/i,
    );
    if (expectedProfile.default) {
      await expect(profile.card).toContainText(/explicit default|default profile/i);
    } else {
      await expect(profile.card).toContainText(/not default|select as default/i);
    }
    await expectDistributionStatus(page, profile, expectedProfile.endpointLabel, 'ready');

    await expect(distributionRow(profile.card, expectedProfile.notSharedEndpointLabel)).toHaveCount(0);
  }
}

async function gotoProvidersWithBootstrap(
  page: Page,
  serverBaseUrl: string,
  expectProfileList = false,
): Promise<void> {
  const ledger = browserRouteLedger(page);
  const after = ledger.mark();
  const navigation = await page.goto(`${serverBaseUrl}/providers`, { waitUntil: 'domcontentloaded' });
  expect(new URL(page.url()).origin).toBe(new URL(serverBaseUrl).origin);
  if (navigation?.status() === 404) {
    throw new ShallowNonEvidence404('GET /providers management shell');
  }
  await ledger.expectNext(resolveRoute(seamMatrix.bootstrap.system), 'provider bootstrap system', after);
  await ledger.expectNext(resolveRoute(seamMatrix.bootstrap.endpoints), 'provider bootstrap endpoints', after);
  await ledger.expectNext(resolveRoute(seamMatrix.bootstrap.providers), 'provider bootstrap providers', after);
  if (expectProfileList) {
    await ledger.expectNext(
      resolveRoute(seamMatrix.profileList, { provider: scenario.provider }),
      'provider profile list visibility',
      after,
    );
  }
  await expect(page.getByRole('heading', { name: 'Providers', exact: true })).toBeVisible();
}

async function openProviders(page: Page): Promise<void> {
  const ledger = browserRouteLedger(page);
  const after = ledger.mark();
  await page.getByRole('link', { name: 'Providers' }).click();
  await ledger.expectNext(resolveRoute(seamMatrix.bootstrap.providers), 'providers navigation', after);
  await expect(page.getByRole('heading', { name: 'Providers', exact: true })).toBeVisible();
}

async function openEndpoints(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Endpoints' }).click();
  await expect(page.getByRole('heading', { name: 'Endpoints', exact: true })).toBeVisible();
}

async function addRemoteEndpoint(
  page: Page,
  label: string,
  baseUrl: string,
  controlSecret: string,
  proxy: EndpointProxy,
): Promise<string> {
  await openEndpoints(page);
  await page.getByRole('button', { name: 'Add remote Endpoint' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add remote Endpoint' });
  await dialog.getByLabel('Endpoint label').fill(label);
  await dialog.getByLabel('Endpoint URL').fill(baseUrl);
  const secret = dialog.getByLabel('Controller credential');
  await expect(secret).toHaveAttribute('type', 'password');
  await secret.fill(controlSecret);
  const response = await expectResponseAfter(
    page,
    resolveRoute(seamMatrix.endpointCatalog.create),
    () => dialog.getByRole('button', { name: 'Add Endpoint' }).click(),
    `add ${label}`,
  );
  const responseBody = (await response.json()) as JsonObject;
  expect(typeof responseBody.endpoint_id).toBe('string');
  expect(JSON.stringify(responseBody)).not.toContain(controlSecret);
  await expectEndpointCatalogBarrier(proxy, label);
  await expect(dialog).toBeHidden();
  const endpoint = page.locator('article').filter({ hasText: label }).first();
  await expect(endpoint).toContainText(/online|ready/i);
  return String(responseBody.endpoint_id);
}

async function configureProvider(page: Page, recorderBaseUrl: string): Promise<void> {
  await openProviders(page);
  await page.getByRole('button', { name: 'Configure provider' }).click();
  const dialog = page.locator('form.editor-panel').filter({ hasText: 'Configure provider' });
  await dialog.getByLabel('Provider ID').fill(scenario.provider);
  await dialog.getByLabel('Provider kind').selectOption('openai_compatible');
  await dialog.getByLabel('Base URL').fill(`${recorderBaseUrl}/v1`);
  await dialog.getByLabel('Models').fill(scenario.model);
  const response = await expectResponseAfter(
    page,
    resolveRoute(seamMatrix.providerDescriptor, { provider: scenario.provider }),
    () => dialog.getByRole('button', { name: 'Save provider' }).click(),
    'provider descriptor revision 1',
  );
  const responseBody = (await response.json()) as JsonObject;
  expect(responseBody.provider).toBe(scenario.provider);
  expect(Number(responseBody.revision)).toBe(1);
  await expect(dialog).toHaveCount(0);
  await expect(page.locator('article').filter({ hasText: scenario.provider }).first()).toContainText(scenario.model);
}

async function updateProviderDescriptor(page: Page, recorderBaseUrl: string, model: string): Promise<void> {
  await openProviders(page);
  const provider = page.getByRole('article', { name: new RegExp(escapeRegex(scenario.provider)) });
  await provider.getByRole('button', { name: 'Edit provider descriptor' }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit provider descriptor' });
  await dialog.getByLabel('Execution base URL').fill(`${recorderBaseUrl}/v1`);
  await dialog.getByLabel('Model').fill(model);
  const response = await expectResponseAfter(
    page,
    resolveRoute(seamMatrix.providerDescriptor, { provider: scenario.provider }),
    () => dialog.getByRole('button', { name: 'Save provider descriptor' }).click(),
    'provider descriptor revision 2',
  );
  const responseBody = (await response.json()) as JsonObject;
  expect(responseBody.provider).toBe(scenario.provider);
  expect(Number(responseBody.revision)).toBe(2);
  await expect(dialog).toBeHidden();
  await expect(provider).toContainText(model);
}

type SessionCreateObservation = {
  path: string;
  idempotencyKey: string;
  body: JsonObject;
  status: number;
  responseBody: JsonObject;
  sessionId: string;
  profileId: string;
  minimumAuthRevision: number;
  descriptor: JsonObject;
};

function jsonObject(value: unknown, label: string): JsonObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} was not a JSON object`);
  }
  return value as JsonObject;
}

function jsonString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} was not a non-empty string`);
  return value;
}

function jsonNumber(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`${label} was not a finite number`);
  return value;
}

function cloneJsonObject(value: JsonObject): JsonObject {
  return jsonObject(JSON.parse(JSON.stringify(value)), 'cloned JSON object');
}

async function installFirstSessionCreateResponseDrop(
  page: Page,
  observations: SessionCreateObservation[],
): Promise<() => Promise<void>> {
  let first = true;
  const handler = async (route: import('@playwright/test').Route): Promise<void> => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() !== 'POST' || !/^\/v1\/endpoints\/[^/]+\/sessions$/.test(path)) {
      await route.continue();
      return;
    }
    const body = jsonObject(request.postDataJSON() ?? {}, 'session create request body');
    const headers = request.headers();
    const response = await route.fetch();
    const endpointId = path.match(/^\/v1\/endpoints\/([^/]+)\/sessions$/)?.[1];
    if (!endpointId) throw new Error(`session create route did not expose an Endpoint ID: ${path}`);
    const expected = resolveRoute(seamMatrix.sessionCreate, { endpoint_id: endpointId });
    expect(request.method(), 'session create method').toBe(expected.method);
    expect(path, 'session create path').toBe(expected.path);
    expect(response.status(), 'session create status').toBe(expected.status);
    const responseBytes = await response.body();
    const responseBody = jsonObject(JSON.parse(responseBytes.toString('utf8')), 'session create response body');
    const model = jsonObject(body.model, 'session create model');
    const descriptor = jsonObject(model.provider_execution, 'session create provider descriptor');
    const sessionId = jsonString(responseBody.session_id ?? responseBody.id, 'session create response session ID');
    const profileId = jsonString(model.auth_profile_id, 'session create auth profile ID');
    const minimumAuthRevision = jsonNumber(
      model.minimum_auth_revision,
      'session create minimum auth revision',
    );
    observations.push({
      path,
      idempotencyKey: headers['idempotency-key'] ?? '',
      body: cloneJsonObject(body),
      status: response.status(),
      responseBody: cloneJsonObject(responseBody),
      sessionId,
      profileId,
      minimumAuthRevision,
      descriptor: cloneJsonObject(descriptor),
    });
    if (first) {
      first = false;
      await route.abort('connectionreset');
      return;
    }
    await route.fulfill({ status: response.status(), headers: response.headers(), body: responseBytes });
  };
  await page.route('**/v1/endpoints/*/sessions', handler);
  return async () => {
    await page.unroute('**/v1/endpoints/*/sessions', handler);
  };
}

function assertFrozenSessionCreateRetry(
  observations: SessionCreateObservation[],
  expectedRoute: RouteContract,
  expectedProfileId: string,
): void {
  if (observations.length !== 2) throw new Error(`expected exactly two session-create observations, got ${observations.length}`);
  const first = observations[0];
  const retry = observations[1];
  if (!first || !retry) throw new Error('session-create retry observations were incomplete');
  expect(first.idempotencyKey, 'first session-create idempotency key').not.toBe('');
  expect(retry.idempotencyKey, 'retry session-create idempotency key').toBe(first.idempotencyKey);
  expect(first.path).toBe(expectedRoute.path);
  expect(retry.path).toBe(expectedRoute.path);
  expect(first.status).toBe(expectedRoute.status);
  expect(retry.status).toBe(expectedRoute.status);
  expect(retry.body).toEqual(first.body);
  expect(retry.profileId, 'retry auth profile binding').toBe(first.profileId);
  expect(first.profileId, 'first auth profile binding').toBe(expectedProfileId);
  expect(retry.minimumAuthRevision, 'retry minimum auth revision').toBe(first.minimumAuthRevision);
  expect(retry.descriptor, 'retry full provider descriptor').toEqual(first.descriptor);
  expect(retry.sessionId, 'retry response idempotent session ID').toBe(first.sessionId);
  expect(retry.responseBody, 'retry response body').toEqual(first.responseBody);
  expect(first.sessionId, 'first session-create response session ID').not.toBe('');
  expect(first.descriptor.revision, 'first provider descriptor revision').toBe(1);
  expect(first.minimumAuthRevision, 'first minimum auth revision').toBe(1);
}

async function openSessionCreateDialog(page: Page, endpointLabel: string, profileLabel: string): Promise<Locator> {
  await page.getByRole('link', { name: 'Sessions' }).click();
  await page.getByRole('button', { name: /new session|create session/i }).click();
  const dialog = page.locator('form.editor-panel').filter({ hasText: /new session|create session/i }).last();
  await dialog.getByLabel('Endpoint', { exact: true }).selectOption({ label: endpointLabel });
  if (profileLabel) {
    await dialog.getByLabel('Auth profile', { exact: true }).selectOption({ label: profileLabel });
  }
  return dialog;
}

async function addApiKeyProfile(
  page: Page,
  label: string,
  apiKey: string,
  endpointLabel: string,
  makeDefault: boolean,
  proxy: EndpointProxy,
): Promise<ProfileResource> {
  const providerCard = page.locator('article.resource-card').filter({ hasText: scenario.provider }).first();
  await providerCard.getByRole('button', { name: /add api[- ]key profile/i }).click();
  const form = providerCard.locator('form.nested-editor');
  await form.getByLabel('Profile label').fill(label);
  const secret = form.getByLabel('API key');
  await expect(secret).toHaveAttribute('type', 'password');
  await secret.fill(apiKey);
  await expect(secret).toHaveAttribute('autocomplete', /off|new-password/);
  if (makeDefault) await form.getByRole('checkbox', { name: 'Make this the default profile' }).check();
  await form.getByRole('checkbox', { name: `Share with ${endpointLabel}` }).check();
  const response = await expectResponseAfter(
    page,
    resolveRoute(seamMatrix.profileCreate, { provider: scenario.provider }),
    () => form.getByRole('button', { name: /create profile/i }).click(),
    `create profile ${label}`,
  );
  const responseBody = (await response.json()) as JsonObject;
  const profileId = String(responseBody.auth_profile_id ?? '');
  const revision = Number(responseBody.revision ?? 0);
  expect(profileId, `profile ${label} ID`).not.toBe('');
  expect(revision, `profile ${label} revision`).toBe(1);
  expect(responseBody.kind, `profile ${label} kind`).toBe('api_key');
  expect(JSON.stringify(responseBody)).not.toContain(apiKey);
  await expectEndpointRequest(
    proxy,
    resolveRoute(seamMatrix.replicaInstall, { profile_id: profileId }),
    `install replica for ${label}`,
  );
  await expect(form).toHaveCount(0);
  return { card: profileCard(page, label), profileId, revision };
}

function findProfileInJson(
  value: unknown,
  label: string,
): { profileId: string; revision: number; kind: string } | undefined {
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findProfileInJson(item, label);
      if (found) return found;
    }
    return undefined;
  }
  if (typeof value !== 'object' || value === null) return undefined;
  const object = value as JsonObject;
  const objectLabel = object.label ?? object.name;
  const objectId = object.auth_profile_id ?? object.profile_id ?? object.id;
  if (objectLabel === label && typeof objectId === 'string' && objectId.length > 0) {
    const revision = Number(object.revision ?? 0);
    if (!Number.isFinite(revision) || revision < 1) throw new Error(`OAuth profile ${label} had no revision`);
    if (typeof object.kind !== 'string') throw new Error(`OAuth profile ${label} had no kind`);
    return { profileId: objectId, revision, kind: object.kind };
  }
  for (const child of Object.values(object)) {
    const found = findProfileInJson(child, label);
    if (found) return found;
  }
  return undefined;
}

async function addOAuthProfile(
  page: Page,
  label: string,
  endpointLabel: string,
  makeDefault: boolean,
  proxy: EndpointProxy,
  provider: OAuthProviderFixture,
  managementOrigin: string,
): Promise<ProfileResource> {
  await page.getByRole('button', { name: /add\s+(an?\s+)?oauth|new\s+oauth|sign\s+in\s+with\s+provider/i }).click();
  const dialog = page.getByRole('dialog').last();
  await dialog.getByLabel('Profile label').fill(label);
  if (makeDefault) await dialog.getByRole('checkbox', { name: 'Make this the default profile' }).check();
  await dialog.getByRole('checkbox', { name: `Share with ${endpointLabel}` }).check();

  const attemptResponsePromise = page.waitForResponse((response) => {
    const path = new URL(response.url()).pathname;
    return response.request().method() === 'POST' && /^\/v1\/providers\/[^/]+\/auth-attempts$/.test(path);
  });
  const ticketResponsePromise = page.waitForResponse((response) => {
    const path = new URL(response.url()).pathname;
    return response.request().method() === 'POST' && /^\/v1\/auth-attempts\/[^/]+\/authorize-tickets$/.test(path);
  });
  await dialog
    .getByRole('button', { name: /start\s+oauth|begin\s+oauth|create\s+oauth|continue(?!\s+to\s+provider)/i })
    .click();
  const [attemptResponse, ticketResponse] = await Promise.all([attemptResponsePromise, ticketResponsePromise]);
  expect(attemptResponse.request().method()).toBe('POST');
  expect(new URL(attemptResponse.url()).pathname).toMatch(/^\/v1\/providers\/[^/]+\/auth-attempts$/);
  expect(new URL(attemptResponse.url()).origin).toBe(managementOrigin);
  expect(attemptResponse.status()).toBeGreaterThanOrEqual(200);
  expect(attemptResponse.status()).toBeLessThan(300);
  expect(ticketResponse.request().method()).toBe('POST');
  expect(new URL(ticketResponse.url()).pathname).toMatch(/^\/v1\/auth-attempts\/[^/]+\/authorize-tickets$/);
  expect(new URL(ticketResponse.url()).origin).toBe(managementOrigin);
  expect(ticketResponse.status()).toBeGreaterThanOrEqual(200);
  expect(ticketResponse.status()).toBeLessThan(300);
  const ticketBody = jsonObject(await ticketResponse.json(), 'OAuth authorize-ticket response');
  const ticket = jsonString(ticketBody.ticket, 'OAuth authorize ticket');
  const beforeExplicitAction = await page.locator('html').evaluate((root) => root.outerHTML);
  expect(beforeExplicitAction).not.toContain(ticket);
  expect(page.url()).not.toContain(ticket);

  const providerBefore = await provider.state();
  await page.getByRole('button', { name: /continue\s+to\s+provider|open\s+provider|authorize|proceed/i }).click();
  await provider.waitForAuthorize(providerBefore.authorize_count);
  await page.waitForURL(
    (url) => url.origin === provider.origin && url.pathname === '/oauth/authorize',
    { timeout: ACTION_TIMEOUT_MS },
  );
  const providerUrl = new URL(page.url());
  expect(providerUrl.searchParams.has('ticket')).toBe(false);
  await expect(page.getByRole('heading', { name: /fixture provider authorization/i })).toBeVisible();

  const callbackResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === 'GET' && url.pathname === '/v1/oauth/callback';
  });
  await page.getByRole('button', { name: /approve|allow/i }).click();
  const callbackResponse = await callbackResponsePromise;
  expect(callbackResponse.request().method()).toBe('GET');
  expect(new URL(callbackResponse.url()).pathname).toBe('/v1/oauth/callback');
  expect(new URL(callbackResponse.url()).origin).toBe(managementOrigin);
  expect(callbackResponse.status()).toBeGreaterThanOrEqual(200);
  expect(callbackResponse.status()).toBeLessThan(400);
  await expect(page.getByRole('heading', { name: 'Providers' })).toBeVisible({ timeout: ACTION_TIMEOUT_MS });

  const profileListResponse = await expectResponseAfter(
    page,
    resolveRoute(seamMatrix.profileList, { provider: scenario.provider }),
    () => page.reload({ waitUntil: 'domcontentloaded' }).then(() => undefined),
    `OAuth profile list for ${label}`,
  );
  const profileListBody: unknown = await profileListResponse.json();
  const found = findProfileInJson(profileListBody, label);
  if (!found) throw new Error(`OAuth profile ${label} was absent from the profile list response`);
  expect(found.kind, `OAuth profile ${label} kind`).toBe('oauth');
  expect(JSON.stringify(profileListBody)).not.toContain(OAUTH_SECRET_MARKERS[0]);
  expect(JSON.stringify(profileListBody)).not.toContain(OAUTH_SECRET_MARKERS[1]);
  const replicaPath = resolveRoute(seamMatrix.replicaInstall, { profile_id: found.profileId });
  await expectEndpointRequest(proxy, replicaPath, `install OAuth replica for ${label}`);
  await expect(dialog).toBeHidden().catch(() => undefined);
  const storage = await page.evaluate(() => `${JSON.stringify(localStorage)}${JSON.stringify(sessionStorage)}`);
  expect(storage).not.toContain(ticket);
  expect((await page.locator('html').evaluate((root) => root.outerHTML))).not.toContain(ticket);
  expect(page.url()).not.toContain(ticket);
  return { card: profileCard(page, label), profileId: found.profileId, revision: found.revision };
}

async function rotateApiKey(
  page: Page,
  profile: ProfileResource,
  nextApiKey: string,
  proxy: EndpointProxy,
): Promise<void> {
  const replicaPath = resolveRoute(seamMatrix.replicaInstall, { profile_id: profile.profileId });
  const before = endpointRequestCount(proxy, replicaPath);
  await profile.card.getByRole('button', { name: 'Rotate API key' }).click();
  const dialog = page.getByRole('dialog', { name: 'Rotate API key' });
  const secret = dialog.getByLabel('New API key (write-only)');
  await expect(secret).toHaveAttribute('type', 'password');
  await secret.fill(nextApiKey);
  await dialog.getByRole('button', { name: 'Save new API key' }).click();
  await expectEndpointRequest(proxy, replicaPath, `rotated replica for ${profile.profileId}`, before);
  await expect(dialog).toBeHidden();
}

async function removeEndpointSharing(
  page: Page,
  profile: ProfileResource,
  endpointLabel: string,
  proxy: EndpointProxy,
): Promise<void> {
  await profile.card.getByRole('button', { name: 'Edit sharing' }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit sharing' });
  const share = dialog.getByRole('checkbox', { name: `Share with ${endpointLabel}` });
  await expect(share).toBeChecked();
  await share.uncheck();
  const tombstonePath = resolveRoute(seamMatrix.replicaTombstone, { profile_id: profile.profileId });
  const requestBefore = endpointRequestCount(proxy, tombstonePath);
  const responseBefore = endpointResponseCount(proxy, tombstonePath);
  await expectResponseAfter(
    page,
    resolveRoute(seamMatrix.sharing, { profile_id: profile.profileId }),
    () => dialog.getByRole('button', { name: 'Save sharing' }).click(),
    `remove sharing for ${profile.profileId}`,
  );
  await expectEndpointRequest(proxy, tombstonePath, `tombstone request for ${profile.profileId}`, requestBefore);
  await expectEndpointResponse(
    proxy,
    { ...tombstonePath, status: 502 },
    `offline tombstone response for ${profile.profileId}`,
    responseBefore,
  );
  await expect(dialog).toBeHidden();
}

async function setDefaultProfile(page: Page, profileId: string, card: Locator): Promise<void> {
  await expectResponseAfter(
    page,
    resolveRoute(seamMatrix.defaultProfile, { provider: scenario.provider }),
    () => card.getByRole('button', { name: 'Set as default' }).click(),
    `set default profile ${profileId}`,
  );
  await expect(card).toContainText(/default/i);
}

async function probeEndpointStatus(
  page: Page,
  proxy: EndpointProxy,
  endpointId: string,
  expectedPublicStatus: number,
  expectedUpstreamStatus: number,
  label: string,
): Promise<void> {
  const identity = resolveRoute(seamMatrix.endpointCatalog.identity);
  const capabilities = resolveRoute(seamMatrix.endpointCatalog.capabilities);
  const identityBefore = endpointResponseCount(proxy, identity);
  const capabilitiesBefore = endpointResponseCount(proxy, capabilities);
  const endpointLabel = label.replace(/\s+(?:offline|restored)$/i, '');
  const endpointCard = page.locator('article.resource-card').filter({ hasText: endpointLabel }).first();
  const response = await expectResponseAfter(
    page,
    resolvedProbeContract(endpointId, expectedPublicStatus),
    () => endpointCard.getByRole('button', { name: 'Refresh Endpoint status' }).click(),
    `${label} probe`,
  );
  if (expectedPublicStatus === seamMatrix.endpointCatalog.probe.offlineStatus) {
    const body = (await response.json()) as JsonObject;
    expect((body.error as JsonObject | undefined)?.code, `${label} public error`).toBe('endpoint_unavailable');
  }
  await expectEndpointResponse(proxy, { ...identity, status: expectedUpstreamStatus }, `${label} identity`, identityBefore);
  if (expectedPublicStatus === seamMatrix.endpointCatalog.probe.offlineStatus) {
    await expect
      .poll(
        () => endpointResponseCount(proxy, capabilities),
        { timeout: ACTION_TIMEOUT_MS },
      )
      .toBe(capabilitiesBefore);
  } else {
    await expectEndpointResponse(
      proxy,
      { ...capabilities, status: expectedUpstreamStatus },
      `${label} capabilities`,
      capabilitiesBefore,
    );
  }
}

async function assertDeleteWarningAndCancel(page: Page, card: Locator): Promise<void> {
  await card.getByRole('button', { name: 'Delete profile' }).click();
  const dialog = page.getByRole('dialog', { name: 'Delete profile' });
  await expect(dialog).toContainText(/best[- ]effort/i);
  await expect(dialog).toContainText(/provider-side.*(rotation|revocation)/i);
  const confirm = dialog.getByRole('button', { name: 'Delete profile permanently' });
  await expect(confirm).toBeDisabled();
  await dialog.getByRole('checkbox', { name: /understand|acknowledge/i }).check();
  await expect(confirm).toBeEnabled();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
}

test.describe('provider profile distribution', () => {
  test.describe.configure({ mode: 'serial', timeout: 180_000 });
  test.use({ actionTimeout: ACTION_TIMEOUT_MS, navigationTimeout: ACTION_TIMEOUT_MS });

  test('e2e_provider_profiles_two_profiles_same_provider_have_explicit_default_and_distinct_endpoint_sharing', async ({
    browser,
    context,
    page,
  }, testInfo) => {
    const apiKeyA = `web-e2e-api-key-a-${randomUUID()}`;
    const controllerA = `web-e2e-controller-a-${randomUUID()}`;
    const controllerB = `web-e2e-controller-b-${randomUUID()}`;
    const environment = await ProviderDistributionEnvironment.start(
      [apiKeyA, controllerA, controllerB],
      testInfo.title,
      [controllerA, controllerB],
    );
    const guard = new SecretSurfaceGuard(page, context, [apiKeyA, controllerA, controllerB]);
    let actorB: ActorBrowserSession | undefined;
    try {
      await gotoProvidersWithBootstrap(page, environment.accessEdges[0].baseUrl);

      await addRemoteEndpoint(page, 'Endpoint A', environment.endpointProxies[0].baseUrl, controllerA, environment.endpointProxies[0]);
      await addRemoteEndpoint(page, 'Endpoint B', environment.endpointProxies[1].baseUrl, controllerB, environment.endpointProxies[1]);
      await configureProvider(page, environment.recorder.baseUrl);

      environment.endpointProxies[0].holdReplicaWrites = true;
      const profileA = await addApiKeyProfile(
        page,
        scenario.profiles[0].label,
        apiKeyA,
        scenario.profiles[0].endpointLabel,
        scenario.profiles[0].default,
        environment.endpointProxies[0],
      );
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'pending');
      await expect(profileA.card.getByRole('button', { name: 'Refresh profile' })).toBeDisabled();
      await guard.assertClean();

      await environment.endpointProxies[0].releaseReplicaWrites();
      await expectEndpointResponse(
        environment.endpointProxies[0],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profileA.profileId }),
        'profile A replica install',
      );
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'ready');
      await expect(profileA.card).toContainText(/explicit default|default profile/i);

      environment.endpointProxies[1].holdReplicaWrites = true;
      const profileB = await addOAuthProfile(
        page,
        scenario.profiles[1].label,
        scenario.profiles[1].endpointLabel,
        scenario.profiles[1].default,
        environment.endpointProxies[1],
        environment.oauthProvider,
        environment.accessEdges[0].baseUrl,
      );
      await expectDistributionStatus(page, profileB, scenario.profiles[1].endpointLabel, 'pending');
      await expect(profileB.card).toContainText(/not default|select as default/i);
      await environment.endpointProxies[1].releaseReplicaWrites();
      await expectEndpointResponse(
        environment.endpointProxies[1],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profileB.profileId }),
        'profile B replica install',
      );
      await expectDistributionStatus(page, profileB, scenario.profiles[1].endpointLabel, 'ready');
      await expect(profileB.card).toContainText(/not default|select as default/i);

      await expect(distributionRow(profileA.card, scenario.profiles[0].endpointLabel)).toContainText(/Endpoint A/);
      await expect(distributionRow(profileA.card, scenario.profiles[1].endpointLabel)).toHaveCount(0);
      await expect(distributionRow(profileB.card, scenario.profiles[1].endpointLabel)).toContainText(/Endpoint B/);
      await expect(distributionRow(profileB.card, scenario.profiles[0].endpointLabel)).toHaveCount(0);
      await expect(profileA.card.getByRole('button', { name: 'Refresh profile' })).toBeEnabled();
      await assertSharedMultiProfileView(page, [profileA, profileB]);

      actorB = await openActorBrowserSession(
        browser,
        environment.accessEdges[1],
        [apiKeyA, controllerA, controllerB],
      );
      await gotoProvidersWithBootstrap(actorB.page, environment.accessEdges[1].baseUrl, true);
      await assertSharedMultiProfileView(actorB.page, [
        profileOnPage(actorB.page, profileA, scenario.profiles[0].label),
        profileOnPage(actorB.page, profileB, scenario.profiles[1].label),
      ]);
      await openEndpoints(actorB.page);
      await expect(
        actorB.page.getByRole('article', { name: new RegExp(escapeRegex(scenario.profiles[0].endpointLabel)) }),
      ).toHaveCount(1);
      await expect(
        actorB.page.getByRole('article', { name: new RegExp(escapeRegex(scenario.profiles[1].endpointLabel)) }),
      ).toHaveCount(1);
      await openProviders(actorB.page);
      await actorB.guard.assertClean();
      await assertDeleteWarningAndCancel(page, profileA.card);
      await guard.assertClean();
    } finally {
      await actorB?.close().catch(() => undefined);
      await environment.stop();
    }
    expect(environment.recorder.exchanges.length).toBe(scenario.llm.requestsExpected);
  });

  test('e2e_provider_profiles_distribution_reconciles_stale_unreachable_and_removed_with_safe_action_gates', async ({
    context,
    page,
  }, testInfo) => {
    const apiKeyA = `web-e2e-api-key-a-${randomUUID()}`;
    const rotatedApiKeyA = `web-e2e-api-key-a-rotated-${randomUUID()}`;
    const controllerA = `web-e2e-controller-a-${randomUUID()}`;
    const controllerB = `web-e2e-controller-b-${randomUUID()}`;
    const environment = await ProviderDistributionEnvironment.start(
      [apiKeyA, rotatedApiKeyA, controllerA, controllerB],
      testInfo.title,
      [controllerA, controllerB],
    );
    const guard = new SecretSurfaceGuard(page, context, [apiKeyA, rotatedApiKeyA, controllerA, controllerB]);
    try {
      await gotoProvidersWithBootstrap(page, environment.accessEdges[0].baseUrl);
      const endpointAId = await addRemoteEndpoint(
        page,
        'Endpoint A',
        environment.endpointProxies[0].baseUrl,
        controllerA,
        environment.endpointProxies[0],
      );
      await addRemoteEndpoint(
        page,
        'Endpoint B',
        environment.endpointProxies[1].baseUrl,
        controllerB,
        environment.endpointProxies[1],
      );
      await configureProvider(page, environment.recorder.baseUrl);

      const profileA = await addApiKeyProfile(
        page,
        scenario.profiles[0].label,
        apiKeyA,
        scenario.profiles[0].endpointLabel,
        scenario.profiles[0].default,
        environment.endpointProxies[0],
      );
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'ready');
      await expectEndpointResponse(
        environment.endpointProxies[0],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profileA.profileId }),
        'profile A replica install',
      );
      const profileB = await addOAuthProfile(
        page,
        scenario.profiles[1].label,
        scenario.profiles[1].endpointLabel,
        scenario.profiles[1].default,
        environment.endpointProxies[1],
        environment.oauthProvider,
        environment.accessEdges[0].baseUrl,
      );
      await expectDistributionStatus(page, profileB, scenario.profiles[1].endpointLabel, 'ready');
      await expectEndpointResponse(
        environment.endpointProxies[1],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profileB.profileId }),
        'profile B replica install',
      );

      environment.endpointProxies[0].holdReplicaWrites = true;
      await rotateApiKey(page, profileA, rotatedApiKeyA, environment.endpointProxies[0]);
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'stale');
      await expect(profileA.card.getByRole('button', { name: 'Refresh profile' })).toBeDisabled();
      await guard.assertClean();

      await environment.endpointProxies[0].releaseReplicaWrites();
      await expectEndpointResponse(
        environment.endpointProxies[0],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profileA.profileId }),
        'rotated profile A replica install',
      );
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'ready');

      environment.endpointProxies[0].online = false;
      await probeEndpointStatus(
        page,
        environment.endpointProxies[0],
        endpointAId,
        seamMatrix.endpointCatalog.probe.offlineStatus,
        502,
        'Endpoint A offline',
      );
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'unreachable');
      await expect(profileA.card.getByRole('button', { name: 'Refresh profile' })).toBeDisabled();
      await guard.assertClean();

      await removeEndpointSharing(page, profileA, scenario.profiles[0].endpointLabel, environment.endpointProxies[0]);
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'unreachable');
      await expect(profileA.card).toContainText(/removal pending|unreachable/i);

      environment.endpointProxies[0].online = true;
      await probeEndpointStatus(
        page,
        environment.endpointProxies[0],
        endpointAId,
        seamMatrix.endpointCatalog.probe.onlineStatus,
        200,
        'Endpoint A restored',
      );
      await expectEndpointResponse(
        environment.endpointProxies[0],
        resolveRoute(seamMatrix.replicaTombstone, { profile_id: profileA.profileId }),
        'profile A tombstone acknowledgement',
      );
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'removed');
      await expect(profileA.card).toContainText(/removed/i);
      await expect(profileA.card.getByRole('button', { name: 'Refresh profile' })).toBeHidden();
      await expect(profileA.card.getByRole('button', { name: 'Use for session' })).toBeHidden();
      await assertDeleteWarningAndCancel(page, profileB.card);
      await guard.assertClean();
    } finally {
      await environment.stop();
    }
    expect(environment.recorder.exchanges.length).toBe(scenario.llm.requestsExpected);
  });

  test('e2e_browser_first_run_freezes_profile_descriptor_and_waits_for_replica_ready', async ({
    browser,
    context,
    page,
  }, testInfo) => {
    expect(testInfo.title).toBe(FIRST_FAILURE_OWNER);
    const cassette = loadFirstFailureCassette();
    const apiKeyA = `web-e2e-api-key-a-${randomUUID()}`;
    const controllerA = `web-e2e-controller-a-${randomUUID()}`;
    const controllerB = `web-e2e-controller-b-${randomUUID()}`;
    const environment = await ProviderDistributionEnvironment.start(
      [apiKeyA, controllerA, controllerB],
      testInfo.title,
      [controllerA, controllerB],
    );
    const guard = new SecretSurfaceGuard(page, context, [apiKeyA, controllerA, controllerB]);
    let adminPage: Page | undefined;
    let actorB: ActorBrowserSession | undefined;
    let removeSessionRoute: (() => Promise<void>) | undefined;
    try {
      if (process.env.ZODE_REPLAY_CASSETTE === '1') {
        await replayFirstFailureCassette(page, environment, cassette);
        await guard.assertClean();
        return;
      }
      await assertBootstrapRouteIsRepaired(page, context, environment, cassette);
      await gotoProvidersWithBootstrap(page, environment.accessEdges[0].baseUrl);

      const endpointAId = await addRemoteEndpoint(
        page,
        'Endpoint A',
        environment.endpointProxies[0].baseUrl,
        controllerA,
        environment.endpointProxies[0],
      );
      const endpointBId = await addRemoteEndpoint(
        page,
        'Endpoint B',
        environment.endpointProxies[1].baseUrl,
        controllerB,
        environment.endpointProxies[1],
      );
      await configureProvider(page, environment.recorder.baseUrl);

      environment.endpointProxies[0].holdReplicaWrites = true;
      const profileA = await addApiKeyProfile(
        page,
        scenario.profiles[0].label,
        apiKeyA,
        scenario.profiles[0].endpointLabel,
        true,
        environment.endpointProxies[0],
      );
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'pending');
      const pendingSessionDialog = await openSessionCreateDialog(page, scenario.profiles[0].endpointLabel, '');
      await expect(pendingSessionDialog.getByLabel('Auth profile', { exact: true })).toHaveValue('');
      await expect(pendingSessionDialog.getByRole('button', { name: /start session|create session/i })).toBeDisabled();
      await pendingSessionDialog.getByRole('button', { name: 'Cancel' }).click();

      environment.endpointProxies[0].online = false;
      await openEndpoints(page);
      await probeEndpointStatus(
        page,
        environment.endpointProxies[0],
        endpointAId,
        seamMatrix.endpointCatalog.probe.offlineStatus,
        502,
        'Endpoint A offline',
      );
      await openProviders(page);
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'unreachable');
      await expect(profileA.card.getByRole('button', { name: 'Refresh profile' })).toBeDisabled();

      environment.endpointProxies[0].online = true;
      await environment.endpointProxies[0].releaseReplicaWrites();
      await expectEndpointResponse(
        environment.endpointProxies[0],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profileA.profileId }),
        'profile A replica install',
      );
      await page.reload({ waitUntil: 'domcontentloaded' });
      await expect(page.getByRole('heading', { name: 'Providers', exact: true })).toBeVisible();
      await expectDistributionStatus(page, profileA, scenario.profiles[0].endpointLabel, 'ready');
      await expect(profileA.card.getByRole('button', { name: 'Refresh profile' })).toBeEnabled();

      const profileB = await addOAuthProfile(
        page,
        scenario.profiles[1].label,
        scenario.profiles[1].endpointLabel,
        false,
        environment.endpointProxies[1],
        environment.oauthProvider,
        environment.accessEdges[0].baseUrl,
      );
      await expectDistributionStatus(page, profileB, scenario.profiles[1].endpointLabel, 'ready');
      await expectEndpointResponse(
        environment.endpointProxies[1],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profileB.profileId }),
        'profile B replica install',
      );

      const observations: SessionCreateObservation[] = [];
      removeSessionRoute = await installFirstSessionCreateResponseDrop(page, observations);
      const sessionDialog = await openSessionCreateDialog(
        page,
        scenario.profiles[0].endpointLabel,
        scenario.profiles[0].label,
      );
      const createButton = sessionDialog.getByRole('button', { name: /start session|create session/i });
      await expect(createButton).toBeEnabled();
      await createButton.click();
      await expect
        .poll(() => observations.length, { timeout: ACTION_TIMEOUT_MS })
        .toBe(1);
      await expect(page.getByRole('button', { name: 'Retry session creation' })).toBeVisible();

      actorB = await openActorBrowserSession(
        browser,
        environment.accessEdges[1],
        [apiKeyA, controllerA, controllerB],
      );
      adminPage = actorB.page;
      await gotoProvidersWithBootstrap(adminPage, environment.accessEdges[1].baseUrl, true);
      await assertSharedMultiProfileView(adminPage, [
        profileOnPage(adminPage, profileA, scenario.profiles[0].label),
        profileOnPage(adminPage, profileB, scenario.profiles[1].label),
      ]);
      const adminProfileB = profileCard(adminPage, scenario.profiles[1].label);
      await setDefaultProfile(adminPage, profileB.profileId, adminProfileB);
      await updateProviderDescriptor(adminPage, environment.recorder.baseUrl, `${scenario.model}-changed`);
      await expect(adminPage.getByRole('article', { name: new RegExp(escapeRegex(scenario.provider)) })).toContainText(
        /revision\s*2/i,
      );

      await page.getByRole('button', { name: 'Retry session creation' }).click();
      await expect
        .poll(() => observations.length, { timeout: ACTION_TIMEOUT_MS })
        .toBe(2);
      const expectedSessionRoute = resolveRoute(seamMatrix.sessionCreate, { endpoint_id: endpointAId });
      assertFrozenSessionCreateRetry(observations, expectedSessionRoute, profileA.profileId);
      const firstModel = jsonObject(observations[0]?.body.model, 'first session-create model');
      expect(observations[0]?.body.endpoint_id).toBeUndefined();
      expect(firstModel.provider).toBe(scenario.provider);
      expect(firstModel.model).toBe(scenario.model);
      expect(observations[0]?.path).not.toBe(`/v1/endpoints/${endpointBId}/sessions`);
      await expect(page).toHaveURL(new RegExp(`/endpoints/${endpointAId}/sessions/`));
      await guard.assertClean();
      await guard.assertClean(adminPage);
    } finally {
      await removeSessionRoute?.().catch(() => undefined);
      await actorB?.close().catch(() => undefined);
      await environment.stop();
    }
    expect(environment.recorder.exchanges.length).toBe(scenario.llm.requestsExpected);
  });

  test('e2e_provider_profiles_secret_markers_never_enter_dom_accessibility_storage_url_console_or_download', async ({
    context,
    page,
  }, testInfo) => {
    const apiKey = `web-e2e-secret-${randomUUID()}`;
    const controllerSecret = `web-e2e-control-secret-${randomUUID()}`;
    const secondaryControllerSecret = `web-e2e-control-secret-secondary-${randomUUID()}`;
    const environment = await ProviderDistributionEnvironment.start(
      [apiKey, controllerSecret, secondaryControllerSecret],
      testInfo.title,
      [controllerSecret, secondaryControllerSecret],
    );
    const guard = new SecretSurfaceGuard(page, context, [apiKey, controllerSecret]);
    try {
      await gotoProvidersWithBootstrap(page, environment.accessEdges[0].baseUrl);
      await addRemoteEndpoint(
        page,
        'Endpoint A',
        environment.endpointProxies[0].baseUrl,
        controllerSecret,
        environment.endpointProxies[0],
      );
      await configureProvider(page, environment.recorder.baseUrl);
      const profile = await addApiKeyProfile(
        page,
        scenario.profiles[0].label,
        apiKey,
        scenario.profiles[0].endpointLabel,
        true,
        environment.endpointProxies[0],
      );
      await expectDistributionStatus(page, profile, scenario.profiles[0].endpointLabel, 'ready');
      await expectEndpointResponse(
        environment.endpointProxies[0],
        resolveRoute(seamMatrix.replicaInstall, { profile_id: profile.profileId }),
        'secret test replica install',
      );
      await guard.assertClean();
      await page.reload({ waitUntil: 'domcontentloaded' });
      await expect(profile.card).toContainText(scenario.profiles[0].label);
      await guard.assertClean();
    } finally {
      await environment.stop();
    }
    expect(environment.recorder.exchanges.length).toBe(scenario.llm.requestsExpected);
  });
});
