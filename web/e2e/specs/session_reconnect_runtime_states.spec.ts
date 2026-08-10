import { expect, test, type Locator, type Page, type Request, type Route } from "@playwright/test";
import { createHash, createSign, generateKeyPairSync, randomBytes, randomUUID, type KeyObject } from "node:crypto";
import { execFile as execFileCallback, spawn, type ChildProcessByStdio } from "node:child_process";
import { readFile, writeFile, mkdir, chmod, cp, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { createServer as createTcpServer, type Socket } from "node:net";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import type { Readable } from "node:stream";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

type Json = Record<string, any>;
type Cassette = Json & { exchanges: Json[] };
type ReadyChild = ChildProcessByStdio<null, Readable, Readable>;
type SecretMarker = string | Buffer;
type ProcessOutput = {
  stdoutChunks: Buffer[];
  stderrChunks: Buffer[];
  stdoutTotal: { value: number };
  stderrTotal: { value: number };
};
type EndpointBoundaryRequest = {
  method: string;
  path: string;
  requestId: string;
  forwardedRequestId: string;
  lastEventId: string;
  forwardedLastEventId: string;
  body: string;
  status?: number;
  responseBody?: string;
  responseContentType?: string;
  responseEventIds: string[];
  responseEventNames: string[];
  responseDurableEvents: Array<{ id: string; name: string }>;
  responseFrames: Array<{
    id: string;
    name: string;
    sessionId?: string;
    messageId?: string;
  }>;
  responseCurrentEventId?: string;
  responseCurrentEventName?: string;
  responseCurrentSessionId?: string;
  responseCurrentMessageId?: string;
  responseSseRemainder?: string;
  responseComplete?: boolean;
  recorded?: boolean;
  matchedBrowserRequest?: BrowserSseRequest;
};
type BrowserSseRequest = {
  method: string;
  path: string;
  endpointId: string;
  requestId: string;
  lastEventId: string;
  status?: number;
  endpointRequest?: EndpointBoundaryRequest;
};
type BrowserNetworkObservation = {
  kind: "http" | "websocket";
  url: string;
  protocol: string;
  method?: string;
};
type BrowserPublicResponse = {
  status: number;
  body: Json | null;
  bodyText: string;
  contentType: string;
};
type TopologyConsumption = {
  topologyId: string;
  expectedSequences: number[];
  consumedSequences: number[];
  countsBySequence: Map<number, number>;
};
type BrowserResponseHold = {
  received: Promise<void>;
  release: () => void;
  dispose: () => Promise<void>;
};
type EndpointEventBodyHold = {
  received: Promise<EndpointBoundaryRequest>;
  release: () => void;
  dispose: () => void;
};

const REPO_ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const CASSETTE_PATH = fileURLToPath(
  new URL("../fixtures/session_reconnect_runtime_states/session_reconnect_runtime_states.v1.json", import.meta.url),
);
const ACCESS_AUDIENCE = "zode-web-session-reconnect-runtime-states";
const ACCESS_SUBJECT = "web-session-reconnect-runtime-states-human";
const CONTROLLER_AUTHORITY = "web-session-reconnect-runtime-states-controller";
const PROVIDER = "fixture-provider";
const MODEL = "fixture-model";
const REPLAY_HISTORY_MODEL = "fixture-model-history";
const REPLAY_BACKPRESSURE_EVENT_COUNT = 272;
const REPLAY_HISTORY_LARGE_MESSAGE_BYTES = 128 * 1024;
const TOOL = "fixture_async";
const REQUEST_ID_HEADER = "x-request-id";
const CASSETTE_RAW_SHA256 = "564185b09086c6533ca58ab9314a3cb5271909e3c5ff70ff45a32f586e084b63";
const ROUTE_MISSING_PATH = "/v1/__session_reconnect_route_missing__";
const ROUTE_CLASSIFIER_TEST_PREFIX = "e2e_browser_route_missing_classifier";
const CASSETTE_SECRET_SLOTS = ["SLOT_PROVIDER_AUTHORIZATION"];
const CASSETTE_REQUEST_SLOTS = [
  "SLOT_KEYBOARD_REQUEST_BODY",
  "SLOT_RECONNECT_REQUEST_BODY",
  "SLOT_OFFLINE_REQUEST_BODY",
  "SLOT_CANCEL_REQUEST_BODY",
  "SLOT_WAIT_TIMEOUT_REQUEST_BODY",
  "SLOT_UNKNOWN_OUTCOME_REQUEST_BODY",
  "SLOT_MOBILE_ACTIVITY_REQUEST_BODY",
];
const CASSETTE_SLOT_MARKERS = [
  ...CASSETTE_SECRET_SLOTS,
  ...CASSETTE_REQUEST_SLOTS,
].flatMap((slot) => [slot, `{{${slot}}}`]);
const ROUTE_MISSING_PUBLIC_BODY = {
  error: {
    code: "route_not_found",
    message: "public route was not found",
    retryable: false,
  },
} as const;
const RESOURCE_NOT_FOUND_PUBLIC_BODY = {
  error: {
    code: "not_found",
    message: "resource was not found",
    retryable: false,
  },
} as const;
const execFile = promisify(execFileCallback);
const STARTUP_OUTPUT_LIMIT = 128 * 1024;
const STARTUP_EVIDENCE_ROOT = join(REPO_ROOT, "target", "test-recordings", "quarantine", "session-reconnect-exact-main-readiness-gap");

const SCENARIOS = {
  keyboard: "keyboard-session",
  reconnect: "reconnect-session",
  offline: "offline-session",
  cancel: "cancel-session",
  waitTimeout: "wait-timeout-session",
  unknown: "unknown-outcome-session",
  mobile: "mobile-activity-session",
  safeReconcile: "safe-reconcile-session",
} as const;
const suiteTopologyConsumptions: TopologyConsumption[] = [];
let suiteExpectedSequences: number[] | undefined;
let suiteSawShallow404 = false;

test.describe.configure({ mode: "serial" });
test.setTimeout(120_000);

async function listen(server: Server, port: number): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolvePromise());
  });
}

async function makeCopiedDirectoryTreeRemovable(root: string): Promise<void> {
  await chmod(root, 0o700);
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      await makeCopiedDirectoryTreeRemovable(join(root, entry.name));
    }
  }
}

async function freePort(): Promise<number> {
  const probe = createTcpServer();
  await new Promise<void>((resolvePromise, reject) => {
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const address = probe.address();
  if (address === null || typeof address === "string") {
    throw new Error("test fixture did not receive a TCP port");
  }
  const port = address.port;
  await new Promise<void>((resolvePromise, reject) => probe.close((error) => (error ? reject(error) : resolvePromise())));
  return port;
}

async function closeServer(server: Server, sockets: Set<Socket>): Promise<void> {
  for (const socket of sockets) socket.destroy();
  if (!server.listening) return;
  await new Promise<void>((resolvePromise, reject) => {
    server.close((error) => (error ? reject(error) : resolvePromise()));
  });
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function markerBytes(marker: SecretMarker): Buffer {
  return Buffer.isBuffer(marker) ? marker : Buffer.from(marker, "utf8");
}

function containsMarker(bytes: Buffer, marker: SecretMarker): boolean {
  const candidate = markerBytes(marker);
  return candidate.length > 0 && bytes.includes(candidate);
}

async function filesUnder(root: string): Promise<string[]> {
  try {
    const entries = await readdir(root, { withFileTypes: true });
    const files: string[] = [];
    for (const entry of entries) {
      const path = join(root, entry.name);
      if (entry.isDirectory()) files.push(...(await filesUnder(path)));
      else files.push(path);
    }
    return files;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

function quoteSqliteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function quoteSqliteString(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

async function sqliteJson(database: string, sql: string): Promise<Json[]> {
  const binary = process.env.ZODE_E2E_SQLITE3_BIN ?? "sqlite3";
  let result;
  try {
    result = await execFile(binary, ["-readonly", "-json", database, sql], {
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    // A stopped WAL owner may leave a read-only sqlite3 CLI unable to create
    // its shared-memory sidecar.  Immutable mode is sufficient for the
    // schema/database-list inspection; the caller still scans every sidecar
    // byte-for-byte and therefore does not hide a session mirror.
    result = await execFile(binary, ["-readonly", "-json", `file:${database}?immutable=1`, sql], {
      maxBuffer: 16 * 1024 * 1024,
    }).catch(() => {
      throw error;
    });
  }
  const text = result.stdout.trim();
  if (text.length === 0) return [];
  const value = JSON.parse(text) as unknown;
  if (!Array.isArray(value)) throw new Error("sqlite3 JSON inspection returned a non-array result");
  return value as Json[];
}

async function inspectSqliteDatabase(database: string): Promise<{ storeFiles: string[]; inspection: string }> {
  const databaseList = await sqliteJson(database, "PRAGMA database_list;");
  const storeFiles = new Set<string>([database]);
  const schemas: Json[] = [];
  const columns: Json[] = [];
  for (const entry of databaseList) {
    const databaseName = String(entry.name ?? "");
    const databasePath = String(entry.file ?? "");
    if (databasePath.length > 0) {
      storeFiles.add(databasePath);
      for (const suffix of ["-wal", "-shm", "-journal"]) storeFiles.add(`${databasePath}${suffix}`);
    }
    const schemaName = quoteSqliteIdentifier(databaseName);
    const schemaRows = await sqliteJson(
      database,
      `SELECT type, name, tbl_name, sql FROM ${schemaName}.sqlite_schema ORDER BY type, name;`,
    );
    schemas.push(...schemaRows.map((row) => ({ database: databaseName, ...row })));
    for (const row of schemaRows.filter((candidate) => candidate.type === "table" && typeof candidate.name === "string")) {
      const tableName = String(row.name);
      const tableColumns = await sqliteJson(
        database,
        `PRAGMA ${schemaName}.table_info(${quoteSqliteString(tableName)});`,
      );
      columns.push(
        ...tableColumns.map((column) => ({ database: databaseName, table: tableName, ...column })),
      );
    }
  }
  return {
    storeFiles: [...storeFiles],
    inspection: canonicalJson({
      database_list: databaseList.map(({ seq, name }) => ({ seq, name })),
      sqlite_schema: schemas,
      columns,
    }),
  };
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value as Json)
        .sort()
        .map((key) => [key, canonicalize((value as Json)[key])]),
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function cassetteDigest(cassette: Cassette): string {
  const withoutDigest = structuredClone(cassette) as Json;
  delete withoutDigest.whole_digest;
  return `sha256:${sha256(JSON.stringify(withoutDigest))}`;
}

async function withTimeout<T>(promise: Promise<T>, milliseconds: number, message: string): Promise<T> {
  const signal = AbortSignal.timeout(milliseconds);
  const timeout = new Promise<never>((_, reject) => {
    signal.addEventListener("abort", () => reject(new Error(message)), { once: true });
  });
  return Promise.race([promise, timeout]);
}

async function apiJson(
  baseUrl: string,
  accessAssertion: string,
  path: string,
  init: RequestInit = {},
): Promise<BrowserPublicResponse> {
  const headers = new Headers(init.headers);
  headers.set("Cf-Access-Jwt-Assertion", accessAssertion);
  headers.set("Origin", baseUrl);
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers,
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  let body: Json | null = null;
  try {
    body = JSON.parse(text) as Json;
  } catch {
    body = null;
  }
  return {
    status: response.status,
    body,
    bodyText: text,
    contentType: response.headers.get("content-type") ?? "",
  };
}

async function retainFailureEvidence(label: string, value: Json): Promise<string | undefined> {
  try {
    await mkdir(STARTUP_EVIDENCE_ROOT, { recursive: true, mode: 0o700 });
    await chmod(STARTUP_EVIDENCE_ROOT, 0o700);
    const path = join(STARTUP_EVIDENCE_ROOT, `${label}-${Date.now()}-${randomUUID()}.json`);
    await writeFile(path, JSON.stringify(value), { mode: 0o600 });
    await chmod(path, 0o600);
    return path;
  } catch {
    return undefined;
  }
}

class NonEvidenceShallow404 extends Error {
  readonly nonEvidence = true;

  constructor(label: string) {
    suiteSawShallow404 = true;
    super(`NON_EVIDENCE_SHALLOW_404: ${label} returned 404 before the product barrier`);
    this.name = "NonEvidenceShallow404";
  }
}

function isExactRouteMissingPublicBody(body: Json | null): boolean {
  return body !== null && canonicalJson(body) === canonicalJson(ROUTE_MISSING_PUBLIC_BODY);
}

function requireBody(response: { status: number; body: Json | null }, expectedStatus: number, label: string): Json {
  if (response.status === 404) {
    if (!isExactRouteMissingPublicBody(response.body)) {
      throw new Error(`${label} returned 404 without the exact public route-missing body/code`);
    }
    throw new NonEvidenceShallow404(label);
  }
  if (response.status !== expectedStatus || response.body === null) {
    throw new Error(`${label} failed at the public Server boundary with status ${response.status}`);
  }
  return response.body;
}

async function classifyBrowser404(
  response: { status(): number; text(): Promise<string> } | null,
  label: string,
): Promise<void> {
  if (response?.status() !== 404) return;
  const text = await response.text();
  let body: Json | null = null;
  try {
    body = JSON.parse(text) as Json;
  } catch {
    body = null;
  }
  if (!isExactRouteMissingPublicBody(body)) {
    throw new Error(`${label} returned 404 without the exact public route-missing body/code`);
  }
  throw new NonEvidenceShallow404(label);
}

async function startAccessFixture(): Promise<AccessFixture> {
  return AccessFixture.start();
}

class AccessFixture {
  private constructor(
    private readonly server: Server,
    private readonly sockets: Set<Socket>,
    private readonly privateKey: KeyObject,
    readonly baseUrl: string,
    readonly issuer: string,
  ) {}

  static async start(): Promise<AccessFixture> {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const exported = publicKey.export({ format: "jwk" }) as Json;
    exported.kid = "web-session-reconnect-runtime-states-key";
    exported.use = "sig";
    exported.alg = "RS256";
    const sockets = new Set<Socket>();
    const server = createServer((request, response) => {
      if (request.url === "/jwks" && request.method === "GET") {
        response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        response.end(JSON.stringify({ keys: [exported] }));
        return;
      }
      response.writeHead(404);
      response.end();
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    const port = await freePort();
    await listen(server, port);
    const baseUrl = `http://127.0.0.1:${port}`;
    return new AccessFixture(server, sockets, privateKey, baseUrl, `${baseUrl}/`);
  }

  token(): string {
    const header = { alg: "RS256", typ: "JWT", kid: "web-session-reconnect-runtime-states-key" };
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: this.issuer,
      aud: [ACCESS_AUDIENCE],
      sub: ACCESS_SUBJECT,
      type: "app",
      iat: now,
      exp: now + 3600,
    };
    const encode = (value: Json): string => Buffer.from(JSON.stringify(value)).toString("base64url");
    const signingInput = `${encode(header)}.${encode(claims)}`;
    const signer = createSign("RSA-SHA256");
    signer.update(signingInput);
    return `${signingInput}.${signer.sign(this.privateKey).toString("base64url")}`;
  }

  async close(): Promise<void> {
    await closeServer(this.server, this.sockets);
  }
}

class ReplayProvider {
  private constructor(
    private readonly server: Server,
    private readonly sockets: Set<Socket>,
    private readonly cassette: Cassette,
    readonly topologyId: string,
    readonly baseUrl: string,
    private readonly mode: "cassette" | "safe-reconcile",
  ) {}

  private readonly calls = new Map<string, number>();
  private readonly consumedSequences: number[] = [];
  private readonly countsBySequence = new Map<number, number>();
  private readonly waiters = new Map<string, Array<{ count: number; resolve: () => void }>>();
  private readonly released = new Set<string>();
  private readonly releaseWaiters = new Map<string, Array<() => void>>();
  private readonly expectedScenarioCounts = new Map<string, number>();
  private readonly toolPreambleScenarios = new Set<string>();
  private readonly heldFirstChunks = new Set<string>();
  private readonly observedRequests: string[] = [];
  private expectedProviderAuthorization = "";
  private suiteConsumptionRecorded = false;

  static async start(
    cassette: Cassette,
    topologyId: string,
    mode: "cassette" | "safe-reconcile" = "cassette",
  ): Promise<ReplayProvider> {
    if (cassette.schema !== "zode.llm-http-recording.v1" || cassette.version !== 1) {
      throw new Error("session lifecycle cassette schema is not supported");
    }
    if (
      cassette.replay_contract?.require_all_exchanges_consumed !== true ||
      cassette.replay_contract?.request?.body !== "exact-canonical-json" ||
      cassette.replay_contract?.request?.fingerprint !== "sha256:canonical-json" ||
      cassette.replay_contract?.response?.body !== "exact-recorded-chunks" ||
      cassette.replay_contract?.response?.fingerprint !== "sha256:canonical-json"
    ) {
      throw new Error("session lifecycle cassette replay contract changed");
    }
    if (
      canonicalJson(cassette.secret_slots) !== canonicalJson(CASSETTE_SECRET_SLOTS) ||
      canonicalJson(cassette.synthetic_request_slots) !== canonicalJson(CASSETTE_REQUEST_SLOTS)
    ) {
      throw new Error("session lifecycle cassette secret-slot boundary changed");
    }
    if (cassette.whole_digest !== cassetteDigest(cassette)) {
      throw new Error("session lifecycle cassette whole digest does not match its contents");
    }
    const sequences = cassette.exchanges.map((exchange) => exchange.sequence).sort((left, right) => left - right);
    if (sequences.some((sequence, index) => sequence !== index)) {
      throw new Error("session lifecycle cassette exchange sequences are not contiguous");
    }
    if (mode === "cassette") {
      if (suiteExpectedSequences === undefined) suiteExpectedSequences = sequences;
      else if (canonicalJson(suiteExpectedSequences) !== canonicalJson(sequences)) {
        throw new Error("session lifecycle cassette sequence plan changed between topologies");
      }
    }
    if (
      cassette.first_seen_failure?.exchange_sequence !== 1 ||
      cassette.first_seen_failure?.termination !== "client_disconnect" ||
      cassette.first_seen_failure?.safe_error !== "model stream disconnected after provisional token" ||
      cassette.contract_response?.admission_status !== 202 ||
      cassette.contract_response?.durable_final_assistant_count !== 1 ||
      cassette.contract_response?.reconnect_header !== "Last-Event-ID"
    ) {
      throw new Error("session lifecycle cassette first-occurrence contract changed");
    }
    const sockets = new Set<Socket>();
    let provider!: ReplayProvider;
    const server = createServer((request, response) => {
      void provider.handle(request, response);
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    const port = await freePort();
    await listen(server, port);
    provider = new ReplayProvider(
      server,
      sockets,
      cassette,
      topologyId,
      `http://127.0.0.1:${port}`,
      mode,
    );
    return provider;
  }

  private scenarioFor(body: string): string {
    for (const scenario of Object.values(SCENARIOS)) {
      if (body.includes(scenario)) return scenario;
    }
    throw new Error("provider replay received a request without a named E2E scenario");
  }

  private exchangeFor(scenario: string, occurrence: number): Json {
    const exchange = this.cassette.exchanges.filter((candidate) => candidate.scenario === scenario)[occurrence];
    if (exchange === undefined) {
      throw new Error(`provider replay exhausted scenario ${scenario} at occurrence ${occurrence}`);
    }
    return exchange;
  }

  setExpectedProviderAuthorization(authorization: string): void {
    this.expectedProviderAuthorization = authorization;
  }

  setExpectedScenario(scenario: string, expectedCount: number): void {
    this.expectedScenarioCounts.set(scenario, expectedCount);
  }

  enableToolPreamble(scenario: string): void {
    this.toolPreambleScenarios.add(scenario);
  }

  holdAfterFirstChunk(scenario: string, occurrence = 0): void {
    this.heldFirstChunks.add(`${scenario}:${occurrence}`);
  }

  private expectedSequences(): number[] {
    if (this.mode === "safe-reconcile") return [];
    return this.cassette.exchanges
      .filter((exchange) => this.expectedScenarioCounts.has(exchange.scenario))
      .map((exchange) => exchange.sequence);
  }

  private assertRequestHeaders(request: IncomingMessage, exchange: Json): void {
    const expected = (exchange.request.headers as Json[] | undefined)?.map(
      (header) => [String(header.name).toLowerCase(), String(header.value)] as [string, string],
    );
    if (expected === undefined || expected.length === 0) {
      throw new Error(`cassette exchange ${exchange.sequence} has no exact request header contract`);
    }
    const expectedHeaders = new Map(expected);
    const ignoredTransportHeaders = new Set([
      "host",
      "user-agent",
      "content-length",
      "transfer-encoding",
      "connection",
      "accept-encoding",
    ]);
    const actualHeaders = Object.entries(request.headers)
      .filter(([name]) => !ignoredTransportHeaders.has(name))
      .map(([name, value]) => [name.toLowerCase(), Array.isArray(value) ? value.join(",") : value ?? ""] as const)
      .sort(([left], [right]) => left.localeCompare(right));
    const resolvedExpected = expected
      .map(([name, value]) => [
        name,
        value === "{{SLOT_PROVIDER_AUTHORIZATION}}" ? this.expectedProviderAuthorization : value,
      ] as const)
      .sort(([left], [right]) => left.localeCompare(right));
    if (canonicalJson(actualHeaders) !== canonicalJson(resolvedExpected)) {
      throw new Error(`cassette exchange ${exchange.sequence} request headers did not match exactly`);
    }
    if (expectedHeaders.has("authorization") && this.expectedProviderAuthorization.length === 0) {
      throw new Error("provider authorization slot was not bound before replay");
    }
  }

  private assertRequestBody(body: string, exchange: Json): void {
    const matcher = exchange.request.body_match?.contains;
    if (typeof matcher !== "string" || !body.includes(matcher)) {
      throw new Error(`cassette exchange ${exchange.sequence} request body did not match its scenario marker`);
    }
    let parsed: Json;
    try {
      parsed = JSON.parse(body) as Json;
    } catch {
      throw new Error(`cassette exchange ${exchange.sequence} request body was not JSON`);
    }
    const expected = { ...this.cassette.request_body_contract, messages: exchange.request.messages };
    const actualFingerprint = `sha256:${sha256(canonicalJson(parsed))}`;
    if (exchange.request.canonical_body_fingerprint !== actualFingerprint) {
      throw new Error(`cassette exchange ${exchange.sequence} body fingerprint is internally inconsistent`);
    }
    if (canonicalJson(parsed) !== canonicalJson(expected)) {
      throw new Error(`cassette exchange ${exchange.sequence} request body did not match exactly`);
    }
  }

  private assertResponseContract(exchange: Json): void {
    const replay = exchange.response as Json;
    const responseHeaders = (replay.headers as Json[] | undefined)?.map(
      (header) => [String(header.name).toLowerCase(), String(header.value)] as [string, string],
    );
    if (
      responseHeaders === undefined ||
      responseHeaders.length === 0 ||
      responseHeaders.find(([name]) => name === "content-type")?.[1] !== replay.content_type
    ) {
      throw new Error(`cassette exchange ${exchange.sequence} has no exact response header contract`);
    }
    const responseFingerprint = `sha256:${sha256(
      canonicalJson({
        status: replay.status,
        content_type: replay.content_type,
        headers: replay.headers,
        complete: replay.complete,
        stream_error: replay.stream_error,
        chunks: replay.chunks,
      }),
    )}`;
    if (replay.canonical_response_fingerprint !== responseFingerprint) {
      throw new Error(`cassette exchange ${exchange.sequence} response fingerprint is internally inconsistent`);
    }
    const responseBody = Buffer.concat((replay.chunks as Json[]).map((chunk) => Buffer.from(chunk.bytes_hex, "hex")));
    if (replay.body_sha256 !== `sha256:${sha256(responseBody)}`) {
      throw new Error(`cassette exchange ${exchange.sequence} response body fingerprint is internally inconsistent`);
    }
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const observedIndex = this.observedRequests.push(`${request.method ?? ""} ${request.url ?? ""}`) - 1;
    if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
      response.writeHead(404);
      response.end();
      return;
    }
    const body = await readBody(request);
    this.observedRequests[observedIndex] += ` body=${body.slice(0, 1_000)}`;
    const scenario = this.scenarioFor(body);
    const occurrence = this.calls.get(scenario) ?? 0;
    if (this.mode === "safe-reconcile") {
      this.handleSafeReconcile(request, response, body, scenario, occurrence, observedIndex);
      return;
    }
    const exchange = this.exchangeFor(scenario, occurrence);
    if (exchange.request.method !== request.method || exchange.request.path !== request.url) {
      response.writeHead(500);
      response.end("fixture request method or path did not match the cassette");
      return;
    }
    try {
      this.assertRequestHeaders(request, exchange);
      this.assertRequestBody(body, exchange);
      this.assertResponseContract(exchange);
    } catch (error) {
      this.observedRequests[observedIndex] += ` error=${error instanceof Error ? error.message : String(error)}`;
      response.writeHead(500);
      response.end(error instanceof Error ? error.message : "fixture cassette contract mismatch");
      return;
    }
    const expectedSequence = this.expectedSequences()[this.consumedSequences.length];
    if (exchange.sequence !== expectedSequence) {
      response.writeHead(500);
      response.end("fixture exchange order did not match the cassette");
      return;
    }
    const sequenceCount = this.countsBySequence.get(exchange.sequence) ?? 0;
    if (sequenceCount !== 0) {
      response.writeHead(500);
      response.end(`fixture exchange ${exchange.sequence} was consumed more than once`);
      return;
    }
    this.calls.set(scenario, occurrence + 1);
    this.consumedSequences.push(exchange.sequence);
    this.countsBySequence.set(exchange.sequence, sequenceCount + 1);
    this.notify(scenario, occurrence + 1);
    if (scenario === SCENARIOS.reconnect && occurrence === 1) {
      await this.waitForRelease("reconnect-final");
    }
    const replay = exchange.response as Json;
    const responseHeaders = Object.fromEntries(
      (replay.headers as Json[]).map(
        (header) => [String(header.name).toLowerCase(), String(header.value)] as [string, string],
      ),
    );
    response.writeHead(replay.status, responseHeaders);
    if (this.toolPreambleScenarios.has(scenario) && occurrence === 0) {
      response.write(
        `data: ${JSON.stringify({ choices: [{ delta: { content: "PRE_TOOL" }, finish_reason: null }] })}\n\n`,
      );
    }
    for (const [index, chunk] of (replay.chunks as Json[]).entries()) {
      const bytes = Buffer.from(chunk.bytes_hex, "hex");
      const heldChunk = `${scenario}:${occurrence}`;
      if (index === 0 && this.heldFirstChunks.has(heldChunk)) {
        const holdName = occurrence === 0
          ? `${scenario}:first-chunk`
          : `${scenario}:first-chunk-${occurrence + 1}`;
        await new Promise<void>((resolvePromise, reject) => {
          response.write(bytes, (error) => error ? reject(error) : resolvePromise());
        });
        this.notify(holdName, 1);
        await this.waitForRelease(holdName);
      } else {
        response.write(bytes);
      }
    }
    if (replay.complete === true) {
      response.end();
    } else {
      // Let the intentionally incomplete frame cross the real socket before
      // closing it.  A synchronous destroy can discard a buffered provisional
      // chunk and turn a transport fixture into a false product red.
      await new Promise<void>((resolvePromise) => setImmediate(resolvePromise));
      response.destroy();
    }
  }

  private handleSafeReconcile(
    request: IncomingMessage,
    response: ServerResponse,
    body: string,
    scenario: string,
    occurrence: number,
    observedIndex: number,
  ): void {
    try {
      if (scenario !== SCENARIOS.safeReconcile || occurrence > 1) {
        throw new Error(`unexpected safe reconcile provider occurrence ${scenario}:${occurrence}`);
      }
      if (request.headers.authorization !== this.expectedProviderAuthorization) {
        throw new Error("safe reconcile provider authorization did not match the synthetic profile");
      }
      const payload = JSON.parse(body) as Json;
      const messages = payload.messages as Json[] | undefined;
      if (
        payload.model !== MODEL ||
        payload.stream !== true ||
        !Array.isArray(messages) ||
        messages[0]?.role !== "user" ||
        messages[0]?.content !== `safe reconcile path ${SCENARIOS.safeReconcile}`
      ) {
        throw new Error("safe reconcile provider request did not use the expected public session context");
      }
      if (occurrence === 0 && messages.length !== 1) {
        throw new Error("safe reconcile first provider round contained unexpected history");
      }
      if (occurrence === 1) {
        const assistant = messages.find((message) => message.role === "assistant") as Json | undefined;
        const toolMessage = messages.find((message) => message.role === "tool") as Json | undefined;
        const toolCall = (assistant?.tool_calls as Json[] | undefined)?.[0];
        if (
          messages.length !== 3 ||
          toolCall?.id !== "safe-reconcile-tool-call" ||
          toolCall?.function?.name !== TOOL ||
          toolCall?.function?.arguments !== '{"mode":"safe"}' ||
          toolMessage?.tool_call_id !== "safe-reconcile-tool-call" ||
          !String(toolMessage?.content ?? "").includes("SAFE_TOOL_RESULT")
        ) {
          throw new Error("safe reconcile follow-up did not preserve the original tool identity and result");
        }
      }
    } catch (error) {
      this.observedRequests[observedIndex] += ` error=${error instanceof Error ? error.message : String(error)}`;
      response.writeHead(500, { "content-type": "text/plain" });
      response.end(error instanceof Error ? error.message : "safe reconcile provider mismatch");
      return;
    }
    this.calls.set(scenario, occurrence + 1);
    this.notify(scenario, occurrence + 1);
    const delta = occurrence === 0
      ? {
          tool_calls: [
            {
              index: 0,
              id: "safe-reconcile-tool-call",
              type: "function",
              function: { name: TOOL, arguments: '{"mode":"safe"}' },
            },
          ],
        }
      : { content: "SAFE_RECONCILE_FINAL" };
    const finishReason = occurrence === 0 ? "tool_calls" : "stop";
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write(`data: ${JSON.stringify({ choices: [{ delta, finish_reason: null }] })}\n\n`);
    response.write(`data: ${JSON.stringify({ choices: [{ delta: {}, finish_reason: finishReason }] })}\n\n`);
    response.end("data: [DONE]\n\n");
  }

  private notify(scenario: string, count: number): void {
    const waiters = this.waiters.get(scenario) ?? [];
    this.waiters.set(
      scenario,
      waiters.filter((waiter) => {
        if (count >= waiter.count) {
          waiter.resolve();
          return false;
        }
        return true;
      }),
    );
  }

  async waitForScenario(scenario: string, count = 1): Promise<void> {
    if ((this.calls.get(scenario) ?? 0) >= count) return;
    await new Promise<void>((resolvePromise) => {
      const waiters = this.waiters.get(scenario) ?? [];
      waiters.push({ count, resolve: resolvePromise });
      this.waiters.set(scenario, waiters);
    });
  }

  release(name: string): void {
    this.released.add(name);
    for (const resolvePromise of this.releaseWaiters.get(name) ?? []) resolvePromise();
    this.releaseWaiters.delete(name);
  }

  private async waitForRelease(name: string): Promise<void> {
    if (this.released.has(name)) return;
    await new Promise<void>((resolvePromise) => {
      const waiters = this.releaseWaiters.get(name) ?? [];
      waiters.push(resolvePromise);
      this.releaseWaiters.set(name, waiters);
    });
  }

  count(scenario: string): number {
    return this.calls.get(scenario) ?? 0;
  }

  debugRequests(): string[] {
    return [...this.observedRequests];
  }

  assertAllExchangesConsumed(): void {
    if (this.mode === "safe-reconcile") {
      for (const [scenario, expectedCount] of this.expectedScenarioCounts) {
        const actualCount = this.calls.get(scenario) ?? 0;
        if (actualCount !== expectedCount) {
          throw new Error(`safe reconcile provider scenario ${scenario} consumed ${actualCount}/${expectedCount}`);
        }
      }
      return;
    }
    const expected = this.expectedSequences();
    const consumed = [...this.consumedSequences];
    if (canonicalJson(consumed) !== canonicalJson(expected)) {
      throw new Error(`provider cassette consumed ${consumed.length}/${expected.length} exchanges`);
    }
    for (const sequence of expected) {
      if ((this.countsBySequence.get(sequence) ?? 0) !== 1) {
        throw new Error(`provider cassette exchange ${sequence} was not consumed exactly once`);
      }
    }
    if (this.suiteConsumptionRecorded) return;
    this.suiteConsumptionRecorded = true;
    suiteTopologyConsumptions.push({
      topologyId: this.topologyId,
      expectedSequences: [...expected],
      consumedSequences: [...consumed],
      countsBySequence: new Map(this.countsBySequence),
    });
  }

  scenarioCounts(): Map<string, number> {
    if (this.mode === "safe-reconcile") return new Map([[SCENARIOS.safeReconcile, 2]]);
    const counts = new Map<string, number>();
    for (const exchange of this.cassette.exchanges) {
      counts.set(exchange.scenario, (counts.get(exchange.scenario) ?? 0) + 1);
    }
    return counts;
  }

  async close(): Promise<void> {
    await closeServer(this.server, this.sockets);
  }
}

class EndpointBoundary {
  private constructor(
    private readonly server: Server,
    private readonly sockets: Set<Socket>,
    private readonly targetBaseUrl: string,
    readonly baseUrl: string,
  ) {}

  private readonly requests: EndpointBoundaryRequest[] = [];
  private readonly waiters: Array<{
    predicate: (request: EndpointBoundaryRequest) => boolean;
    resolve: (request: EndpointBoundaryRequest) => void;
  }> = [];
  private readonly eventIdWaiters: Array<{
    request: EndpointBoundaryRequest;
    resolve: (eventIds: string[]) => void;
  }> = [];
  private nextEventBodyHold:
    | {
        received: (request: EndpointBoundaryRequest) => void;
        released: Promise<void>;
        release: () => void;
      }
    | undefined;
  static async start(targetBaseUrl: string): Promise<EndpointBoundary> {
    // This is a transparent real HTTP boundary: Server is configured with this
    // origin, every request is forwarded to the spawned Endpoint, and no
    // product response or route is synthesized here.
    const sockets = new Set<Socket>();
    let boundary!: EndpointBoundary;
    const server = createServer((request, response) => {
      void boundary.forward(request, response);
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    const port = await freePort();
    await listen(server, port);
    boundary = new EndpointBoundary(server, sockets, targetBaseUrl, `http://127.0.0.1:${port}`);
    return boundary;
  }

  private record(request: EndpointBoundaryRequest): void {
    if (request.recorded === true) return;
    request.recorded = true;
    this.requests.push(request);
    for (let index = this.waiters.length - 1; index >= 0; index -= 1) {
      const waiter = this.waiters[index];
      if (!waiter.predicate(request)) continue;
      this.waiters.splice(index, 1);
      waiter.resolve(request);
    }
  }

  private recordSseLine(request: EndpointBoundaryRequest, line: string): void {
    if (line.length === 0) {
      if (request.responseCurrentEventName) {
        request.responseFrames.push({
          id: request.responseCurrentEventId ?? "",
          name: request.responseCurrentEventName,
          sessionId: request.responseCurrentSessionId,
          messageId: request.responseCurrentMessageId,
        });
      }
      if (request.responseCurrentEventId && request.responseCurrentEventName) {
        request.responseDurableEvents.push({
          id: request.responseCurrentEventId,
          name: request.responseCurrentEventName,
        });
      }
      request.responseCurrentEventId = undefined;
      request.responseCurrentEventName = undefined;
      request.responseCurrentSessionId = undefined;
      request.responseCurrentMessageId = undefined;
      return;
    }
    if (line.startsWith("event:")) {
      const value = line.startsWith("event: ") ? line.slice(7) : line.slice(6);
      request.responseCurrentEventName = value;
      if (value.length > 0 && !request.responseEventNames.includes(value)) {
        request.responseEventNames.push(value);
      }
    }
    if (line.startsWith("data:")) {
      const value = line.startsWith("data: ") ? line.slice(6) : line.slice(5);
      try {
        const data = JSON.parse(value) as Json;
        if (typeof data.session_id === "string") request.responseCurrentSessionId = data.session_id;
        if (typeof data.data?.message?.message_id === "string") {
          request.responseCurrentMessageId = data.data.message.message_id;
        }
      } catch {
        // Keep the boundary transparent. Non-JSON data is still forwarded and
        // simply cannot provide the typed correlation used by this assertion.
      }
    }
    if (!line.startsWith("id:")) return;
    const value = line.startsWith("id: ") ? line.slice(4) : line.slice(3);
    if (value.length === 0) return;
    request.responseCurrentEventId = value;
    request.responseEventIds.push(value);
    for (let index = this.eventIdWaiters.length - 1; index >= 0; index -= 1) {
      const waiter = this.eventIdWaiters[index];
      if (waiter.request !== request) continue;
      this.eventIdWaiters.splice(index, 1);
      waiter.resolve([...request.responseEventIds]);
    }
  }

  private observeSseChunk(request: EndpointBoundaryRequest, chunk: Buffer): void {
    const text = `${request.responseSseRemainder ?? ""}${chunk.toString("utf8")}`;
    const lines = text.split(/\r\n|\n|\r/);
    request.responseSseRemainder = lines.pop() ?? "";
    for (const line of lines) this.recordSseLine(request, line);
  }

  private finishSseResponse(request: EndpointBoundaryRequest): void {
    if (request.responseComplete === true) return;
    if (request.responseSseRemainder !== undefined) {
      this.recordSseLine(request, request.responseSseRemainder);
      request.responseSseRemainder = "";
    }
    this.recordSseLine(request, "");
    request.responseComplete = true;
  }

  private async forward(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const body = await readBody(request);
    const lastEventId = request.headers["last-event-id"] ?? "";
    const normalizedLastEventId = Array.isArray(lastEventId) ? lastEventId.join(",") : lastEventId;
    const requestId = request.headers[REQUEST_ID_HEADER] ?? "";
    const normalizedRequestId = Array.isArray(requestId) ? requestId.join(",") : requestId;
    const target = new URL(request.url ?? "/", this.targetBaseUrl);
    const forwardedHeaders: Record<string, string | string[] | undefined> = { ...request.headers };
    delete forwardedHeaders.host;
    delete forwardedHeaders.connection;
    delete forwardedHeaders["content-length"];
    delete forwardedHeaders["transfer-encoding"];
    forwardedHeaders.host = target.host;
    if (body.length > 0) forwardedHeaders["content-length"] = String(Buffer.byteLength(body));
    const forwardedHeader = forwardedHeaders["last-event-id"] ?? "";
    const normalizedForwardedHeader = Array.isArray(forwardedHeader)
      ? forwardedHeader.join(",")
      : forwardedHeader;
    const forwardedRequestId = forwardedHeaders[REQUEST_ID_HEADER] ?? "";
    const normalizedForwardedRequestId = Array.isArray(forwardedRequestId)
      ? forwardedRequestId.join(",")
      : forwardedRequestId;
    const captured: EndpointBoundaryRequest = {
      method: request.method ?? "",
      path: target.pathname,
      requestId: normalizedRequestId,
      forwardedRequestId: normalizedForwardedRequestId,
      lastEventId: normalizedLastEventId,
      forwardedLastEventId: normalizedForwardedHeader,
      body,
      responseEventIds: [],
      responseEventNames: [],
      responseDurableEvents: [],
      responseFrames: [],
    };
    const upstream = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: request.method,
        headers: forwardedHeaders,
      },
      (upstreamResponse) => {
        captured.status = upstreamResponse.statusCode;
        captured.responseContentType = Array.isArray(upstreamResponse.headers["content-type"])
          ? upstreamResponse.headers["content-type"].join(",")
          : String(upstreamResponse.headers["content-type"] ?? "");
        const eventBodyHold =
          upstreamResponse.statusCode === 200 && captured.path.endsWith("/events")
            ? this.nextEventBodyHold
            : undefined;
        if (eventBodyHold !== undefined) this.nextEventBodyHold = undefined;
        if (upstreamResponse.statusCode === 404) {
          const chunks: Buffer[] = [];
          upstreamResponse.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
          upstreamResponse.once("end", () => {
            captured.responseBody = Buffer.concat(chunks).toString("utf8");
            captured.responseComplete = true;
            this.record(captured);
          });
        } else {
          if (upstreamResponse.statusCode === 200 && captured.path.endsWith("/events")) {
            upstreamResponse.on("data", (chunk) => this.observeSseChunk(captured, Buffer.from(chunk)));
            upstreamResponse.once("end", () => this.finishSseResponse(captured));
            upstreamResponse.once("close", () => this.finishSseResponse(captured));
          }
          this.record(captured);
        }
        const responseHeaders: Record<string, string | string[] | undefined> = { ...upstreamResponse.headers };
        delete responseHeaders.connection;
        delete responseHeaders["keep-alive"];
        delete responseHeaders["transfer-encoding"];
        response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
        if (eventBodyHold === undefined) {
          upstreamResponse.pipe(response);
        } else {
          upstreamResponse.pause();
          response.flushHeaders();
          eventBodyHold.received(captured);
          void eventBodyHold.released.then(() => {
            if (response.destroyed) {
              upstreamResponse.destroy();
              return;
            }
            upstreamResponse.pipe(response);
            upstreamResponse.resume();
          });
        }
      },
    );
    const wireRequestId = upstream.getHeader(REQUEST_ID_HEADER);
    captured.forwardedRequestId = Array.isArray(wireRequestId)
      ? wireRequestId.join(",")
      : String(wireRequestId ?? "");
    const wireLastEventId = upstream.getHeader("last-event-id");
    captured.forwardedLastEventId = Array.isArray(wireLastEventId)
      ? wireLastEventId.join(",")
      : String(wireLastEventId ?? "");
    upstream.once("error", () => {
      captured.status = 502;
      this.finishSseResponse(captured);
      this.record(captured);
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { code: "endpoint_unavailable" } }));
      } else {
        response.destroy();
      }
    });
    upstream.end(body);
  }

  holdNextEventBody(): EndpointEventBodyHold {
    if (this.nextEventBodyHold !== undefined) {
      throw new Error("Endpoint event body hold is already armed");
    }
    let markReceived!: (request: EndpointBoundaryRequest) => void;
    let releasePromise!: () => void;
    let released = false;
    const received = new Promise<EndpointBoundaryRequest>((resolvePromise) => {
      markReceived = resolvePromise;
    });
    const releaseGate = new Promise<void>((resolvePromise) => {
      releasePromise = resolvePromise;
    });
    const pending = {
      received: markReceived,
      released: releaseGate,
      release: () => {
        if (released) return;
        released = true;
        releasePromise();
      },
    };
    this.nextEventBodyHold = pending;
    return {
      received,
      release: pending.release,
      dispose: () => {
        if (this.nextEventBodyHold === pending) this.nextEventBodyHold = undefined;
        pending.release();
      },
    };
  }

  async waitForEventRequest(
    browserRequest: BrowserSseRequest,
    options: { allowNon2xx?: boolean } = {},
  ): Promise<EndpointBoundaryRequest> {
    if (browserRequest.endpointRequest !== undefined) return browserRequest.endpointRequest;
    const { lastEventId, requestId } = browserRequest;
    const path = "/v1/events";
    const matches = (request: EndpointBoundaryRequest): boolean =>
      request.method === "GET" &&
      request.path === path &&
      request.lastEventId === lastEventId &&
      request.forwardedLastEventId === lastEventId &&
      request.matchedBrowserRequest === undefined &&
      (requestId.length === 0 || request.requestId.length === 0
        ? true
        : request.requestId === requestId && request.forwardedRequestId === requestId);
    const existing =
      (options.allowNon2xx === true
        ? this.requests.find((request) => matches(request) && request.status === 200)
        : undefined) ?? this.requests.find(matches);
    if (existing !== undefined) {
      existing.matchedBrowserRequest = browserRequest;
      browserRequest.endpointRequest = existing;
      if (options.allowNon2xx !== true) this.assertEventResponse(existing);
      return existing;
    }
    const request = await withTimeout(
      new Promise<EndpointBoundaryRequest>((resolvePromise) => {
        this.waiters.push({
          predicate: matches,
          resolve: (matched) => {
            matched.matchedBrowserRequest = browserRequest;
            browserRequest.endpointRequest = matched;
            resolvePromise(matched);
          },
        });
      }),
      15_000,
      `Endpoint boundary did not receive Last-Event-ID ${lastEventId || "<empty>"}; events=${JSON.stringify(this.eventRequests().map((request) => ({ last_event_id: request.lastEventId, matched: request.matchedBrowserRequest !== undefined, status: request.status, ids: request.responseEventIds })))}`,
    );
    if (options.allowNon2xx !== true) this.assertEventResponse(request);
    return request;
  }

  async waitForResponseEventIds(request: EndpointBoundaryRequest, label: string): Promise<string[]> {
    if (request.responseEventIds.length > 0) return [...request.responseEventIds];
    const waiter: {
      request: EndpointBoundaryRequest;
      resolve: (eventIds: string[]) => void;
    } = {
      request,
      resolve: () => undefined,
    };
    const eventIds = new Promise<string[]>((resolvePromise) => {
      waiter.resolve = resolvePromise;
      this.eventIdWaiters.push(waiter);
    });
    try {
      return await withTimeout(eventIds, 15_000, `${label} did not expose an SSE id field`);
    } finally {
      const index = this.eventIdWaiters.indexOf(waiter);
      if (index >= 0) this.eventIdWaiters.splice(index, 1);
    }
  }

  private assertEventResponse(request: EndpointBoundaryRequest): void {
    if (request.status === 404) {
      let body: Json | null = null;
      try {
        body = JSON.parse(request.responseBody ?? "") as Json;
      } catch {
        body = null;
      }
      if (!isExactRouteMissingPublicBody(body)) {
      throw new Error("Endpoint events returned 404 without the exact public route-missing body/code");
      }
      throw new NonEvidenceShallow404("Endpoint events");
    }
    if (request.status !== 200) {
      throw new Error(`Endpoint events returned status ${request.status ?? "<missing>"}`);
    }
    if (!request.responseContentType?.toLowerCase().includes("text/event-stream")) {
      throw new Error("Endpoint events returned 200 without a text/event-stream content type");
    }
  }

  eventRequests(): EndpointBoundaryRequest[] {
    return this.requests.filter(
      (request) => request.method === "GET" && request.path === "/v1/events",
    );
  }

  debugRequests(): string[] {
    return this.requests.map((request) =>
      `${request.method} ${request.path} status=${request.status ?? "<pending>"} request_id=${request.requestId} forwarded_request_id=${request.forwardedRequestId} last_event_id=${request.lastEventId} forwarded_last_event_id=${request.forwardedLastEventId} matched=${request.matchedBrowserRequest !== undefined} events=${request.responseEventNames.join(",")} ids=${request.responseEventIds.join(",")} body=${request.body.slice(0, 180)}`,
    );
  }

  async close(): Promise<void> {
    await closeServer(this.server, this.sockets);
  }
}

class ToolService {
  private constructor(
    private readonly server: Server,
    private readonly sockets: Set<Socket>,
    readonly baseUrl: string,
    private readonly safeReconcile: boolean,
  ) {}

  private readonly calls = new Map<string, number>();
  private readonly waiters = new Map<string, Array<{ resolve: () => void }>>();
  private readonly requestBodies = new Map<string, string[]>();

  static async start(safeReconcile = false): Promise<ToolService> {
    const sockets = new Set<Socket>();
    let service!: ToolService;
    const server = createServer((request, response) => {
      void service.handle(request, response);
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    const port = await freePort();
    await listen(server, port);
    service = new ToolService(server, sockets, `http://127.0.0.1:${port}`, safeReconcile);
    return service;
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (request.method !== "POST" || request.url !== "/fixture_async") {
      response.writeHead(404);
      response.end();
      return;
    }
    const body = await readBody(request);
    const inputMode = (JSON.parse(body) as Json)?.input?.mode;
    const mode = inputMode === "safe" ? "safe" : inputMode === "unknown" ? "unknown" : "cancel";
    this.calls.set(mode, (this.calls.get(mode) ?? 0) + 1);
    this.requestBodies.set(mode, [...(this.requestBodies.get(mode) ?? []), body]);
    for (const waiter of this.waiters.get(mode) ?? []) waiter.resolve();
    this.waiters.delete(mode);
    response.once("close", () => undefined);
    if (mode === "cancel" || mode === "unknown" || (mode === "safe" && this.safeReconcile && this.calls.get(mode) === 1)) {
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ result: { content: "SAFE_TOOL_RESULT" } }));
  }

  async waitFor(mode: "cancel" | "unknown" | "safe", count = 1): Promise<void> {
    if ((this.calls.get(mode) ?? 0) >= count) return;
    await new Promise<void>((resolvePromise) => {
      const waiters = this.waiters.get(mode) ?? [];
      waiters.push({ resolve: resolvePromise });
      this.waiters.set(mode, waiters);
    });
  }

  bodiesFor(mode: "cancel" | "unknown" | "safe"): string[] {
    return [...(this.requestBodies.get(mode) ?? [])];
  }

  async close(): Promise<void> {
    await closeServer(this.server, this.sockets);
  }
}

class ReadyProcess {
  private constructor(
    private readonly binary: string,
    private readonly args: string[],
    private readonly prefix: string,
    private child: ReadyChild,
    private output: ProcessOutput,
    readonly baseUrl: string,
  ) {}

  static async start(binary: string, args: string[], prefix: string): Promise<ReadyProcess> {
    const child = await ReadyProcess.spawnChild(binary, args, prefix);
    return new ReadyProcess(binary, args, prefix, child.child, child.output, child.baseUrl);
  }

  private static boundedText(chunks: Buffer[], total: { value: number }): string {
    const bytes = Buffer.concat(chunks);
    return bytes.subarray(0, Math.min(total.value, STARTUP_OUTPUT_LIMIT)).toString("utf8");
  }

  private static async spawnChild(
    binary: string,
    args: string[],
    prefix: string,
  ): Promise<{ child: ReadyChild; baseUrl: string; output: ProcessOutput }> {
    const child = spawn(binary, args, {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env },
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    const stdoutTotal = { value: 0 };
    const stderrTotal = { value: 0 };
    const capture = (chunks: Buffer[], total: { value: number }, chunk: Buffer): void => {
      total.value += chunk.length;
      if (total.value <= STARTUP_OUTPUT_LIMIT) chunks.push(Buffer.from(chunk));
    };
    child.stdout.on("data", (chunk: Buffer) => capture(stdoutChunks, stdoutTotal, chunk));
    child.stderr.on("data", (chunk: Buffer) => capture(stderrChunks, stderrTotal, chunk));
    const readiness = new Promise<string>((resolvePromise, reject) => {
      const output = createInterface({ input: child.stdout });
      const finish = (callback: () => void) => {
        output.close();
        child.stdout.resume();
        callback();
      };
      output.on("line", (line) => {
        if (line.startsWith(prefix)) finish(() => resolvePromise(line.slice(prefix.length).trim()));
      });
      child.once("error", (error) => finish(() => reject(error)));
      child.once("exit", (code) => {
        if (code !== null) {
          const stdout = ReadyProcess.boundedText(stdoutChunks, stdoutTotal);
          const stderr = ReadyProcess.boundedText(stderrChunks, stderrTotal);
          finish(() => reject(new Error(
            `real process exited before readiness (${code}); stdout=${JSON.stringify(stdout)}; stderr=${JSON.stringify(stderr)}`,
          )));
        }
      });
    });
    try {
      const baseUrl = await withTimeout(readiness, 15_000, "real process readiness timed out");
      return {
        child,
        baseUrl,
        output: { stdoutChunks, stderrChunks, stdoutTotal, stderrTotal },
      };
    } catch (error) {
      child.kill("SIGKILL");
      throw error;
    }
  }

  async restart(): Promise<void> {
    await this.stop();
    const replacement = await ReadyProcess.spawnChild(this.binary, this.args, this.prefix);
    if (replacement.baseUrl !== this.baseUrl) {
      replacement.child.kill("SIGKILL");
      throw new Error("real process changed its configured URL across restart");
    }
    this.child = replacement.child;
    this.output = replacement.output;
  }

  outputSnapshot(knownSecrets: SecretMarker[] = []): { stdout: string; stderr: string } {
    const redact = (value: string): string => {
      let result = value;
      for (const secret of knownSecrets) {
        const marker = Buffer.isBuffer(secret) ? secret.toString("base64") : secret;
        if (marker.length > 0) result = result.replaceAll(marker, "<redacted>");
      }
      return result;
    };
    return {
      stdout: redact(ReadyProcess.boundedText(this.output.stdoutChunks, this.output.stdoutTotal)),
      stderr: redact(ReadyProcess.boundedText(this.output.stderrChunks, this.output.stderrTotal)),
    };
  }

  async stop(): Promise<void> {
    if (this.child.exitCode !== null) return;
    const processGone = (): boolean => {
      if (this.child.exitCode !== null) return true;
      const pid = this.child.pid;
      if (pid === undefined) return true;
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        // The OS has already reaped the child, but Node may not have delivered
        // its exit event yet because the process was detached during a
        // restart.  Treat that as successfully stopped and avoid a false
        // teardown failure.
        return true;
      }
    };
    const waitForExit = async (timeoutMs: number, message: string): Promise<void> => {
      if (processGone()) return;
      await withTimeout(
        new Promise<void>((resolvePromise) => {
          let poll: ReturnType<typeof setInterval> | undefined;
          const finish = (): void => {
            if (poll !== undefined) clearInterval(poll);
            this.child.off("exit", onExit);
            resolvePromise();
          };
          const onExit = (): void => {
            finish();
          };
          this.child.once("exit", onExit);
          poll = setInterval(() => {
            if (processGone()) finish();
          }, 25);
          if (processGone()) finish();
        }),
        timeoutMs,
        message,
      );
    };
    this.child.kill("SIGTERM");
    try {
      await waitForExit(10_000, "real process did not stop");
    } catch {
      if (this.child.exitCode === null) this.child.kill("SIGKILL");
      await waitForExit(5_000, "real process could not be reaped");
    }
  }
}

class Topology {
  private constructor(
    readonly topologyId: string,
    readonly root: string,
    readonly access: AccessFixture,
    readonly provider: ReplayProvider,
    readonly tools: ToolService,
    readonly endpoint: ReadyProcess,
    readonly endpointBoundary: EndpointBoundary,
    readonly server: ReadyProcess,
    readonly serverDatabase: string,
    readonly endpointSecret: string,
    readonly accessAssertion: string,
    readonly subjectKey: Buffer,
    readonly endpointConfig: string,
    readonly serverConfig: string,
    readonly endpointPort: number,
    readonly serverPort: number,
  ) {
    this.knownSecrets = [endpointSecret, accessAssertion, Buffer.from(subjectKey), ...CASSETTE_SLOT_MARKERS];
  }

  endpointId = "";
  profileId = "";
  descriptorRevision = 0;
  profileRevision = 0;
  private currentSseRequestId = `e2e-sse-${randomUUID()}`;
  private readonly observedMarkers: string[] = [];
  readonly knownSecrets: SecretMarker[];
  private readonly expectedScenarioCounts = new Map<string, number>();

  static async start(topologyId: string, seed = true, safeReconcile = false): Promise<Topology> {
    const cassetteBytes = await readFile(CASSETTE_PATH);
    if (sha256(cassetteBytes) !== CASSETTE_RAW_SHA256) {
      throw new Error("session lifecycle cassette raw bytes changed; retain the original first occurrence");
    }
    const cassette = JSON.parse(cassetteBytes.toString("utf8")) as Cassette;
    const root = await mkdtemp(join(tmpdir(), "zode-web-rs-"));
    const access = await startAccessFixture();
    const provider = await ReplayProvider.start(
      cassette,
      topologyId,
      safeReconcile ? "safe-reconcile" : "cassette",
    );
    const tools = await ToolService.start(safeReconcile);
    const endpointPort = await freePort();
    const serverPort = await freePort();
    const endpointRoot = join(root, "endpoint");
    const serverRoot = join(root, "server");
    await mkdir(join(endpointRoot, "credentials"), { recursive: true });
    await mkdir(join(endpointRoot, "blobs"), { recursive: true });
    await mkdir(join(serverRoot, "secrets"), { recursive: true });
    const uiAssetsDirectory = join(serverRoot, "ui");
    const sourceUiAssetsDirectory = process.env.ZODE_UI_ASSETS_DIRECTORY
      ?? join(REPO_ROOT, "web", "dist");
    await cp(sourceUiAssetsDirectory, uiAssetsDirectory, {
      recursive: true,
      force: false,
      errorOnExist: true,
    });
    await makeCopiedDirectoryTreeRemovable(uiAssetsDirectory);
    const endpointSecret = `synthetic-controller-${randomUUID()}`;
    const providerSecret = `synthetic-provider-${randomUUID()}`;
    provider.setExpectedProviderAuthorization(`Bearer ${providerSecret}`);
    const controllerSecretPath = join(endpointRoot, "controller.secret");
    await writeFile(controllerSecretPath, endpointSecret, { mode: 0o600 });
    await chmod(controllerSecretPath, 0o600);
    const subjectKeyPath = join(serverRoot, "subject.key");
    const subjectKey = randomBytes(32);
    await writeFile(subjectKeyPath, subjectKey, { mode: 0o600 });
    await chmod(subjectKeyPath, 0o600);
    const endpointDatabase = join(endpointRoot, "runtime.sqlite3");
    const endpointConfig = join(endpointRoot, "config.json");
    await writeFile(
      endpointConfig,
      JSON.stringify({
        schema: "zode.config.v1",
        listen: `127.0.0.1:${endpointPort}`,
        runtime_store: { kind: "sqlite", path: endpointDatabase },
        credential_replica_store: { kind: "files", directory: join(endpointRoot, "credentials") },
        blob_store: { kind: "files", directory: join(endpointRoot, "blobs") },
        controller_auth: [
          {
            authority_id: CONTROLLER_AUTHORITY,
            revision: 1,
            kind: "bearer_secret_file",
            secret_file: controllerSecretPath,
          },
        ],
        runtime: {
          tool_foreground_ms: 2_000,
          model_step_max_attempts: 2,
          model_retry_base_ms: 1,
          model_retry_max_ms: 10,
          snapshot_every_events: 1,
        },
        provider_execution: {
          adapter_kinds: ["openai_compatible"],
          allowed_base_url_origins: [new URL(provider.baseUrl).origin],
        },
        tools: [
          {
            name: TOOL,
            description: "Controlled asynchronous HTTP tool for browser lifecycle E2E.",
            input_schema: {
              type: "object",
              properties: { mode: { type: "string" } },
              required: ["mode"],
              additionalProperties: false,
            },
            completion_mode: "response",
            auto_wait_timeout_seconds: 1,
            recovery: {
              on_running_restart: "unknown_outcome",
              retry_dispatch: safeReconcile ? "same_invocation_key_deduplicated" : "never",
            },
            adapter: { kind: "http", url: `${tools.baseUrl}/fixture_async` },
          },
        ],
      }),
      { mode: 0o600 },
    );
    const serverDatabase = join(serverRoot, "control.sqlite3");
    const serverConfig = join(serverRoot, "config.json");
    await writeFile(
      serverConfig,
      JSON.stringify({
        schema: "zode.server-config.v1",
        listen: `127.0.0.1:${serverPort}`,
        management_origin: `http://127.0.0.1:${serverPort}`,
        callback_origin: `http://127.0.0.2:${serverPort}`,
        server_authority_id: CONTROLLER_AUTHORITY,
        deployment: "server_only",
        ui_mode: "assets",
        ui_assets_directory: uiAssetsDirectory,
        control_database: serverDatabase,
        secret_directory: join(serverRoot, "secrets"),
        access: {
          issuer: access.issuer,
          audiences: [ACCESS_AUDIENCE],
          jwks_url: `${access.baseUrl}/jwks`,
          subject_key_file: subjectKeyPath,
          subject_key_version: 1,
        },
      }),
      { mode: 0o600 },
    );
    const endpointBinary = process.env.ZODE_ENDPOINT_BIN ?? resolve(REPO_ROOT, "target/debug/zode");
    const serverBinary = process.env.ZODE_SERVER_BIN ?? resolve(REPO_ROOT, "server/target/debug/zode-server");
    let endpoint: ReadyProcess | undefined;
    let endpointBoundary: EndpointBoundary | undefined;
    let server: ReadyProcess | undefined;
    try {
      endpoint = await ReadyProcess.start(endpointBinary, ["--config", endpointConfig], "ZODE_READY ");
      endpointBoundary = await EndpointBoundary.start(endpoint.baseUrl);
      server = await ReadyProcess.start(serverBinary, ["--config", serverConfig], "ZODE_SERVER_READY ");
      const topology = new Topology(
        topologyId,
        root,
        access,
        provider,
        tools,
        endpoint,
        endpointBoundary,
        server,
        serverDatabase,
        endpointSecret,
        access.token(),
        subjectKey,
        endpointConfig,
        serverConfig,
        endpointPort,
        serverPort,
      );
      await topology.assertServerPositiveBarrier();
      topology.knownSecrets.push(providerSecret);
      if (seed) await topology.seed(providerSecret);
      return topology;
    } catch (error) {
      if (server !== undefined) await server.stop().catch(() => undefined);
      if (endpoint !== undefined) await endpoint.stop().catch(() => undefined);
      await endpointBoundary?.close().catch(() => undefined);
      await provider.close().catch(() => undefined);
      await tools.close().catch(() => undefined);
      await access.close().catch(() => undefined);
      await rm(root, { recursive: true, force: true });
      throw error;
    }
  }

  private async assertServerPositiveBarrier(): Promise<void> {
    const system = requireBody(
      await apiJson(this.server.baseUrl, this.accessAssertion, "/v1/system"),
      200,
      "Server system positive barrier",
    );
    if (system.schema !== "zode.system.v1") {
      throw new Error("Server system positive barrier returned the wrong public schema");
    }
  }

  recordSession(sessionId: string): void {
    for (const fact of [
      sessionId,
      `/v1/sessions/${sessionId}`,
      `/sessions/${sessionId}`,
      `session:${sessionId}`,
      `session_id:${sessionId}`,
      `/v1/endpoints/${this.endpointId}/sessions/${sessionId}`,
    ]) {
      this.observedMarkers.push(fact);
    }
  }

  nextSseRequestId(): string {
    this.currentSseRequestId = `e2e-sse-${randomUUID()}`;
    return this.currentSseRequestId;
  }

  get sseRequestId(): string {
    return this.currentSseRequestId;
  }

  recordCursor(cursor: string): void {
    if (cursor.length === 0) return;
    for (const fact of [
      cursor,
      `cursor:${cursor}`,
      `event:${cursor}`,
      `last-event-id:${cursor}`,
      `Last-Event-ID:${cursor}`,
    ]) {
      if (fact !== cursor || cursor.length >= 8) this.observedMarkers.push(fact);
    }
  }

  recordEventIds(eventIds: string[]): void {
    for (const eventId of eventIds) {
      if (eventId.length === 0) continue;
      this.observedMarkers.push(`id:${eventId}`);
      this.recordCursor(eventId);
    }
  }

  expectScenario(scenario: string, expectedCount: number): void {
    this.expectedScenarioCounts.set(scenario, expectedCount);
    this.provider.setExpectedScenario(scenario, expectedCount);
  }

  async assertEndpointUnreachableBarrier(): Promise<void> {
    const response = await apiJson(
      this.server.baseUrl,
      this.accessAssertion,
      `/v1/endpoints/${this.endpointId}/probe`,
      {
        method: "POST",
        headers: { "Idempotency-Key": `browser-unreachable-${randomUUID()}` },
      },
    );
    if (response.status === 404) {
      if (!isExactRouteMissingPublicBody(response.body)) {
        throw new Error("Endpoint unreachable probe returned 404 without the exact public route-missing body/code");
      }
      throw new NonEvidenceShallow404("Endpoint unreachable probe");
    }
    if (response.status !== 503 || response.body?.error?.code !== "endpoint_unavailable") {
      throw new Error(
        `Endpoint unreachable barrier failed with status ${response.status} and code ${response.body?.error?.code ?? "<none>"}`,
      );
    }
  }

  async assertServerStoreHasNoSessionMirror(requiredPath?: string): Promise<void> {
    if (this.endpointId.length === 0) return;
    if (requiredPath !== undefined) {
      try {
        await stat(requiredPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          throw new Error(`required Server-owned store file is missing: ${requiredPath}`);
        }
        throw error;
      }
    }
    let sqliteInspection = { storeFiles: [] as string[], inspection: "" };
    try {
      await stat(this.serverDatabase);
      sqliteInspection = await inspectSqliteDatabase(this.serverDatabase);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      // A server that only served the public route classifier may never have
      // opened its control store. Missing SQLite is an empty store, not a
      // hidden session mirror.
    }
    const serverRoot = join(this.root, "server");
    const secretStoreRoot = join(serverRoot, "secrets");
    const subjectKeyPath = join(serverRoot, "subject.key");
    const secretStoreFiles = await filesUnder(secretStoreRoot);
    for (const path of secretStoreFiles) {
      const relativePath = relative(secretStoreRoot, path);
      if (
        relativePath !== ".zode-server.lock" &&
        relativePath !== ".server-owner" &&
        !/^(?:endpoints|providers)\/[0-9a-f]{64}$/.test(relativePath)
      ) {
        throw new Error(`Server secret-store file is outside the dedicated allowlist: ${path}`);
      }
    }
    const dedicatedSecretFiles = new Set([subjectKeyPath, ...secretStoreFiles].map((path) => resolve(path)));
    const files = new Set<string>([
      ...(await filesUnder(serverRoot)),
      ...sqliteInspection.storeFiles,
    ]);
    const inspectionBytes = Buffer.from(sqliteInspection.inspection, "utf8");
    for (const secret of this.knownSecrets) {
      if (containsMarker(inspectionBytes, secret)) {
        throw new Error("Server SQLite schema/columns/attached-store inspection contained a known secret");
      }
    }
    for (const marker of this.observedMarkers) {
      if (containsMarker(inspectionBytes, marker)) {
        throw new Error(`Server SQLite schema/columns/attached-store inspection contained a forbidden marker: ${marker}`);
      }
    }
    for (const path of files) {
      let bytes: Buffer;
      try {
        bytes = await readFile(path);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      const isDedicatedSecretFile = dedicatedSecretFiles.has(resolve(path));
      for (const secret of this.knownSecrets) {
        if (!isDedicatedSecretFile && containsMarker(bytes, secret)) {
          throw new Error(`Server-owned file ${path} contained a known secret`);
        }
      }
      for (const marker of this.observedMarkers) {
        if (containsMarker(bytes, marker)) {
          throw new Error(`Server-owned file ${path} contained a session/event/cursor marker: ${marker}`);
        }
      }
    }
  }

  private assertCassetteScenariosConsumed(): void {
    const cassetteCounts = this.provider.scenarioCounts();
    for (const [scenario, expectedCount] of this.expectedScenarioCounts) {
      if (cassetteCounts.get(scenario) !== expectedCount) {
        throw new Error(`E2E declared the wrong cassette count for scenario ${scenario}`);
      }
    }
    this.provider.assertAllExchangesConsumed();
    for (const [scenario, expectedCount] of this.expectedScenarioCounts) {
      const actualCount = this.provider.count(scenario);
      if (actualCount !== expectedCount) {
        throw new Error(`provider cassette scenario ${scenario} consumed ${actualCount}/${expectedCount} exchanges`);
      }
    }
  }

  private async seed(providerSecret: string): Promise<void> {
    const endpoint = requireBody(
      await apiJson(this.server.baseUrl, this.accessAssertion, "/v1/endpoints", {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": `browser-endpoint-${randomUUID()}` },
        body: JSON.stringify({
          label: "Browser lifecycle fixture endpoint",
          base_url: this.endpointBoundary.baseUrl,
          control_auth: { kind: "bearer", secret: this.endpointSecret },
        }),
      }),
      201,
      "Endpoint registration",
    );
    this.endpointId = endpoint.endpoint_id;
    const descriptor = requireBody(
      await apiJson(this.server.baseUrl, this.accessAssertion, `/v1/providers/${PROVIDER}`, {
        method: "PUT",
        headers: { "content-type": "application/json", "Idempotency-Key": `browser-descriptor-${randomUUID()}` },
        body: JSON.stringify({
          kind: "openai_compatible",
          base_url: `${this.provider.baseUrl}/v1`,
          models: [MODEL, REPLAY_HISTORY_MODEL],
          options: {},
        }),
      }),
      200,
      "Provider descriptor",
    );
    this.descriptorRevision = descriptor.revision;
    const profile = requireBody(
      await apiJson(this.server.baseUrl, this.accessAssertion, `/v1/providers/${PROVIDER}/auth-profiles`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": `browser-profile-${randomUUID()}` },
        body: JSON.stringify({
          kind: "api_key",
          label: "Browser lifecycle fixture profile",
          api_key: providerSecret,
          make_default: true,
          sharing: { mode: "selected", endpoint_ids: [this.endpointId] },
        }),
      }),
      201,
      "Provider profile",
    );
    this.profileId = profile.auth_profile_id;
    this.profileRevision = profile.revision;
    await expect
      .poll(
        async () => {
          const response = await apiJson(
            this.server.baseUrl,
            this.accessAssertion,
            `/v1/auth-profiles/${this.profileId}/replicas`,
          );
          if (response.status !== 200 || response.body === null) return "unavailable";
          const item = (response.body.items as Json[] | undefined)?.find(
            (candidate) => candidate.endpoint_id === this.endpointId,
          );
          if (item === undefined) return "missing";
          return item.status;
        },
        { timeout: 30_000, message: "profile replica did not become ready through Server" },
      )
      .toBe("ready");
  }

  async stop(): Promise<void> {
    let assertionError: unknown;
    try {
      this.assertCassetteScenariosConsumed();
    } catch (error) {
      assertionError = error;
    }
    let serverStopped = false;
    try {
      await this.server.stop();
      serverStopped = true;
    } catch (error) {
      if (assertionError === undefined) assertionError = error;
    }
    if (serverStopped) {
      try {
        await this.assertServerStoreHasNoSessionMirror();
      } catch (error) {
        if (assertionError === undefined) assertionError = error;
      }
    }
    const cleanupErrors: unknown[] = [];
    for (const cleanup of [
      () => (serverStopped ? Promise.resolve() : this.server.stop()),
      () => this.endpoint.stop(),
      () => this.endpointBoundary.close(),
      () => this.provider.close(),
      () => this.tools.close(),
      () => this.access.close(),
      () => rm(this.root, { recursive: true, force: true }),
    ]) {
      try {
        await cleanup();
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (assertionError !== undefined) throw assertionError;
    if (cleanupErrors.length > 0) throw cleanupErrors[0];
  }
}

async function bootstrap(page: Page, topology: Topology): Promise<void> {
  const pageErrors: string[] = [];
  const failedRequests: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("requestfailed", (request) => failedRequests.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText ?? "unknown"}`));
  await page.context().setExtraHTTPHeaders({
    "Cf-Access-Jwt-Assertion": topology.accessAssertion,
    [REQUEST_ID_HEADER]: topology.sseRequestId,
  });
  const response = await page.goto(`${topology.server.baseUrl}/`, { waitUntil: "domcontentloaded" });
  await classifyBrowser404(response, "management UI root");
  try {
    await expect(
      page.getByRole("heading", { name: "What do you want to work on?", exact: true }),
    ).toBeVisible();
  } catch (error) {
    const diagnostics = {
      ...(await page.evaluate(() => ({
      title: document.title,
      body: document.body?.innerText.slice(0, 4000) ?? "",
      scripts: [...document.scripts].map((script) => script.src),
      appHtml: document.querySelector("#app")?.innerHTML.slice(0, 4000) ?? "",
      }))),
      pageErrors,
      failedRequests,
    };
    throw new Error(`${error instanceof Error ? error.message : String(error)}; browser_diagnostics=${JSON.stringify(diagnostics)}`);
  }
  await expect(page.getByRole("button", { name: "Log in" })).toHaveCount(0);
  await expect(page.getByRole("textbox", { name: /token|password/i })).toHaveCount(0);
}

async function bootstrapServerSystem(page: Page, topology: Topology): Promise<void> {
  await page.context().setExtraHTTPHeaders({
    "Cf-Access-Jwt-Assertion": topology.accessAssertion,
    [REQUEST_ID_HEADER]: topology.sseRequestId,
  });
  const response = await page.goto(`${topology.server.baseUrl}/v1/system`, { waitUntil: "domcontentloaded" });
  if (response === null || response.status() !== 200) {
    throw new Error(`browser Server positive barrier failed with status ${response?.status() ?? "<missing>"}`);
  }
  const body = (await response.json()) as Json;
  if (body.schema !== "zode.system.v1") {
    throw new Error("browser Server positive barrier returned the wrong public schema");
  }
}

async function browserPublicJson(
  page: Page,
  baseUrl: string,
  path: string,
  accessAssertion: string,
): Promise<BrowserPublicResponse> {
  return page.evaluate(
    async ({ url, assertion }) => {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          Accept: "application/json",
          "Cf-Access-Jwt-Assertion": assertion,
        },
      });
      const bodyText = await response.text();
      let body: Json | null = null;
      try {
        body = JSON.parse(bodyText) as Json;
      } catch {
        body = null;
      }
      return {
        status: response.status,
        body,
        bodyText,
        contentType: response.headers.get("content-type") ?? "",
      };
    },
    { url: `${baseUrl}${path}`, assertion: accessAssertion },
  ) as Promise<BrowserPublicResponse>;
}

function assertDualPublicResponse(
  label: string,
  serverResponse: BrowserPublicResponse,
  browserResponse: BrowserPublicResponse,
): void {
  if (browserResponse.status !== serverResponse.status) {
    throw new Error(
      `${label} browser/Server status diverged: ${browserResponse.status} != ${serverResponse.status}`,
    );
  }
  if (browserResponse.bodyText !== serverResponse.bodyText) {
    throw new Error(`${label} browser/Server body bytes diverged`);
  }
  if (canonicalJson(browserResponse.body) !== canonicalJson(serverResponse.body)) {
    throw new Error(`${label} browser/Server JSON bodies diverged`);
  }
  if (browserResponse.contentType !== serverResponse.contentType) {
    throw new Error(`${label} browser/Server content types diverged`);
  }
}

function assertExactResourceNotFound(response: BrowserPublicResponse, label: string): void {
  if (response.status !== 404 || canonicalJson(response.body) !== canonicalJson(RESOURCE_NOT_FOUND_PUBLIC_BODY)) {
    throw new Error(`${label} did not return the explicit resource not_found public contract`);
  }
  if (!response.contentType.toLowerCase().includes("application/json")) {
    throw new Error(`${label} omitted the JSON content type required by the resource not_found contract`);
  }
  if (isExactRouteMissingPublicBody(response.body)) {
    throw new Error(`${label} misclassified a normal resource not_found response as route-missing`);
  }
}

function assertExactRouteMissing(response: BrowserPublicResponse, label: string): void {
  if (response.status !== 404 || !isExactRouteMissingPublicBody(response.body)) {
    throw new Error(
      `${label} returned a bare fallback or normal resource not_found 404; only the explicit route_not_found body/code is shallow non-evidence`,
    );
  }
  if (!response.contentType.toLowerCase().includes("application/json")) {
    throw new Error(`${label} omitted the JSON content type required by the route-missing contract`);
  }
}

function fixtureModelSelection(topology: Topology, model = MODEL): Json {
  return {
    provider: PROVIDER,
    model,
    provider_execution: {
      schema: "zode.provider-execution.v1",
      revision: topology.descriptorRevision,
      kind: "openai_compatible",
      base_url: `${topology.provider.baseUrl}/v1`,
      options: {},
    },
    auth_profile_id: topology.profileId,
    minimum_auth_revision: topology.profileRevision,
  };
}

async function seedDurableReplayHistory(
  topology: Topology,
  sessionId: string,
  count: number,
): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    const selected = requireBody(
      await apiJson(
        topology.server.baseUrl,
        topology.accessAssertion,
        `/v1/endpoints/${topology.endpointId}/sessions/${sessionId}/model`,
        {
          method: "PUT",
          headers: {
            "content-type": "application/json",
            "Idempotency-Key": `browser-replay-history-${index}-${randomUUID()}`,
          },
          body: JSON.stringify(
            fixtureModelSelection(topology, index % 2 === 0 ? REPLAY_HISTORY_MODEL : MODEL),
          ),
        },
      ),
      202,
      `browser durable replay history selection ${index}`,
    );
    const selectedVersion = Number(selected.version);
    await withTimeout(
      (async () => {
        while (true) {
          const current = await apiJson(
            topology.server.baseUrl,
            topology.accessAssertion,
            `/v1/endpoints/${topology.endpointId}/sessions/${sessionId}`,
          );
          if (
            current.status === 200 &&
            current.body !== null &&
            Number(current.body.version) > selectedVersion &&
            current.body.active_activation === null &&
            current.body.active_model_round === null
          ) {
            return;
          }
          await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 5));
        }
      })(),
      15_000,
      `browser durable replay history selection ${index} did not reach an idle public projection`,
    );
  }
}

async function seedEndpointReplayHistory(
  topology: Topology,
  count: number,
): Promise<{ sessionId: string; tailMessageId: string; tailEventId: string }> {
  if (count < 2 || count % 2 !== 0) {
    throw new Error("browser Endpoint replay history requires an even durable event count");
  }
  let sessionId = "";
  let tailMessageId = "";
  for (let index = 0; index < count / 2; index += 1) {
    const created = requireBody(
      await apiJson(
        topology.server.baseUrl,
        topology.accessAssertion,
        `/v1/endpoints/${topology.endpointId}/sessions`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "Idempotency-Key": `browser-endpoint-replay-history-${index}-${randomUUID()}`,
          },
          body: JSON.stringify({ tools: [] }),
        },
      ),
      201,
      `browser Endpoint replay history session ${index}`,
    );
    sessionId = String(created.session_id ?? "");
    if (sessionId.length === 0) {
      throw new Error(`browser Endpoint replay history session ${index} omitted session_id`);
    }
    const messageId = `browser-replay-history-message-${index}`;
    const prefix = `${messageId}:`;
    const content = `${prefix}${"x".repeat(REPLAY_HISTORY_LARGE_MESSAGE_BYTES - prefix.length)}`;
    requireBody(
      await apiJson(
        topology.server.baseUrl,
        topology.accessAssertion,
        `/v1/endpoints/${topology.endpointId}/sessions/${sessionId}/messages`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "Idempotency-Key": `browser-endpoint-replay-history-message-${index}-${randomUUID()}`,
          },
          body: JSON.stringify({ message_id: messageId, content }),
        },
      ),
      202,
      `browser Endpoint replay history message ${index}`,
    );
    tailMessageId = messageId;
  }

  await expect
    .poll(
      () =>
        topology.endpointBoundary
          .eventRequests()
          .flatMap((request) => request.responseFrames)
          .find(
            (frame) =>
              frame.sessionId === sessionId && frame.messageId === tailMessageId,
          )?.id ?? "",
      {
        timeout: 15_000,
        message: "the live Endpoint stream did not publish the replay-history tail",
      },
    )
    .toMatch(/^[0-9]+$/);
  const tailEventId = topology.endpointBoundary
    .eventRequests()
    .flatMap((request) => request.responseFrames)
    .find(
      (frame) => frame.sessionId === sessionId && frame.messageId === tailMessageId,
    )?.id ?? "";
  return { sessionId, tailMessageId, tailEventId };
}

async function createSessionWithKeyboard(
  page: Page,
  topology: Topology,
  beforeOpen?: (sessionId: string) => Promise<void>,
): Promise<string> {
  // The product form intentionally creates a session with tools=[]; this
  // lifecycle fixture needs one explicitly selected HTTP tool so its later
  // cancellation/unknown-outcome scenarios exercise the real tool path.
  // Create it through the same authenticated public Server route, then hand
  // the resulting canonical session URL to the real browser UI.
  const response = requireBody(
    await apiJson(topology.server.baseUrl, topology.accessAssertion, `/v1/endpoints/${topology.endpointId}/sessions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "Idempotency-Key": `browser-session-${randomUUID()}`,
      },
      body: JSON.stringify({
        model: fixtureModelSelection(topology),
        tools: [TOOL],
      }),
    }),
    201,
    "browser lifecycle session creation",
  );
  const sessionId = String(response.session_id ?? "");
  if (!/^[A-Z0-9]+$/.test(sessionId)) throw new Error("public session creation omitted a canonical session_id");
  await beforeOpen?.(sessionId);
  await page.goto(`${topology.server.baseUrl}/endpoints/${topology.endpointId}/sessions/${sessionId}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page).toHaveURL(new RegExp(`/endpoints/${topology.endpointId}/sessions/${sessionId}$`));
  await expect(page.getByRole("textbox", { name: "Message" })).toBeVisible();
  topology.recordSession(sessionId);
  return sessionId;
}

async function sendMessageWithKeyboard(
  page: Page,
  prompt: string,
  whileDrafted?: () => Promise<void>,
  whileAdmissionPending?: (composer: Locator) => Promise<void>,
): Promise<void> {
  const composer = page.getByRole("textbox", { name: "Message" });
  await expect(page.getByRole("button", { name: "Send" })).toBeEnabled({ timeout: 15_000 });
  await composer.fill(prompt);
  await whileDrafted?.();
  try {
    await expect(composer).toHaveValue(prompt);
  } catch (error) {
    const evidencePath = await retainFailureEvidence("composer-draft-render-red", {
      schema: "zode.web-e2e.composer-draft-render-failure.v1",
      e2e: test.info().title,
      relation: "later_test_reproduction_of_initial_browser_failure",
      expected: "same-session durable SSE rendering preserves the unsent in-memory composer draft",
      prompt,
      observed_value: await composer.inputValue().catch(() => "<unavailable>"),
      browser_url: page.url(),
      browser_body: (await page.locator("body").innerText()).slice(0, 4_000),
    });
    throw new Error(
      `${error instanceof Error ? error.message : String(error)}; evidence_path=${evidencePath ?? "unavailable"}`,
    );
  }
  const admission = page.waitForResponse(
    (response) => response.url().includes("/messages") && response.request().method() === "POST",
  );
  await composer.press("Enter");
  await whileAdmissionPending?.(composer);
  const response = await admission;
  await classifyBrowser404(response, "session message admission");
  expect(response.status()).toBe(202);
}

async function holdNextBrowserMessageResponse(page: Page): Promise<BrowserResponseHold> {
  const pattern = "**/messages";
  let consumed = false;
  let markReceived = (): void => undefined;
  let release = (): void => undefined;
  const received = new Promise<void>((resolvePromise) => {
    markReceived = resolvePromise;
  });
  const released = new Promise<void>((resolvePromise) => {
    release = resolvePromise;
  });
  const handler = async (route: Route): Promise<void> => {
    if (consumed || route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    consumed = true;
    // Fetch the unmodified public response first, then delay only its delivery
    // to the browser. The real Server and Endpoint have already admitted the
    // request; no product route or response body is synthesized here.
    const response = await route.fetch();
    markReceived();
    await released;
    await route.fulfill({ response });
  };
  await page.route(pattern, handler);
  return {
    received,
    release,
    dispose: async () => {
      release();
      await page.unroute(pattern, handler);
    },
  };
}

function observeEventRequests(page: Page, topology?: Topology): BrowserSseRequest[] {
  const requests: BrowserSseRequest[] = [];
  const byPlaywrightRequest = new Map<Request, BrowserSseRequest>();
  page.on("request", (request) => {
    const url = new URL(request.url());
    const path = url.pathname;
    if (!path.endsWith("/events")) return;
    const match = path.match(/^\/v1\/endpoints\/([^/]+)\/events$/);
    if (match === null) {
      throw new Error(`browser SSE request used a non-Endpoint-scoped path: ${path}`);
    }
    const headers = request.headers();
    const observed = {
      method: request.method(),
      path,
      endpointId: match[1],
      requestId: headers[REQUEST_ID_HEADER] ?? "",
      lastEventId: headers["last-event-id"] ?? "",
    };
    requests.push(observed);
    byPlaywrightRequest.set(request, observed);
    topology?.recordCursor(observed.lastEventId);
  });
  page.on("response", (response) => {
    const observed = byPlaywrightRequest.get(response.request());
    if (observed !== undefined) observed.status = response.status();
  });
  page.on("requestfailed", (request) => {
    const observed = byPlaywrightRequest.get(request);
    if (observed !== undefined) observed.status = 0;
  });
  return requests;
}

function matchingBrowserSseRequests(
  requests: BrowserSseRequest[],
  endpointId: string,
  _sessionId: string,
  lastEventId: string,
): BrowserSseRequest[] {
  return requests.filter(
    (request) =>
      request.method === "GET" &&
      request.path === `/v1/endpoints/${endpointId}/events` &&
      request.endpointId === endpointId &&
      request.lastEventId === lastEventId,
  );
}

async function waitForBrowserSseRequest(
  requests: BrowserSseRequest[],
  endpointId: string,
  sessionId: string,
  lastEventId: string,
  label: string,
  requestId?: string,
): Promise<BrowserSseRequest> {
  const matchesForLabel = (): BrowserSseRequest[] => {
    const matches = matchingBrowserSseRequests(requests, endpointId, sessionId, lastEventId);
    return requestId === undefined ? matches : matches.filter((request) => request.requestId === requestId);
  };
  await expect
    .poll(
      () => matchesForLabel().length,
      { timeout: 15_000, message: `${label} did not arrive at the browser boundary` },
    )
    .toBeGreaterThan(0);
  const matches = matchesForLabel();
  const latest = matches.at(-1);
  if (latest === undefined) throw new Error(`${label} was not a browser SSE request`);
  if (latest.requestId.length === 0) throw new Error(`${label} omitted ${REQUEST_ID_HEADER}`);
  return latest;
}

function assertExactSseCorrelation(
  topology: Topology,
  browserRequest: BrowserSseRequest,
  endpointRequest: EndpointBoundaryRequest,
): void {
  assertSseBoundaryPair(browserRequest, endpointRequest);
  expect(browserRequest.endpointId).toBe(topology.endpointId);
  expect(browserRequest.path).toBe(`/v1/endpoints/${topology.endpointId}/events`);
  expect(browserRequest.requestId).toBe(topology.sseRequestId);
}

function assertSseBoundaryPair(
  browserRequest: BrowserSseRequest,
  endpointRequest: EndpointBoundaryRequest,
): void {
  // Server's public SSE contract forwards the Endpoint-wide path and
  // Last-Event-ID. x-request-id is a browser-local diagnostic header and is
  // not part of the Server→Endpoint protocol, so it is deliberately not
  // treated as an ownership or correlation requirement here.
  expect(browserRequest.method).toBe("GET");
  expect(browserRequest.path).toBe(`/v1/endpoints/${browserRequest.endpointId}/events`);
  expect(endpointRequest.lastEventId).toBe(browserRequest.lastEventId);
  expect(endpointRequest.forwardedLastEventId).toBe(browserRequest.lastEventId);
  expect(endpointRequest.path).toBe("/v1/events");
}

async function recordSseResponseMarkers(
  topology: Topology,
  requests: BrowserSseRequest[],
  _sessionId: string,
  label: string,
): Promise<void> {
  await expect
    .poll(
      () => requests.filter((request) => request.endpointId === topology.endpointId).length,
      { timeout: 15_000, message: `${label} did not open a browser SSE request` },
    )
    .toBeGreaterThan(0);
  await expect
    .poll(
      () => requests.filter((request) => request.endpointId === topology.endpointId).every((request) => request.status !== undefined),
      { timeout: 15_000, message: `${label} did not receive browser SSE response statuses` },
    )
    .toBe(true);
  const browserRequests = requests.filter(
    (request) => request.endpointId === topology.endpointId && request.status === 200,
  );
  if (browserRequests.length === 0) throw new Error(`${label} did not receive a successful browser SSE response`);
  let successfulEndpointResponses = 0;
  for (const browserRequest of browserRequests) {
    const endpointRequest = await topology.endpointBoundary.waitForEventRequest(
      browserRequest,
      { allowNon2xx: true },
    );
    assertSseBoundaryPair(browserRequest, endpointRequest);
    if (endpointRequest.status !== 200) continue;
    successfulEndpointResponses += 1;
    const eventIds =
      endpointRequest.responseEventIds.length > 0
        ? await topology.endpointBoundary.waitForResponseEventIds(
            endpointRequest,
            `${label} response ${browserRequest.requestId}`,
          )
        : [];
    topology.recordEventIds(eventIds);
    if (browserRequest.lastEventId.length > 0) {
      await expect
        .poll(
          () =>
            topology
              .endpointBoundary
              .eventRequests()
              .some((candidate) => candidate.responseEventIds.includes(browserRequest.lastEventId)),
          { timeout: 15_000, message: `${label} sent an unobserved Endpoint Last-Event-ID` },
        )
      .toBe(true);
    }
  }
  if (successfulEndpointResponses === 0) {
    throw new Error(
      `${label} did not receive a successful Endpoint SSE response; browser=${JSON.stringify(
        browserRequests.map((request) => ({
          requestId: request.requestId,
          lastEventId: request.lastEventId,
          status: request.status,
        })),
      )}; endpoint=${JSON.stringify(topology.endpointBoundary.debugRequests().slice(-12))}`,
    );
  }
}

function observeBrowserNetwork(page: Page): BrowserNetworkObservation[] {
  const observations: BrowserNetworkObservation[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    observations.push({ kind: "http", url: request.url(), protocol: url.protocol, method: request.method() });
  });
  page.on("websocket", (webSocket) => {
    const url = new URL(webSocket.url());
    observations.push({ kind: "websocket", url: webSocket.url(), protocol: url.protocol });
  });
  return observations;
}

function assertBrowserNetworkUsesManagementOrigin(
  observations: BrowserNetworkObservation[],
  managementBaseUrl: string,
): void {
  const managementOrigin = new URL(managementBaseUrl).origin;
  for (const observation of observations) {
    const url = new URL(observation.url);
    if (observation.kind === "websocket" || observation.protocol === "ws:" || observation.protocol === "wss:") {
      throw new Error(`browser opened a WebSocket instead of management HTTP/SSE: ${observation.url}`);
    }
    if (observation.protocol !== "http:" && observation.protocol !== "https:") {
      throw new Error(`browser used a non-management network scheme: ${observation.url}`);
    }
    if (url.origin !== managementOrigin) {
      throw new Error(`browser request escaped management origin: ${url.origin}${url.pathname}`);
    }
  }
}

async function expectOneDurableFinal(page: Page, text: string): Promise<void> {
  await expect(page.getByText(text, { exact: true })).toHaveCount(1);
}

test.describe("session reconnect and runtime states", () => {
  let topology: Topology | undefined;
  let browserNetwork: BrowserNetworkObservation[] = [];

  test.beforeEach(async ({ page }, testInfo) => {
    browserNetwork = observeBrowserNetwork(page);
    topology = await Topology.start(
      testInfo.title,
      !testInfo.title.startsWith(ROUTE_CLASSIFIER_TEST_PREFIX),
      testInfo.title.includes("safe_deduplicated_retry"),
    );
  });

  test.afterAll(() => {
    const behaviorConsumptions = suiteTopologyConsumptions.filter(
      (topologyConsumption) => topologyConsumption.expectedSequences.length > 0,
    );
    if (suiteSawShallow404 || behaviorConsumptions.length !== 5 || suiteExpectedSequences === undefined) return;
    const flattened: number[] = [];
    const counts = new Map<number, number>();
    for (const topologyConsumption of behaviorConsumptions) {
      if (canonicalJson(topologyConsumption.consumedSequences) !== canonicalJson(topologyConsumption.expectedSequences)) {
        throw new Error(`provider cassette topology ${topologyConsumption.topologyId} did not consume its ordered exchange plan`);
      }
      for (const sequence of topologyConsumption.expectedSequences) {
        if ((topologyConsumption.countsBySequence.get(sequence) ?? 0) !== 1) {
          throw new Error(
            `provider cassette topology ${topologyConsumption.topologyId} consumed exchange ${sequence} more than once or not at all`,
          );
        }
      }
      for (const sequence of topologyConsumption.consumedSequences) {
        flattened.push(sequence);
        counts.set(sequence, (counts.get(sequence) ?? 0) + 1);
      }
    }
    const coveredSequences = [...new Set(flattened)].sort((left, right) => left - right);
    if (canonicalJson(coveredSequences) !== canonicalJson(suiteExpectedSequences)) {
      throw new Error(
        `provider cassette suite covered exchanges ${coveredSequences.length}/${suiteExpectedSequences.length}`,
      );
    }
    for (const sequence of suiteExpectedSequences) {
      if ((counts.get(sequence) ?? 0) === 0) {
        throw new Error(`provider cassette suite exchange ${sequence} was not consumed`);
      }
    }
  });

  test.afterEach(async () => {
    const current = topology;
    topology = undefined;
    let assertionError: unknown;
    try {
      if (current !== undefined) {
        assertBrowserNetworkUsesManagementOrigin(browserNetwork, current.server.baseUrl);
      }
    } catch (error) {
      assertionError = error;
    }
    try {
      if (current !== undefined) await current.stop();
    } catch (error) {
      if (assertionError === undefined) assertionError = error;
    }
    if (assertionError !== undefined) throw assertionError;
  });

  test("e2e_browser_route_missing_classifier_distinguishes_resource_not_found_from_bare_fallback", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    await bootstrapServerSystem(page, topology);
    const resourcePath = `/v1/endpoints/${randomUUID()}`;
    const serverResource = await apiJson(topology.server.baseUrl, topology.accessAssertion, resourcePath, {
      headers: { Accept: "application/json" },
    });
    const browserResource = await browserPublicJson(
      page,
      topology.server.baseUrl,
      resourcePath,
      topology.accessAssertion,
    );
    assertDualPublicResponse("resource not_found", serverResource, browserResource);
    assertExactResourceNotFound(serverResource, "Server resource not_found");
    assertExactResourceNotFound(browserResource, "browser resource not_found");

    const serverRoute = await apiJson(topology.server.baseUrl, topology.accessAssertion, ROUTE_MISSING_PATH, {
      headers: { Accept: "application/json" },
    });
    const browserRoute = await browserPublicJson(
      page,
      topology.server.baseUrl,
      ROUTE_MISSING_PATH,
      topology.accessAssertion,
    );
    assertDualPublicResponse("route-missing", serverRoute, browserRoute);
    assertExactRouteMissing(serverRoute, "Server route-missing");
    assertExactRouteMissing(browserRoute, "browser route-missing");
  });

  test("e2e_browser_server_store_scan_fails_closed_on_missing_subject_key_or_sqlite_sidecar", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    const sseRequests = observeEventRequests(page, topology);
    await bootstrap(page, topology);
    const sessionId = await createSessionWithKeyboard(page, topology);
    const browserSse = await waitForBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      "",
      "server-store-scan initial browser SSE",
    );
    const endpointSse = await topology.endpointBoundary.waitForEventRequest(
      browserSse,
    );
    assertExactSseCorrelation(topology, browserSse, endpointSse);
    await expect
      .poll(() => browserSse.status ?? 0, {
        timeout: 15_000,
        message: "server-store-scan did not receive a 200 browser SSE response",
      })
      .toBe(200);
    const eventIds = await topology.endpointBoundary.waitForResponseEventIds(
      endpointSse,
      "server-store-scan initial Endpoint SSE",
    );
    expect(eventIds.length).toBeGreaterThan(0);
    topology.recordEventIds(eventIds);

    await topology.server.stop();
    await topology.assertServerStoreHasNoSessionMirror();

    const candidates = [
      `${topology.serverDatabase}-wal`,
      `${topology.serverDatabase}-shm`,
      `${topology.serverDatabase}-journal`,
      join(topology.root, "server", "subject.key"),
    ];
    let missingTarget: string | undefined;
    let originalBytes: Buffer | undefined;
    for (const candidate of candidates) {
      try {
        originalBytes = await readFile(candidate);
        missingTarget = candidate;
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    if (missingTarget === undefined || originalBytes === undefined) {
      throw new Error("server-store-scan fixture had no test-owned subject key or SQLite sidecar to remove");
    }
    await rm(missingTarget);
    try {
      await expect(
        topology.assertServerStoreHasNoSessionMirror(missingTarget),
        "server store scan must fail closed after its subject key or SQLite sidecar is deleted",
      ).rejects.toThrow();
    } finally {
      await writeFile(missingTarget, originalBytes, { mode: 0o600 });
      if (missingTarget.endsWith("subject.key")) await chmod(missingTarget, 0o600);
    }
  });

  test("e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final", async ({
    page,
  }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    const testTopology = topology;
    const sseRequests = observeEventRequests(page, topology);
    await bootstrap(page, topology);
    topology.expectScenario(SCENARIOS.keyboard, 1);
    const keyboardSessionId = await createSessionWithKeyboard(page, topology);
    const pendingDraft = "second unsent draft while the first message is admitted";
    const keyboardAdmission = await holdNextBrowserMessageResponse(page);
    try {
      await sendMessageWithKeyboard(
        page,
        `keyboard path ${SCENARIOS.keyboard}`,
        () => seedDurableReplayHistory(topology!, keyboardSessionId, 2),
        async (composer) => {
          await withTimeout(
            keyboardAdmission.received,
            15_000,
            "browser message response was not held after real admission",
          );
          await composer.fill(pendingDraft);
          keyboardAdmission.release();
        },
      );
      await expect(page.getByRole("button", { name: "Send" })).toBeEnabled({ timeout: 15_000 });
      const composer = page.getByRole("textbox", { name: "Message" });
      try {
        await expect(composer).toHaveValue(pendingDraft);
      } catch (error) {
        const evidencePath = await retainFailureEvidence("composer-admission-draft-red", {
          schema: "zode.web-e2e.composer-admission-draft-failure.v1",
          e2e: test.info().title,
          expected: "accepting one submission preserves a newer unsent same-session draft",
          submitted_prompt: `keyboard path ${SCENARIOS.keyboard}`,
          pending_draft: pendingDraft,
          observed_value: await composer.inputValue().catch(() => "<unavailable>"),
          browser_url: page.url(),
          browser_body: (await page.locator("body").innerText()).slice(0, 4_000),
          endpoint_boundary: topology.endpointBoundary.debugRequests(),
          provider_requests: topology.provider.debugRequests(),
        });
        throw new Error(
          `${error instanceof Error ? error.message : String(error)}; evidence_path=${evidencePath ?? "unavailable"}`,
        );
      }
      await composer.fill("");
    } finally {
      await keyboardAdmission.dispose();
    }
    try {
      await withTimeout(
        topology.provider.waitForScenario(SCENARIOS.keyboard),
        15_000,
        `provider did not receive ${SCENARIOS.keyboard} through Endpoint`,
      );
    } catch (error) {
      const sessionSnapshot = await apiJson(
        topology.server.baseUrl,
        topology.accessAssertion,
        `/v1/endpoints/${topology.endpointId}/sessions/${keyboardSessionId}`,
      );
      throw new Error(
        `${error instanceof Error ? error.message : String(error)}; session_snapshot=${JSON.stringify(sessionSnapshot.body)}; provider_requests=${JSON.stringify(topology.provider.debugRequests())}; endpoint_boundary=${JSON.stringify(topology.endpointBoundary.debugRequests())}; endpoint_process=${JSON.stringify(topology.endpoint.outputSnapshot(topology.knownSecrets))}; server_process=${JSON.stringify(topology.server.outputSnapshot(topology.knownSecrets))}; browser_body=${JSON.stringify((await page.locator("body").innerText()).slice(0, 2000))}`,
      );
    }
    await expectOneDurableFinal(page, "KEYBOARD_FINAL");
    topology.provider.holdAfterFirstChunk(SCENARIOS.reconnect);
    topology.provider.holdAfterFirstChunk(SCENARIOS.reconnect, 1);
    const firstProviderChunk = topology.provider.waitForScenario(`${SCENARIOS.reconnect}:first-chunk`);
    const secondProviderChunk = topology.provider.waitForScenario(`${SCENARIOS.reconnect}:first-chunk-2`);
    const sessionId = await createSessionWithKeyboard(page, topology);
    const replayHistory = await seedEndpointReplayHistory(topology, REPLAY_BACKPRESSURE_EVENT_COUNT);
    const replayBodyHold = topology.endpointBoundary.holdNextEventBody();
    const replayRequestId = topology.nextSseRequestId();
    await page.context().setExtraHTTPHeaders({
      "Cf-Access-Jwt-Assertion": topology.accessAssertion,
      [REQUEST_ID_HEADER]: replayRequestId,
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    const initialEndpointRequest = await withTimeout(
      replayBodyHold.received,
      15_000,
      "Endpoint replay body was not held after its public headers",
    );
    const initialBrowserRequest = await waitForBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      "",
      "initial browser SSE",
      replayRequestId,
    );
    initialBrowserRequest.endpointRequest = initialEndpointRequest;
    assertExactSseCorrelation(topology, initialBrowserRequest, initialEndpointRequest);
    topology.expectScenario(SCENARIOS.reconnect, 2);
    try {
      await sendMessageWithKeyboard(page, `reconnect path ${SCENARIOS.reconnect}`);
      await withTimeout(
        firstProviderChunk,
        15_000,
        "provider did not flush its provisional chunk",
      );
      await topology.provider.waitForScenario(SCENARIOS.reconnect);
      replayBodyHold.release();
      try {
        await expect(page.getByText("PROVISIONAL_TOKEN", { exact: true })).toBeVisible();
      } catch (error) {
        const sessionSnapshot = await apiJson(
          topology.server.baseUrl,
          topology.accessAssertion,
          `/v1/endpoints/${topology.endpointId}/sessions/${sessionId}`,
        );
        const evidencePath = await retainFailureEvidence("provisional-browser-red", {
          schema: "zode.web-e2e.session-reconnect-failure.v1",
          e2e: "e2e_browser_session_admission_is_separate_from_completion_and_last_event_id_reconnect_replaces_provisional_final",
          expected: "the browser renders the provisional token after opening a long durable replay and before retry or Server restart",
          browser_body: (await page.locator("body").innerText()).slice(0, 4000),
          session_snapshot: sessionSnapshot.body,
          provider_requests: topology.provider.debugRequests(),
          endpoint_boundary: topology.endpointBoundary.debugRequests(),
        });
        throw new Error(
          `${error instanceof Error ? error.message : String(error)}; evidence_path=${evidencePath ?? "unavailable"}; browser_body=${JSON.stringify((await page.locator("body").innerText()).slice(0, 4000))}; session_snapshot=${JSON.stringify(sessionSnapshot.body)}; provider_requests=${JSON.stringify(topology.provider.debugRequests())}; endpoint_boundary=${JSON.stringify(topology.endpointBoundary.debugRequests())}`,
        );
      }
      await expect
        .poll(
          () => initialEndpointRequest.responseEventNames.includes("assistant_message_delta"),
          {
            timeout: 15_000,
            message: "the fenced Endpoint-wide SSE did not carry the provisional assistant delta",
          },
        )
        .toBe(true);
      const deliveryEndpointRequest = initialEndpointRequest;
      expect(deliveryEndpointRequest.path).toBe("/v1/events");
      await expect
        .poll(
          () =>
            deliveryEndpointRequest.responseFrames.findIndex(
              (frame) => frame.name === "assistant_message_delta",
            ),
          {
            timeout: 15_000,
            message: "Endpoint replay never interleaved post-fence transient progress",
          },
        )
        .toBeGreaterThanOrEqual(0);
      const provisionalFrameIndex = deliveryEndpointRequest.responseFrames.findIndex(
        (frame) => frame.name === "assistant_message_delta",
      );
      await expect
        .poll(
          () =>
            deliveryEndpointRequest.responseFrames.findIndex(
              (frame) =>
                frame.id === replayHistory.tailEventId &&
                frame.sessionId === replayHistory.sessionId &&
                frame.messageId === replayHistory.tailMessageId,
            ),
          {
            timeout: 15_000,
            message: "Endpoint replay did not expose the seeded durable history tail",
          },
        )
        .toBeGreaterThanOrEqual(0);
      const replayTailFrameIndex = deliveryEndpointRequest.responseFrames.findIndex(
        (frame) =>
          frame.id === replayHistory.tailEventId &&
          frame.sessionId === replayHistory.sessionId &&
          frame.messageId === replayHistory.tailMessageId,
      );
      expect(provisionalFrameIndex).toBeLessThan(replayTailFrameIndex);
      await expect
        .poll(() => deliveryEndpointRequest.responseEventIds.at(-1) ?? "", {
          timeout: 15_000,
          message: "Endpoint stream did not expose a durable cursor before refresh",
        })
        .toMatch(/^[0-9]+$/);
      const initialEventIds = [...deliveryEndpointRequest.responseEventIds];
      topology.recordEventIds(initialEventIds);
      await expect(
        page.getByLabel("You").getByText(`reconnect path ${SCENARIOS.reconnect}`, { exact: true }),
      ).toBeVisible();
      const provisionalCursor = initialEventIds.at(-1) ?? "";
      topology.recordCursor(provisionalCursor);

      const reloadRequestId = topology.nextSseRequestId();
      await page.context().setExtraHTTPHeaders({
        "Cf-Access-Jwt-Assertion": topology.accessAssertion,
        [REQUEST_ID_HEADER]: reloadRequestId,
      });
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.getByRole("textbox", { name: "Message" })).toBeVisible();
      const reloadedBrowserRequest = await waitForBrowserSseRequest(
        sseRequests,
        topology.endpointId,
        sessionId,
        "",
        "refreshed browser SSE",
        reloadRequestId,
      );
      const reloadedEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
        reloadedBrowserRequest,
      );
      assertExactSseCorrelation(topology, reloadedBrowserRequest, reloadedEndpointRequest);
      expect(reloadedBrowserRequest.requestId).toBe(reloadRequestId);
      expect(reloadedBrowserRequest.lastEventId).toBe("");
      expect(reloadedEndpointRequest.status).toBe(200);
      await expect(page.getByText("PROVISIONAL_TOKEN", { exact: true })).toHaveCount(0);

      requireBody(
        await apiJson(
          topology.server.baseUrl,
          topology.accessAssertion,
          `/v1/endpoints/${topology.endpointId}/sessions/${sessionId}/model`,
          {
            method: "PUT",
            headers: {
              "content-type": "application/json",
              "Idempotency-Key": `browser-reconnect-cursor-barrier-${randomUUID()}`,
            },
            body: JSON.stringify(fixtureModelSelection(topology, REPLAY_HISTORY_MODEL)),
          },
        ),
        202,
        "browser reconnect cursor consumption barrier",
      );
      await expect(
        page.getByLabel(new RegExp(`model ${REPLAY_HISTORY_MODEL}`, "i")),
      ).toBeVisible({ timeout: 30_000 });

      const publishedBeforeOutage = new Set(
        topology.endpointBoundary.eventRequests().flatMap((request) => request.responseEventIds),
      );
      const cursorCountBeforeOutage = sseRequests.length;
      await topology.server.stop();
      await topology.assertServerStoreHasNoSessionMirror();
      await expect(page.getByText("Reconnecting", { exact: true })).toBeVisible({ timeout: 30_000 });
      const resumedRequestId = topology.nextSseRequestId();
      await page.context().setExtraHTTPHeaders({
        "Cf-Access-Jwt-Assertion": topology.accessAssertion,
        [REQUEST_ID_HEADER]: resumedRequestId,
      });
      await topology.server.restart();
      await expect
        .poll(
          () =>
            sseRequests
              .slice(cursorCountBeforeOutage)
              .find(
                (request) =>
                  request.requestId === resumedRequestId && request.lastEventId.length > 0,
              )?.lastEventId ?? "",
          {
            timeout: 15_000,
            message: "browser did not reconnect the Endpoint SSE with Last-Event-ID",
          },
        )
        .toMatch(/^[0-9]+$/);
      const resumedCursor = sseRequests
        .slice(cursorCountBeforeOutage)
        .filter(
          (request) => request.requestId === resumedRequestId && request.lastEventId.length > 0,
        )
        .at(-1)?.lastEventId ?? "";
      expect(publishedBeforeOutage.has(resumedCursor)).toBe(true);
      expect(BigInt(resumedCursor)).toBeGreaterThanOrEqual(BigInt(provisionalCursor));
      topology.recordCursor(resumedCursor);
      const resumedBrowserRequest = await waitForBrowserSseRequest(
        sseRequests,
        topology.endpointId,
        sessionId,
        resumedCursor,
        "reconnected browser SSE",
        resumedRequestId,
      );
      const resumedEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
        resumedBrowserRequest,
      );
      expect(resumedBrowserRequest.path).toBe(`/v1/endpoints/${topology.endpointId}/events`);
      expect(resumedBrowserRequest.requestId).toBe(resumedRequestId);
      assertExactSseCorrelation(topology, resumedBrowserRequest, resumedEndpointRequest);

      topology.provider.release(`${SCENARIOS.reconnect}:first-chunk`);
      await withTimeout(
        topology.provider.waitForScenario(SCENARIOS.reconnect, 2),
        15_000,
        "provider retry request did not start after the durable retry decision",
      );
      topology.provider.release("reconnect-final");
      await withTimeout(
        secondProviderChunk,
        15_000,
        "second attempt did not flush its transient chunk",
      );
      topology.provider.release(`${SCENARIOS.reconnect}:first-chunk-2`);
      await expect
        .poll(
          async () => {
            const response = await apiJson(
              topology!.server.baseUrl,
              topology!.accessAssertion,
              `/v1/endpoints/${topology!.endpointId}/sessions/${sessionId}`,
            );
            const transcript = Array.isArray(response.body?.transcript) ? response.body.transcript : [];
            return {
              status: response.status,
              final: transcript.filter(
                (message) => message.role === "assistant" && message.content === "DURABLE_FINAL",
              ).length,
              idle:
                response.body?.active_activation === null && response.body?.active_model_round === null,
            };
          },
          {
            timeout: 15_000,
            message: "second attempt did not commit its unique durable final",
          },
        )
        .toEqual({ status: 200, final: 1, idle: true });

      await expect
        .poll(
          () =>
            resumedEndpointRequest.responseEventNames.includes("assistant_message_committed")
              ? resumedEndpointRequest.responseEventIds.at(-1) ?? ""
              : "",
          { timeout: 15_000, message: "resumed SSE omitted its unique durable final cursor" },
        )
        .toMatch(/^[0-9]+$/);
      const resumedEventIds = [...resumedEndpointRequest.responseEventIds];
      topology.recordEventIds(resumedEventIds);
      await expectOneDurableFinal(page, "DURABLE_FINAL");
      await expect(page.locator("article.message-provisional")).toHaveCount(0);
      await expect(page.getByText("PROVISIONAL_TOKEN", { exact: true })).toHaveCount(0);
      const committedFinalCursor = resumedEndpointRequest.responseDurableEvents
        .filter((event) => event.name === "assistant_message_committed")
        .at(-1)?.id ?? "";
      expect(committedFinalCursor).toMatch(/^[0-9]+$/);
      const publishedBeforeEndpointRestart = new Set(
        topology.endpointBoundary.eventRequests().flatMap((request) => request.responseEventIds),
      );

      const cursorCountBeforeEndpointRestart = sseRequests.length;
      await topology.endpoint.stop();
      await topology.assertEndpointUnreachableBarrier();
      await expect(page.getByText("Reconnecting", { exact: true })).toBeVisible({ timeout: 30_000 });
      const endpointRestartRequestId = topology.nextSseRequestId();
      await page.context().setExtraHTTPHeaders({
        "Cf-Access-Jwt-Assertion": topology.accessAssertion,
        [REQUEST_ID_HEADER]: endpointRestartRequestId,
      });
      await topology.endpoint.restart();
      await expect
        .poll(
          () =>
            sseRequests
              .slice(cursorCountBeforeEndpointRestart)
              .find(
                (request) =>
                  request.requestId === endpointRestartRequestId &&
                  request.lastEventId.length > 0 &&
                  request.status === 200,
              )?.lastEventId ?? "",
          {
            timeout: 15_000,
            message: "Endpoint restart did not resume the Endpoint stream after its durable final",
          },
        )
        .toMatch(/^[0-9]+$/);
      const endpointRestartCursor = sseRequests
        .slice(cursorCountBeforeEndpointRestart)
        .filter(
          (request) =>
            request.requestId === endpointRestartRequestId &&
            request.lastEventId.length > 0 &&
            request.status === 200,
        )
        .at(-1)?.lastEventId ?? "";
      expect(publishedBeforeEndpointRestart.has(endpointRestartCursor)).toBe(true);
      expect(BigInt(endpointRestartCursor)).toBeGreaterThanOrEqual(BigInt(committedFinalCursor));
      await expect(page.getByRole("button", { name: "Send" })).toBeEnabled({ timeout: 15_000 });
      await expectOneDurableFinal(page, "DURABLE_FINAL");
      await recordSseResponseMarkers(topology, sseRequests, sessionId, "reconnect all runtime state");
      expect(sseRequests[0]?.lastEventId).toBe("");
      expect(topology.provider.count(SCENARIOS.reconnect)).toBe(2);
    } finally {
      replayBodyHold.dispose();
      testTopology.provider.release(`${SCENARIOS.reconnect}:first-chunk`);
      testTopology.provider.release("reconnect-final");
      testTopology.provider.release(`${SCENARIOS.reconnect}:first-chunk-2`);
    }
  });

  test("e2e_browser_offline_state_distinguishes_server_outage_from_endpoint_unreachable", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    const sseRequests = observeEventRequests(page, topology);
    await bootstrap(page, topology);
    const sessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.offline, 1);
    await sendMessageWithKeyboard(page, `offline path ${SCENARIOS.offline}`);
    await expectOneDurableFinal(page, "OFFLINE_FINAL");
    const initialBrowserRequest = await waitForBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      "",
      "offline initial browser SSE",
    );
    const initialEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
      initialBrowserRequest,
    );
    assertExactSseCorrelation(topology, initialBrowserRequest, initialEndpointRequest);
    const initialEventIds = await topology.endpointBoundary.waitForResponseEventIds(
      initialEndpointRequest,
      "offline initial Endpoint SSE",
    );
    topology.recordEventIds(initialEventIds);
    await expect
      .poll(
        () =>
          topology.endpointBoundary
            .eventRequests()
            .flatMap((request) => request.responseDurableEvents)
            .filter((event) => event.name === "assistant_message_committed")
            .at(-1)?.id ?? "",
        { timeout: 15_000, message: "offline session did not expose its durable final cursor" },
      )
      .toMatch(/^[0-9]+$/);
    const committedFinalCursor = topology.endpointBoundary
      .eventRequests()
      .flatMap((request) => request.responseDurableEvents)
      .filter((event) => event.name === "assistant_message_committed")
      .at(-1)?.id ?? "";
    expect(committedFinalCursor).toMatch(/^[0-9]+$/);
    const publishedBeforeServerOutage = new Set(
      topology.endpointBoundary.eventRequests().flatMap((request) => request.responseEventIds),
    );
    const cursorCountBeforeServerOutage = sseRequests.length;
    await topology.server.stop();
    await topology.assertServerStoreHasNoSessionMirror();
    await expect(page.getByText("Reconnecting", { exact: true })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toHaveCount(0);
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await topology.server.restart();
    await expect
      .poll(
        () =>
          sseRequests
            .slice(cursorCountBeforeServerOutage)
            .find((request) => request.lastEventId.length > 0 && request.status === 200)
            ?.lastEventId ?? "",
        {
          timeout: 15_000,
          message: "Server outage recovery did not resume the Endpoint stream from a browser cursor",
        },
      )
      .toMatch(/^[0-9]+$/);
    const resumedCursor = sseRequests
      .slice(cursorCountBeforeServerOutage)
      .filter((request) => request.lastEventId.length > 0 && request.status === 200)
      .at(-1)?.lastEventId ?? "";
    expect(publishedBeforeServerOutage.has(resumedCursor)).toBe(true);
    expect(BigInt(resumedCursor)).toBeGreaterThanOrEqual(BigInt(committedFinalCursor));
    topology.recordCursor(resumedCursor);
    const resumedBrowserRequest = await waitForBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      resumedCursor,
      "offline resumed browser SSE",
    );
    const resumedEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
      resumedBrowserRequest,
    );
    assertExactSseCorrelation(topology, resumedBrowserRequest, resumedEndpointRequest);
    expect(resumedEndpointRequest.status).toBe(200);
    await expectOneDurableFinal(page, "OFFLINE_FINAL");
    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(/Server unavailable/i)).toHaveCount(0);
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await expectOneDurableFinal(page, "OFFLINE_FINAL");
    await expect(page.getByRole("button", { name: "Send" })).toBeDisabled();
    expect(sseRequests[0]?.lastEventId).toBe("");
    await topology.endpoint.restart();
    await expect(page.getByRole("button", { name: "Send" })).toBeEnabled({ timeout: 15_000 });
    await recordSseResponseMarkers(topology, sseRequests, sessionId, "offline all runtime state");
  });

  test("e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    const sseRequests = observeEventRequests(page, topology);
    await bootstrap(page, topology);
    const cancelSessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.cancel, 1);
    await sendMessageWithKeyboard(page, `cancel path ${SCENARIOS.cancel}`);
    await topology.provider.waitForScenario(SCENARIOS.cancel);
    await topology.tools.waitFor("cancel");
    const cancelRow = page.getByRole("listitem", { name: new RegExp(`${TOOL}.*running`, "i") });
    await expect(cancelRow).toBeVisible();
    await expect(cancelRow.getByRole("button", { name: "Cancel tool" })).toBeEnabled();
    const cancelResponsePromise = page.waitForResponse((response) => {
      const path = new URL(response.url()).pathname;
      return response.request().method() === "POST" && path.endsWith("/cancel");
    });
    await cancelRow.getByRole("button", { name: "Cancel tool" }).click();
    const cancelResponse = await cancelResponsePromise;
    expect(cancelResponse.status()).toBe(200);
    expect((await cancelResponse.json() as { status?: string }).status).toBe("cancelled");
    const cancelledRow = page.getByRole("listitem", {
      name: new RegExp(`${TOOL}.*cancelled`, "i"),
    });
    await expect(cancelledRow).toBeVisible();
    await expect(cancelledRow.getByRole("button", { name: "Retry dispatch" })).toHaveCount(0);
    await recordSseResponseMarkers(topology, sseRequests, cancelSessionId, "cancel runtime state");
    const waitSessionId = await createSessionWithKeyboard(page, topology);
    await sendMessageWithKeyboard(page, `wait path ${SCENARIOS.waitTimeout}`);
    topology.expectScenario(SCENARIOS.waitTimeout, 2);
    await topology.provider.waitForScenario(SCENARIOS.waitTimeout);
    await expect(page.getByText(/Waiting.*deadline/i)).toBeVisible();
    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByText(/Server unavailable/i)).toHaveCount(0);
    await expect(page.getByText(/Waiting.*deadline/i)).toBeVisible();
    await expect(page.getByText(/timed out/i)).toHaveCount(0);
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await topology.endpoint.restart();
    await expect(page.getByRole("button", { name: "Send" })).toBeEnabled({ timeout: 15_000 });
    await expect(page.getByText(/timed out/i)).toBeVisible({ timeout: 15_000 });
    await expectOneDurableFinal(page, "WAIT_TIMEOUT_FINAL");
    await recordSseResponseMarkers(topology, sseRequests, waitSessionId, "wait-timeout runtime state");
    topology.expectScenario(SCENARIOS.unknown, 1);
    const unknownSessionId = await createSessionWithKeyboard(page, topology);
    await sendMessageWithKeyboard(page, `unknown path ${SCENARIOS.unknown}`);
    await topology.provider.waitForScenario(SCENARIOS.unknown);
    await topology.tools.waitFor("unknown");
    const runningUnknownRow = page.getByRole("listitem", { name: new RegExp(`${TOOL}.*running`, "i") });
    await expect(runningUnknownRow).toBeVisible();
    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByText(/Server unavailable/i)).toHaveCount(0);
    await expect(runningUnknownRow).toContainText(/running/i);
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await topology.endpoint.restart();
    const unknownRow = page.getByRole("listitem", { name: `${TOOL}, unknown outcome`, exact: true });
    await expect(unknownRow).toBeVisible();
    await expect(unknownRow).toContainText(/Unable to determine tool outcome/i);
    await expect(unknownRow.getByRole("button", { name: "Cancel tool" })).toHaveCount(0);
    await expect(unknownRow.getByRole("button", { name: "Mark failed" })).toHaveCount(0);
    await expect(unknownRow.getByRole("button", { name: "Reconcile tool outcome" })).toHaveCount(0);
    await recordSseResponseMarkers(topology, sseRequests, unknownSessionId, "unknown-outcome runtime state");
  });

  test("e2e_browser_safe_deduplicated_retry_reconciles_unknown_tool_with_original_identity", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    const sseRequests = observeEventRequests(page, topology);
    await bootstrap(page, topology);
    topology.expectScenario(SCENARIOS.safeReconcile, 2);
    const sessionId = await createSessionWithKeyboard(page, topology);
    await sendMessageWithKeyboard(page, `safe reconcile path ${SCENARIOS.safeReconcile}`);
    await topology.provider.waitForScenario(SCENARIOS.safeReconcile);
    await topology.tools.waitFor("safe");
    const runningRow = page.getByRole("listitem", { name: new RegExp(`${TOOL}.*running`, "i") });
    await expect(runningRow).toBeVisible();

    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await topology.endpoint.restart();

    await expect
      .poll(
        async () => {
          const response = await apiJson(
            topology!.server.baseUrl,
            topology!.accessAssertion,
            `/v1/endpoints/${topology!.endpointId}/sessions/${sessionId}/tool-calls/safe-reconcile-tool-call`,
          );
          return response.body?.status ?? `http-${response.status}`;
        },
        { timeout: 15_000, message: "restarted Endpoint did not publish the durable unknown outcome" },
      )
      .toBe("unknown_outcome");
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByRole("textbox", { name: "Message" })).toBeVisible();

    const unknownRow = page.getByRole("listitem", { name: `${TOOL}, unknown outcome`, exact: true });
    await expect(unknownRow).toBeVisible({ timeout: 15_000 });
    const reconcile = unknownRow.getByRole("button", { name: "Reconcile tool outcome" });
    await expect(reconcile).toBeEnabled();
    const reconcileResponsePromise = page.waitForResponse((response) => {
      const path = new URL(response.url()).pathname;
      return response.request().method() === "POST" && path.endsWith("/reconcile");
    });
    await reconcile.click();
    const reconcileResponse = await reconcileResponsePromise;
    expect(reconcileResponse.status()).toBe(200);
    expect((await reconcileResponse.json() as { tool_call_id?: string }).tool_call_id).toBe(
      "safe-reconcile-tool-call",
    );

    await withTimeout(
      topology.tools.waitFor("safe", 2),
      15_000,
      `safe reconcile did not dispatch the original tool identity twice; bodies=${JSON.stringify(topology.tools.bodiesFor("safe"))}`,
    );
    await expect(
      page.getByRole("listitem", { name: new RegExp(`${TOOL}.*completed`, "i") }),
    ).toBeVisible({ timeout: 15_000 });
    await expect
      .poll(
        async () => {
          if (topology!.provider.count(SCENARIOS.safeReconcile) >= 2) return "provider-2";
          const response = await apiJson(
            topology!.server.baseUrl,
            topology!.accessAssertion,
            `/v1/endpoints/${topology!.endpointId}/sessions/${sessionId}`,
          );
          return JSON.stringify({
            projection: response.body,
            provider: topology!.provider.debugRequests(),
          });
        },
        { timeout: 15_000, message: "safe reconcile completion did not wake a final model round" },
      )
      .toBe("provider-2");
    await expectOneDurableFinal(page, "SAFE_RECONCILE_FINAL");

    const toolRequests = topology.tools.bodiesFor("safe").map((body) => JSON.parse(body) as Json);
    expect(toolRequests).toHaveLength(2);
    expect(toolRequests.map((request) => request.tool_call_id)).toEqual([
      "safe-reconcile-tool-call",
      "safe-reconcile-tool-call",
    ]);
    expect(toolRequests.map((request) => request.tool_name)).toEqual([TOOL, TOOL]);
    expect(toolRequests.map((request) => request.input)).toEqual([{ mode: "safe" }, { mode: "safe" }]);

    const publicTool = requireBody(
      await apiJson(
        topology.server.baseUrl,
        topology.accessAssertion,
        `/v1/endpoints/${topology.endpointId}/sessions/${sessionId}/tool-calls/safe-reconcile-tool-call`,
      ),
      200,
      "safe reconcile public tool projection",
    );
    expect(publicTool.status).toBe("completed");
    expect(publicTool.tool_call_id).toBe("safe-reconcile-tool-call");
    await recordSseResponseMarkers(topology, sseRequests, sessionId, "safe reconcile runtime state");
  });

  test("e2e_browser_tool_call_completion_replaces_transient_preamble", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    await bootstrap(page, topology);
    const sessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.cancel, 1);
    topology.provider.enableToolPreamble(SCENARIOS.cancel);
    await sendMessageWithKeyboard(page, `cancel path ${SCENARIOS.cancel}`);
    await topology.provider.waitForScenario(SCENARIOS.cancel);
    await topology.tools.waitFor("cancel");
    const durableAssistant = page
      .locator("article.message-assistant:not(.message-provisional)")
      .filter({ hasText: "PRE_TOOL" });
    await expect(durableAssistant).toHaveCount(1, {
      timeout: 15_000,
      message: `assistant tool-call completion did not become durable; observed=${JSON.stringify(topology.endpointBoundary.debugRequests())}`,
    });
    try {
      expect(await page.locator("article.message-provisional").count()).toBe(0);
    } catch (error) {
      const evidencePath = await retainFailureEvidence("tool-preamble-provisional-red", {
        schema: "zode.web-e2e.tool-preamble-provisional-failure.v1",
        e2e: "e2e_browser_tool_call_completion_replaces_transient_preamble",
        expected: "a durable assistant message containing a tool call removes the transient preamble",
        browser_body: (await page.locator("body").innerText()).slice(0, 4_000),
        session_id: sessionId,
        endpoint_boundary: topology.endpointBoundary.debugRequests(),
        provider_requests: topology.provider.debugRequests(),
      });
      throw new Error(
        `${error instanceof Error ? error.message : String(error)}; evidence_path=${evidencePath ?? "unavailable"}`,
      );
    }
  });

  test("e2e_browser_mobile_collapsed_activity_rail_keeps_current_tool_error_state", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    const sseRequests = observeEventRequests(page, topology);
    await bootstrap(page, topology);
    const sessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.mobile, 1);
    await sendMessageWithKeyboard(page, `mobile path ${SCENARIOS.mobile}`);
    await topology.provider.waitForScenario(SCENARIOS.mobile);
    await topology.tools.waitFor("unknown");
    const runningToolRow = page.getByRole("listitem", { name: new RegExp(`${TOOL}.*running`, "i") });
    await expect(runningToolRow).toBeVisible();
    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible({
      timeout: 30_000,
    });
    await topology.endpoint.restart();
    const unknownOutcomeRow = page.getByRole("listitem", {
      name: `${TOOL}, unknown outcome`,
      exact: true,
    });
    await expect(unknownOutcomeRow).toBeVisible({ timeout: 15_000 });
    await expect(unknownOutcomeRow).toContainText(/Unable to determine tool outcome/i);
    await expect(page.getByText(/Waiting.*deadline|Wait timed out/i)).toHaveCount(0);
    const widths = [320, 375, 414, 768];
    for (const width of widths) {
      await page.setViewportSize({ width, height: 800 });
      const toggle = page.getByRole("button", { name: "Activity" });
      if (await toggle.getAttribute("aria-expanded") === "true") {
        await toggle.press("Enter");
      }
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
      await expect(unknownOutcomeRow).toBeVisible();
      await expect(unknownOutcomeRow).toContainText(/Unable to determine tool outcome/i);
      await expect(unknownOutcomeRow.getByRole("button", { name: "Reconcile tool outcome" })).toHaveCount(0);
      await expect(unknownOutcomeRow.getByRole("button", { name: "Cancel tool" })).toHaveCount(0);
      await expect(unknownOutcomeRow.getByRole("button", { name: "Mark failed" })).toHaveCount(0);
      await toggle.press("Enter");
      await expect(toggle).toHaveAttribute("aria-expanded", "true");
      const rail = page.getByRole("complementary", { name: "Activity" });
      await expect(rail).toBeVisible();
      await toggle.press("Enter");
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
    }
    await recordSseResponseMarkers(topology, sseRequests, sessionId, "mobile runtime state");
  });
});
