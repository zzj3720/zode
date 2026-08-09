import { expect, test, type Page, type Request } from "@playwright/test";
import { createHash, createSign, generateKeyPairSync, randomBytes, randomUUID, type KeyObject } from "node:crypto";
import { execFile as execFileCallback, spawn, type ChildProcessByStdio } from "node:child_process";
import { once } from "node:events";
import { readFile, writeFile, mkdir, chmod, mkdtemp, readdir, rm, cp } from "node:fs/promises";
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
  responseSseRemainder?: string;
  responseComplete?: boolean;
  recorded?: boolean;
};
type BrowserSseRequest = {
  method: string;
  path: string;
  endpointId: string;
  sessionId: string;
  requestId: string;
  lastEventId: string;
  status?: number;
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

const REPO_ROOT = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const CASSETTE_PATH = fileURLToPath(
  new URL("../fixtures/session_reconnect_runtime_states/session_reconnect_runtime_states.v1.json", import.meta.url),
);
const ACCESS_AUDIENCE = "zode-web-session-reconnect-runtime-states";
const ACCESS_SUBJECT = "web-session-reconnect-runtime-states-human";
const CONTROLLER_AUTHORITY = "web-session-reconnect-runtime-states-controller";
const PROVIDER = "fixture-provider";
const MODEL = "fixture-model";
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

const SCENARIOS = {
  keyboard: "keyboard-session",
  reconnect: "reconnect-session",
  offline: "offline-session",
  cancel: "cancel-session",
  waitTimeout: "wait-timeout-session",
  unknown: "unknown-outcome-session",
  mobile: "mobile-activity-session",
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
  const result = await execFile(binary, ["-readonly", "-json", database, sql], {
    maxBuffer: 16 * 1024 * 1024,
  });
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
  ) {}

  private readonly calls = new Map<string, number>();
  private readonly consumedSequences: number[] = [];
  private readonly countsBySequence = new Map<number, number>();
  private readonly waiters = new Map<string, Array<{ count: number; resolve: () => void }>>();
  private readonly released = new Set<string>();
  private readonly releaseWaiters = new Map<string, Array<() => void>>();
  private readonly expectedScenarioCounts = new Map<string, number>();
  private expectedProviderAuthorization = "";
  private suiteConsumptionRecorded = false;

  static async start(cassette: Cassette, topologyId: string): Promise<ReplayProvider> {
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
    if (suiteExpectedSequences === undefined) suiteExpectedSequences = sequences;
    else if (canonicalJson(suiteExpectedSequences) !== canonicalJson(sequences)) {
      throw new Error("session lifecycle cassette sequence plan changed between topologies");
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
    provider = new ReplayProvider(server, sockets, cassette, topologyId, `http://127.0.0.1:${port}`);
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

  private expectedSequences(): number[] {
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
    if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
      response.writeHead(404);
      response.end();
      return;
    }
    const body = await readBody(request);
    const scenario = this.scenarioFor(body);
    const occurrence = this.calls.get(scenario) ?? 0;
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
    for (const chunk of replay.chunks as Json[]) {
      response.write(Buffer.from(chunk.bytes_hex, "hex"));
    }
    if (replay.complete === true) response.end();
    else response.destroy();
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
    await withTimeout(
      new Promise<void>((resolvePromise) => {
        const waiters = this.waiters.get(scenario) ?? [];
        waiters.push({ count, resolve: resolvePromise });
        this.waiters.set(scenario, waiters);
      }),
      15_000,
      `provider scenario ${scenario} did not reach the retained public exchange`,
    );
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

  assertAllExchangesConsumed(): void {
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
    if (!line.startsWith("id:")) return;
    const value = line.startsWith("id: ") ? line.slice(4) : line.slice(3);
    if (value.length === 0) return;
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
        upstreamResponse.pipe(response);
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

  async waitForEventRequest(sessionId: string, lastEventId: string, requestId: string): Promise<EndpointBoundaryRequest> {
    const path = `/v1/sessions/${sessionId}/events`;
    const existing = this.requests.find(
      (request) =>
        request.method === "GET" &&
        request.path === path &&
        request.requestId === requestId &&
        request.forwardedRequestId === requestId &&
        request.lastEventId === lastEventId &&
        request.forwardedLastEventId === lastEventId,
    );
    if (existing !== undefined) {
      this.assertEventResponse(existing);
      return existing;
    }
    const request = await withTimeout(
      new Promise<EndpointBoundaryRequest>((resolvePromise) => {
        this.waiters.push({
          predicate: (request) =>
            request.method === "GET" &&
            request.path === path &&
            request.requestId === requestId &&
            request.forwardedRequestId === requestId &&
            request.lastEventId === lastEventId &&
            request.forwardedLastEventId === lastEventId,
          resolve: resolvePromise,
        });
      }),
      15_000,
      `Endpoint boundary did not receive Last-Event-ID ${lastEventId || "<empty>"}`,
    );
    this.assertEventResponse(request);
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
        throw new Error("Endpoint session events returned 404 without the exact public route-missing body/code");
      }
      throw new NonEvidenceShallow404("Endpoint session events");
    }
    if (request.status !== 200) {
      throw new Error(`Endpoint session events returned status ${request.status ?? "<missing>"}`);
    }
    if (!request.responseContentType?.toLowerCase().includes("text/event-stream")) {
      throw new Error("Endpoint session events returned 200 without a text/event-stream content type");
    }
  }

  eventRequests(sessionId: string): EndpointBoundaryRequest[] {
    return this.requests.filter(
      (request) => request.method === "GET" && request.path === `/v1/sessions/${sessionId}/events`,
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
  ) {}

  private readonly calls = new Map<string, number>();
  private readonly waiters = new Map<string, Array<{ resolve: () => void }>>();

  static async start(): Promise<ToolService> {
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
    service = new ToolService(server, sockets, `http://127.0.0.1:${port}`);
    return service;
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (request.method !== "POST" || request.url !== "/fixture_async") {
      response.writeHead(404);
      response.end();
      return;
    }
    const body = await readBody(request);
    const mode = body.includes('"mode":"unknown"') ? "unknown" : "cancel";
    this.calls.set(mode, (this.calls.get(mode) ?? 0) + 1);
    for (const waiter of this.waiters.get(mode) ?? []) waiter.resolve();
    this.waiters.delete(mode);
    response.once("close", () => undefined);
    if (mode === "cancel" || mode === "unknown") return;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  }

  async waitFor(mode: "cancel" | "unknown"): Promise<void> {
    if ((this.calls.get(mode) ?? 0) > 0) return;
    await new Promise<void>((resolvePromise) => {
      const waiters = this.waiters.get(mode) ?? [];
      waiters.push({ resolve: resolvePromise });
      this.waiters.set(mode, waiters);
    });
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
    readonly baseUrl: string,
  ) {}

  static async start(binary: string, args: string[], prefix: string): Promise<ReadyProcess> {
    const child = await ReadyProcess.spawnChild(binary, args, prefix);
    return new ReadyProcess(binary, args, prefix, child.child, child.baseUrl);
  }

  private static async spawnChild(
    binary: string,
    args: string[],
    prefix: string,
  ): Promise<{ child: ReadyChild; baseUrl: string }> {
    const child = spawn(binary, args, {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env },
    });
    child.stderr.resume();
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
        if (code !== null) finish(() => reject(new Error(`real process exited before readiness (${code})`)));
      });
    });
    try {
      const baseUrl = await withTimeout(readiness, 15_000, "real process readiness timed out");
      return { child, baseUrl };
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
  }

  async stop(): Promise<void> {
    if (this.child.exitCode !== null) return;
    this.child.kill("SIGTERM");
    try {
      await withTimeout(once(this.child, "exit").then(() => undefined), 10_000, "real process did not stop");
    } catch {
      this.child.kill("SIGKILL");
      await withTimeout(once(this.child, "exit").then(() => undefined), 5_000, "real process could not be reaped");
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
  private readonly observedMarkers = ["session", "event", "cursor"];
  private readonly knownSecrets: SecretMarker[];
  private readonly expectedScenarioCounts = new Map<string, number>();

  static async start(topologyId: string, seed = true): Promise<Topology> {
    const cassetteBytes = await readFile(CASSETTE_PATH);
    if (sha256(cassetteBytes) !== CASSETTE_RAW_SHA256) {
      throw new Error("session lifecycle cassette raw bytes changed; retain the original first occurrence");
    }
    const cassette = JSON.parse(cassetteBytes.toString("utf8")) as Cassette;
    const root = await mkdtemp(join(tmpdir(), "zode-web-rs-"));
    const access = await startAccessFixture();
    const provider = await ReplayProvider.start(cassette, topologyId);
    const tools = await ToolService.start();
    const endpointPort = await freePort();
    const serverPort = await freePort();
    const endpointRoot = join(root, "endpoint");
    const serverRoot = join(root, "server");
    await mkdir(join(endpointRoot, "credentials"), { recursive: true });
    await mkdir(join(endpointRoot, "blobs"), { recursive: true });
    await mkdir(join(serverRoot, "secrets"), { recursive: true });
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
          max_rounds_per_activation: 8,
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
              retry_dispatch: "never",
            },
            adapter: { kind: "http", url: `${tools.baseUrl}/fixture_async` },
          },
        ],
      }),
      { mode: 0o600 },
    );
    const serverDatabase = join(serverRoot, "control.sqlite3");
    const serverConfig = join(serverRoot, "config.json");
    const sourceUiDirectory = process.env.ZODE_UI_ASSETS_DIRECTORY
      ?? join(REPO_ROOT, "target", "ci", "product-ui");
    const confinedUiDirectory = join(serverRoot, "ui");
    await cp(sourceUiDirectory, confinedUiDirectory, {
      recursive: true,
      force: false,
      errorOnExist: true,
    });
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
        ui_assets_directory: confinedUiDirectory,
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
      `/v1/sessions/${sessionId}/events`,
      `/sessions/${sessionId}/events`,
      `/v1/endpoints/${this.endpointId}/sessions/${sessionId}`,
      `/v1/endpoints/${this.endpointId}/sessions/${sessionId}/events`,
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
      this.observedMarkers.push(fact);
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

  async assertServerStoreHasNoSessionMirror(): Promise<void> {
    const sqliteInspection = await inspectSqliteDatabase(this.serverDatabase);
    const serverRoot = join(this.root, "server");
    const secretStoreRoot = join(serverRoot, "secrets");
    const subjectKeyPath = join(serverRoot, "subject.key");
    const secretStoreFiles = await filesUnder(secretStoreRoot);
    for (const path of secretStoreFiles) {
      const relativePath = relative(secretStoreRoot, path);
      if (relativePath !== ".zode-server.lock" && !/^endpoints\/[0-9a-f]{64}$/.test(relativePath)) {
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
          models: [MODEL],
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
  await page.context().setExtraHTTPHeaders({
    "Cf-Access-Jwt-Assertion": topology.accessAssertion,
    [REQUEST_ID_HEADER]: topology.sseRequestId,
  });
  const response = await page.goto(`${topology.server.baseUrl}/`, { waitUntil: "domcontentloaded" });
  await classifyBrowser404(response, "management UI root");
  await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
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

async function createSessionWithKeyboard(page: Page, topology: Topology): Promise<string> {
  const create = page.getByRole("button", { name: "New session" });
  await create.focus();
  await page.keyboard.press("Enter");
  const form = page.locator("form.editor-panel").filter({ hasText: "New session" });
  await expect(form).toBeVisible();
  await form.getByRole("combobox", { name: "Endpoint" }).selectOption(topology.endpointId);
  await form.getByRole("combobox", { name: "Provider" }).selectOption(PROVIDER);
  await form.getByRole("combobox", { name: "Model" }).selectOption(MODEL);
  await form.getByRole("combobox", { name: "Auth profile" }).selectOption(topology.profileId);
  const submit = form.getByRole("button", { name: "Start session" });
  await submit.focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/endpoints/${topology.endpointId}/sessions/[A-Z0-9]+$`));
  const match = new URL(page.url()).pathname.match(/\/sessions\/([^/]+)$/);
  if (match === null) throw new Error("canonical Endpoint-scoped session URL omitted session_id");
  topology.recordSession(match[1]);
  return match[1];
}

async function sendMessageWithKeyboard(page: Page, prompt: string): Promise<void> {
  const admission = page.waitForResponse(
    (response) => response.url().includes("/messages") && response.request().method() === "POST",
  );
  const composer = page.getByRole("textbox", { name: "Message" });
  await composer.focus();
  await page.keyboard.type(prompt);
  await page.keyboard.press("Enter");
  const response = await admission;
  await classifyBrowser404(response, "session message admission");
  expect(response.status()).toBe(202);
  await expect(page.getByText("Message accepted; waiting for durable completion.", { exact: true })).toBeVisible();
}

function observeEventRequests(page: Page, topology?: Topology): BrowserSseRequest[] {
  const requests: BrowserSseRequest[] = [];
  const byPlaywrightRequest = new Map<Request, BrowserSseRequest>();
  page.on("request", (request) => {
    const url = new URL(request.url());
    const path = url.pathname;
    if (!path.endsWith("/events")) return;
    const match = path.match(/^\/v1\/endpoints\/([^/]+)\/sessions\/([^/]+)\/events$/);
    if (match === null) {
      throw new Error(`browser SSE request used a non-Endpoint-scoped path: ${path}`);
    }
    const headers = request.headers();
    const observed = {
      method: request.method(),
      path,
      endpointId: match[1],
      sessionId: match[2],
      requestId: headers[REQUEST_ID_HEADER] ?? "",
      lastEventId: headers["last-event-id"] ?? "",
    };
    requests.push(observed);
    byPlaywrightRequest.set(request, observed);
    topology?.recordSession(observed.sessionId);
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
  sessionId: string,
  lastEventId: string,
): BrowserSseRequest[] {
  return requests.filter(
    (request) =>
      request.method === "GET" &&
      request.path === `/v1/endpoints/${endpointId}/sessions/${sessionId}/events` &&
      request.endpointId === endpointId &&
      request.sessionId === sessionId &&
      request.lastEventId === lastEventId,
  );
}

async function waitForExactBrowserSseRequest(
  requests: BrowserSseRequest[],
  endpointId: string,
  sessionId: string,
  lastEventId: string,
  label: string,
): Promise<BrowserSseRequest> {
  await expect
    .poll(
      () => matchingBrowserSseRequests(requests, endpointId, sessionId, lastEventId).length,
      { timeout: 15_000, message: `${label} did not arrive at the browser boundary` },
    )
    .toBe(1);
  const matches = matchingBrowserSseRequests(requests, endpointId, sessionId, lastEventId);
  if (matches.length !== 1) throw new Error(`${label} was not a single exact browser SSE request`);
  if (matches[0].requestId.length === 0) throw new Error(`${label} omitted ${REQUEST_ID_HEADER}`);
  return matches[0];
}

function assertExactSseCorrelation(
  topology: Topology,
  browserRequest: BrowserSseRequest,
  endpointRequest: EndpointBoundaryRequest,
): void {
  assertSseBoundaryPair(browserRequest, endpointRequest);
  expect(browserRequest.endpointId).toBe(topology.endpointId);
  expect(browserRequest.path).toBe(
    `/v1/endpoints/${topology.endpointId}/sessions/${browserRequest.sessionId}/events`,
  );
  expect(browserRequest.requestId).toBe(topology.sseRequestId);
}

function assertSseBoundaryPair(
  browserRequest: BrowserSseRequest,
  endpointRequest: EndpointBoundaryRequest,
): void {
  expect(browserRequest.method).toBe("GET");
  expect(browserRequest.path).toBe(`/v1/endpoints/${browserRequest.endpointId}/sessions/${browserRequest.sessionId}/events`);
  expect(endpointRequest.requestId).toBe(browserRequest.requestId);
  expect(endpointRequest.forwardedRequestId).toBe(browserRequest.requestId);
  expect(endpointRequest.lastEventId).toBe(browserRequest.lastEventId);
  expect(endpointRequest.forwardedLastEventId).toBe(browserRequest.lastEventId);
  expect(endpointRequest.path).toBe(`/v1/sessions/${browserRequest.sessionId}/events`);
}

async function recordSseResponseMarkers(
  topology: Topology,
  requests: BrowserSseRequest[],
  sessionId: string,
  label: string,
): Promise<void> {
  await expect
    .poll(
      () => requests.filter((request) => request.sessionId === sessionId).length,
      { timeout: 15_000, message: `${label} did not open a browser SSE request` },
    )
    .toBeGreaterThan(0);
  await expect
    .poll(
      () => requests.filter((request) => request.sessionId === sessionId).every((request) => request.status !== undefined),
      { timeout: 15_000, message: `${label} did not receive browser SSE response statuses` },
    )
    .toBe(true);
  const browserRequests = requests.filter((request) => request.sessionId === sessionId && request.status === 200);
  if (browserRequests.length === 0) throw new Error(`${label} did not receive a successful browser SSE response`);
  const emittedEventIds = new Set<string>();
  for (const browserRequest of browserRequests) {
    const endpointRequest = await topology.endpointBoundary.waitForEventRequest(
      sessionId,
      browserRequest.lastEventId,
      browserRequest.requestId,
    );
    assertSseBoundaryPair(browserRequest, endpointRequest);
    if (browserRequest.lastEventId.length > 0 && !emittedEventIds.has(browserRequest.lastEventId)) {
      throw new Error(`${label} sent a Last-Event-ID that was not emitted by an earlier Endpoint SSE id field`);
    }
    const eventIds = await topology.endpointBoundary.waitForResponseEventIds(
      endpointRequest,
      `${label} response ${browserRequest.requestId}`,
    );
    topology.recordEventIds(eventIds);
    for (const eventId of eventIds) emittedEventIds.add(eventId);
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
    );
  });

  test.afterAll(() => {
    const behaviorConsumptions = suiteTopologyConsumptions.filter(
      (topologyConsumption) => topologyConsumption.expectedSequences.length > 0,
    );
    if (suiteSawShallow404 || behaviorConsumptions.length !== 4 || suiteExpectedSequences === undefined) return;
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
    if (canonicalJson(flattened) !== canonicalJson(suiteExpectedSequences)) {
      throw new Error(
        `provider cassette suite consumed ordered exchanges ${flattened.length}/${suiteExpectedSequences.length}`,
      );
    }
    for (const sequence of suiteExpectedSequences) {
      if ((counts.get(sequence) ?? 0) !== 1) {
        throw new Error(`provider cassette suite exchange ${sequence} was consumed ${counts.get(sequence) ?? 0} times`);
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
    await bootstrap(page, topology);
    const sseRequests = observeEventRequests(page, topology);
    const sessionId = await createSessionWithKeyboard(page, topology);
    const browserSse = await waitForExactBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      "",
      "server-store-scan initial browser SSE",
    );
    const endpointSse = await topology.endpointBoundary.waitForEventRequest(
      sessionId,
      "",
      browserSse.requestId,
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
        topology.assertServerStoreHasNoSessionMirror(),
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
    await bootstrap(page, topology);
    const sseRequests = observeEventRequests(page, topology);
    topology.expectScenario(SCENARIOS.keyboard, 1);
    await createSessionWithKeyboard(page, topology);
    await sendMessageWithKeyboard(page, `keyboard path ${SCENARIOS.keyboard}`);
    await topology.provider.waitForScenario(SCENARIOS.keyboard);
    await expectOneDurableFinal(page, "KEYBOARD_FINAL");
    const sessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.reconnect, 2);
    await sendMessageWithKeyboard(page, `reconnect path ${SCENARIOS.reconnect}`);
    await topology.provider.waitForScenario(SCENARIOS.reconnect);
    const initialBrowserRequest = await waitForExactBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      "",
      "initial browser SSE",
    );
    const initialEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
      sessionId,
      "",
      initialBrowserRequest.requestId,
    );
    assertExactSseCorrelation(topology, initialBrowserRequest, initialEndpointRequest);
    const initialEventIds = await topology.endpointBoundary.waitForResponseEventIds(
      initialEndpointRequest,
      "reconnect initial Endpoint SSE",
    );
    topology.recordEventIds(initialEventIds);
    await expect(page.getByText("PROVISIONAL_TOKEN", { exact: true })).toBeVisible();
    await expect(page.getByText("Message accepted", { exact: true })).toBeVisible();
    await expect
      .poll(
        () =>
          sseRequests
            .filter((request) => request.sessionId === sessionId && request.lastEventId.length > 0)
            .at(-1)?.lastEventId ?? "",
        {
          timeout: 15_000,
          message: "browser did not expose the durable pre-outage event cursor",
        },
      )
      .toMatch(/^[0-9]+$/);
    const originalCursor =
      sseRequests
        .filter((request) => request.sessionId === sessionId && request.lastEventId.length > 0)
        .at(-1)?.lastEventId ?? "";
    expect(initialEventIds).toContain(originalCursor);
    topology.recordCursor(originalCursor);
    const cursorCountBeforeOutage = sseRequests.length;
    await topology.server.stop();
    await topology.assertServerStoreHasNoSessionMirror();
    await expect(page.getByText(/Server unavailable/i)).toBeVisible();
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
            .find((request) => request.sessionId === sessionId && request.lastEventId.length > 0)?.lastEventId ?? "",
        {
          timeout: 15_000,
          message: "browser did not reconnect the session SSE with Last-Event-ID",
        },
      )
      .toBe(originalCursor);
    const resumedBrowserRequest = await waitForExactBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      originalCursor,
      "reconnected browser SSE",
    );
    const resumedEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
      sessionId,
      originalCursor,
      resumedBrowserRequest.requestId,
    );
    expect(resumedBrowserRequest.path).toBe(
      `/v1/endpoints/${topology.endpointId}/sessions/${sessionId}/events`,
    );
    expect(resumedBrowserRequest.requestId).toBe(resumedRequestId);
    assertExactSseCorrelation(topology, resumedBrowserRequest, resumedEndpointRequest);
    topology.provider.release("reconnect-final");
    const resumedEventIds = await topology.endpointBoundary.waitForResponseEventIds(
      resumedEndpointRequest,
      "reconnect resumed Endpoint SSE",
    );
    topology.recordEventIds(resumedEventIds);
    await expectOneDurableFinal(page, "DURABLE_FINAL");
    await expect(page.getByText("PROVISIONAL_TOKEN", { exact: true })).toHaveCount(0);
    await recordSseResponseMarkers(topology, sseRequests, sessionId, "reconnect all runtime state");
    expect(sseRequests[0]?.lastEventId).toBe("");
    expect(topology.provider.count(SCENARIOS.reconnect)).toBe(2);
  });

  test("e2e_browser_offline_state_distinguishes_server_outage_from_endpoint_unreachable", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    await bootstrap(page, topology);
    const sseRequests = observeEventRequests(page, topology);
    const sessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.offline, 1);
    await sendMessageWithKeyboard(page, `offline path ${SCENARIOS.offline}`);
    await expectOneDurableFinal(page, "OFFLINE_FINAL");
    const initialBrowserRequest = await waitForExactBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      "",
      "offline initial browser SSE",
    );
    const initialEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
      sessionId,
      "",
      initialBrowserRequest.requestId,
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
          sseRequests
            .filter((request) => request.lastEventId.length > 0)
            .at(-1)?.lastEventId ?? "",
        {
          timeout: 15_000,
          message: "offline session did not expose its durable event cursor",
        },
      )
      .toMatch(/^[0-9]+$/);
    const originalCursor = sseRequests.filter((request) => request.lastEventId.length > 0).at(-1)?.lastEventId ?? "";
    expect(initialEventIds).toContain(originalCursor);
    topology.recordCursor(originalCursor);
    const cursorCountBeforeServerOutage = sseRequests.length;
    await topology.server.stop();
    await topology.assertServerStoreHasNoSessionMirror();
    await expect(page.getByText(/Server unavailable/i)).toBeVisible();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toHaveCount(0);
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await topology.server.restart();
    await expect
      .poll(
        () =>
          sseRequests
            .slice(cursorCountBeforeServerOutage)
            .find((request) => request.lastEventId.length > 0)?.lastEventId ?? "",
        {
          timeout: 15_000,
          message: "Server outage recovery did not resume with the original cursor",
        },
      )
      .toBe(originalCursor);
    const resumedBrowserRequest = await waitForExactBrowserSseRequest(
      sseRequests,
      topology.endpointId,
      sessionId,
      originalCursor,
      "offline resumed browser SSE",
    );
    const resumedEndpointRequest = await topology.endpointBoundary.waitForEventRequest(
      sessionId,
      originalCursor,
      resumedBrowserRequest.requestId,
    );
    assertExactSseCorrelation(topology, resumedBrowserRequest, resumedEndpointRequest);
    const resumedEventIds = await topology.endpointBoundary.waitForResponseEventIds(
      resumedEndpointRequest,
      "offline resumed Endpoint SSE",
    );
    topology.recordEventIds(resumedEventIds);
    await expectOneDurableFinal(page, "OFFLINE_FINAL");
    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible();
    await expect(page.getByText(/Server unavailable/i)).toHaveCount(0);
    await expect(page.getByText(/non-authoritative/i)).toBeVisible();
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await expectOneDurableFinal(page, "OFFLINE_FINAL");
    await expect(page.getByRole("button", { name: "Send message" })).toBeDisabled();
    expect(sseRequests[0]?.lastEventId).toBe("");
    await topology.endpoint.restart();
    await expect(page.getByText(/Endpoint online/i)).toBeVisible();
    await recordSseResponseMarkers(topology, sseRequests, sessionId, "offline all runtime state");
  });

  test("e2e_browser_async_tool_wait_timeout_cancel_and_unknown_outcome_gate_safe_actions", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    await bootstrap(page, topology);
    const sseRequests = observeEventRequests(page, topology);
    const cancelSessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.cancel, 1);
    await sendMessageWithKeyboard(page, `cancel path ${SCENARIOS.cancel}`);
    await topology.provider.waitForScenario(SCENARIOS.cancel);
    await topology.tools.waitFor("cancel");
    const cancelRow = page.getByRole("listitem", { name: new RegExp(`${TOOL}.*running`, "i") });
    await expect(cancelRow).toBeVisible();
    await expect(cancelRow.getByRole("button", { name: "Cancel tool" })).toBeEnabled();
    await cancelRow.getByRole("button", { name: "Cancel tool" }).click();
    await expect(cancelRow).toContainText(/cancelled/i);
    await expect(cancelRow.getByRole("button", { name: "Retry dispatch" })).toHaveCount(0);
    await recordSseResponseMarkers(topology, sseRequests, cancelSessionId, "cancel runtime state");
    const waitSessionId = await createSessionWithKeyboard(page, topology);
    await sendMessageWithKeyboard(page, `wait path ${SCENARIOS.waitTimeout}`);
    topology.expectScenario(SCENARIOS.waitTimeout, 2);
    await topology.provider.waitForScenario(SCENARIOS.waitTimeout);
    await expect(page.getByText(/Waiting.*deadline/i)).toBeVisible();
    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible();
    await expect(page.getByText(/Server unavailable/i)).toHaveCount(0);
    await expect(page.getByText(/Waiting.*deadline/i)).toBeVisible();
    await expect(page.getByText(/timed out/i)).toHaveCount(0);
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await topology.endpoint.restart();
    await expect(page.getByText(/Endpoint online/i)).toBeVisible();
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
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible();
    await expect(page.getByText(/Server unavailable/i)).toHaveCount(0);
    await expect(runningUnknownRow).toContainText(/running/i);
    await expect(page.getByText("Agent failed", { exact: true })).toHaveCount(0);
    await topology.endpoint.restart();
    const unknownRow = page.getByRole("listitem", { name: new RegExp(`${TOOL}.*unknown outcome`, "i") });
    await expect(unknownRow).toBeVisible();
    await expect(unknownRow).toContainText(/Unable to determine tool outcome/i);
    await expect(unknownRow.getByRole("button", { name: "Cancel tool" })).toHaveCount(0);
    await expect(unknownRow.getByRole("button", { name: "Mark failed" })).toHaveCount(0);
    await expect(unknownRow.getByRole("button", { name: "Reconcile tool outcome" })).toBeEnabled();
    await recordSseResponseMarkers(topology, sseRequests, unknownSessionId, "unknown-outcome runtime state");
  });

  test("e2e_browser_mobile_collapsed_activity_rail_keeps_current_wait_tool_error_state", async ({ page }) => {
    if (topology === undefined) throw new Error("test topology did not start");
    await bootstrap(page, topology);
    const sseRequests = observeEventRequests(page, topology);
    const sessionId = await createSessionWithKeyboard(page, topology);
    topology.expectScenario(SCENARIOS.mobile, 1);
    await sendMessageWithKeyboard(page, `mobile path ${SCENARIOS.mobile}`);
    await topology.provider.waitForScenario(SCENARIOS.mobile);
    await topology.tools.waitFor("unknown");
    await topology.endpoint.stop();
    await topology.assertEndpointUnreachableBarrier();
    await expect(page.getByText(/Endpoint (unreachable|unavailable)/i)).toBeVisible();
    await topology.endpoint.restart();
    await expect(page.getByText(/Waiting.*deadline/i)).toBeVisible();
    const unknownOutcomeRow = page.getByRole("listitem", { name: new RegExp(`${TOOL}.*unknown outcome`, "i") });
    await expect(unknownOutcomeRow).toBeVisible();
    await expect(unknownOutcomeRow).toContainText(/Unable to determine tool outcome/i);
    const widths = [320, 375, 414, 768];
    for (const width of widths) {
      await page.setViewportSize({ width, height: 800 });
      const toggle = page.getByRole("button", { name: "Activity" });
      if (await toggle.getAttribute("aria-expanded") === "true") {
        await toggle.focus();
        await page.keyboard.press("Enter");
      }
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
      await toggle.focus();
      await page.keyboard.press("Enter");
      const rail = page.getByRole("complementary", { name: "Activity" });
      await expect(rail).toBeVisible();
      await expect(rail.getByText(/deadline/i)).toBeVisible();
      await expect(rail.getByText(/unknown[_ ]outcome/i)).toBeVisible();
      await expect(rail.getByRole("alert")).toContainText("Unable to determine tool outcome");
      await expect(rail.getByRole("button", { name: "Reconcile tool outcome" })).toBeEnabled();
      await expect(rail.getByRole("button", { name: "Cancel tool" })).toHaveCount(0);
      await expect(rail.getByRole("button", { name: "Mark failed" })).toHaveCount(0);
      await toggle.focus();
      await page.keyboard.press("Enter");
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
    }
    await recordSseResponseMarkers(topology, sseRequests, sessionId, "mobile runtime state");
  });
});
