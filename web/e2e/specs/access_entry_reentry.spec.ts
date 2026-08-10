import { test, expect, type BrowserContext, type Page, type TestInfo } from "@playwright/test";
import { createHash, createSign, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { access, chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const SPEC_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = process.env.ZODE_REPO_ROOT ?? resolve(SPEC_DIR, "../../..");
const require = createRequire(import.meta.url);
const { ProductBehaviorFailure, RealProcess: CapturedRealProcess, RecordingJournal, SecretLedger } = require("../support/harness.cjs") as {
  ProductBehaviorFailure: new (classification: string, message: string, details?: Record<string, unknown>) => Error;
  RealProcess: {
    start: (options: Record<string, unknown>) => Promise<CapturedProcess>;
  };
  RecordingJournal: new (options: { rootDir: string; ledger: SecretLedgerContract }) => RecordingJournalContract;
  SecretLedger: new () => SecretLedgerContract;
};
const FIXTURE_ROOT = resolve(REPO_ROOT, "web/e2e/fixtures/access_entry_reentry");
const ENTRY_CASSETTE_PATH = join(FIXTURE_ROOT, "management-entry-first-failure.v1.json");
const REENTRY_CASSETTE_PATH = join(FIXTURE_ROOT, "browser-access-reentry-first-failure.v1.json");
const SHALLOW_CLASSIFICATION_PATH = join(FIXTURE_ROOT, "shallow-non-evidence.v1.json");
const ACCESS_AUDIENCE = "zode-management-web-e2e";
const ACCESS_KID = "access-entry-e2e";
const ACCESS_SUBJECT = "synthetic-human-access-entry-e2e";
const ACCESS_EMAIL = "synthetic-access-entry@example.invalid";
const VIEW_STATE_PATH = process.env.ZODE_ACCESS_VIEW_PATH ?? "/?view=sessions";
const MUTATION_TEXT = "non-secret-access-entry-view-state";
const EXPIRY_E2E_NAME = "e2e_browser_access_reentry_stops_mutations_and_uses_management_origin";
const EXPIRY_LATER_RELATION = "later_test_reproduction_of_gap";
const EXPIRY_ORIGINAL_GAP = "access-assertion-expiry-sse-first-occurrence-gap";
const SESSION_ACCESS_REENTRY_E2E_NAME =
  "e2e_browser_access_401_reentry_is_not_endpoint_unavailable";
const SESSION_ACCESS_REENTRY_CLASSIFICATION =
  "ACCESS_REENTRY_401_RENDERED_AS_ENDPOINT_UNAVAILABLE";
const SESSION_ACCESS_REENTRY_FIRST_OBSERVED =
  "the real Access edge returned HTTP 401 for a session read, but the browser rendered Endpoint unavailable instead of re-entering Access";
const SSE_ACCESS_REENTRY_E2E_NAME =
  "e2e_browser_sse_401_reenters_management_origin_and_stops_retries";
const SSE_ACCESS_REENTRY_CLASSIFICATION =
  "ACCESS_REENTRY_SSE_401_RECONNECT_LOOP";
const SSE_ACCESS_REENTRY_FIRST_OBSERVED =
  "the real Access edge returned HTTP 401 for a session event stream, but the browser kept retrying instead of re-entering Access";
const INCIDENT_DIRECTORY = resolve(REPO_ROOT, "web/e2e/fixtures/incidents");
const execFileAsync = promisify(execFile);

type AccessMode = "valid" | "expired" | "invalid" | "expiring";
type SemanticHeader = { name: string; value: string };
type ResponseChunk = { offset_us: number; body_hex: string };
type SignedAssertion = {
  token: string;
  expiresAtMs: number;
};

type CapturedProcess = {
  baseUrl?: string;
  stop: () => Promise<unknown>;
};

type SecretLedgerContract = {
  add: (label: string, value: string) => void;
};

type RecordingJournalContract = {
  beginCaptureSet: (options: { e2eName: string; maxMembers?: number }) => string;
  waitForIdle: () => Promise<void>;
  beginIngress: (options: {
    boundary: string;
    method: string;
    requestPath: string;
    requestHeaders: Record<string, unknown>;
    captureSetId: string;
  }) => unknown;
  ingressChunk: (context: unknown, data: Buffer) => void;
  endIngress: (context: unknown) => Buffer;
  updateIngressHeaders: (context: unknown, requestHeaders: Record<string, unknown>) => void;
  responseStarted: (context: unknown, response: { status: number; headers: Record<string, string> }) => void;
  chunk: (context: unknown, data: Buffer, offsetUs: number) => void;
  finish: (context: unknown, outcome: string) => unknown;
  first: (options: {
    boundary?: string;
    requestPath?: string;
    responseStatus?: number;
    captureSetId?: string;
  }) => { recordingId: string } | undefined;
  flushCaptureSet: (
    captureSetId: string,
    options?: { firstFailureRecordingId?: string },
  ) => { records?: Array<{ recordingId: string; rawPath?: string }>; sourceDigest?: string };
  replay: (envelope: unknown, options: Record<string, unknown>) => Promise<unknown>;
  promoteCaptureSet: (
    captureSetId: string,
    options: {
      e2eName: string;
      classification: string;
      firstObserved: string;
      firstFailureRecordingId: string;
      destinationDirectory: string;
      replay: (envelope: unknown) => Promise<unknown>;
    },
  ) => Promise<{ cassettePath: string }>;
};

type Cassette = {
  schema: "zode.http-incident-recording.v1";
  version: 1;
  recording_id: string;
  purpose: string;
  owner: string;
  boundary: string;
  secret_slots: string[];
  first_observed_outcome: {
    sequence: number;
    status: number;
    safe_error: string;
  };
  target_contract: {
    status: number;
    browser_observable: string;
  };
  exchanges: Array<{
    sequence: number;
    request: {
      method: string;
      path: string;
      semantic_headers: Array<{ name: string; value: string }>;
      raw_body_hex: string;
      body_sha256: string;
    };
    recorded_response: {
      status: number;
      semantic_headers: Array<{ name: string; value: string }>;
      chunks: Array<{ offset_us: number; body_hex: string }>;
      completed: boolean;
      termination: string;
      body_sha256: string;
    };
  }>;
  whole_digest: string;
};

type ShallowNonEvidenceSource = {
  cassette: string;
  owner: string;
  path: string;
  first_observed_outcome: {
    sequence: number;
    status: number;
    safe_error: string;
  };
  recorded_response: {
    status: number;
    body_sha256: string;
  };
  target_status: number;
  cassette_digest: string;
};

type ShallowNonEvidenceFixture = {
  schema: "zode.access-entry-shallow-non-evidence.v1";
  version: 1;
  classification: "PRODUCT_ROUTE_MISSING_SHALLOW_404";
  evidence_status: "shallow_non_evidence";
  non_evidence: true;
  replay_policy: {
    boundary: "browser->management-origin";
    shallow_404_is_non_evidence: true;
    readiness_is_non_evidence: true;
    continue_only_after_status: 200;
  };
  sources: ShallowNonEvidenceSource[];
  whole_digest: string;
};

type WireExchange = {
  sequence: number;
  method: string;
  path: string;
  requestSemanticHeaders: SemanticHeader[];
  headerNames: string[];
  bodySha256: string;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseChunks: ResponseChunk[];
  responseCompleted: boolean;
  responseTermination: string;
  responseBodySha256: string;
};

type SseExchange = WireExchange & {
  lastEventId: string;
  eventIds: string[];
  assertionExpiresAtMs: number;
  openedAtMs: number;
  closedAtMs: number;
};

class ShallowNonEvidence extends Error {
  readonly classification = "PRODUCT_ROUTE_MISSING_SHALLOW_404" as const;
  readonly nonEvidence = true as const;

  constructor(readonly path: string, readonly status: number, detail: string) {
    super(
      `BLOCKED_SHALLOW_404: ${path} is still HTTP ${status}; ${detail}; this is non-evidence for Access UI behavior`,
    );
    this.name = "ShallowNonEvidence";
  }
}

class ReadinessNonEvidence extends Error {
  readonly classification = "REAL_PROCESS_READINESS_NON_EVIDENCE" as const;
  readonly nonEvidence = true as const;

  constructor() {
    super("BLOCKED_READINESS: the real Server/Endpoint process did not reach readiness; this is non-evidence for Access UI behavior");
    this.name = "ReadinessNonEvidence";
  }
}

const SHALLOW_NON_EVIDENCE_SOURCES = Object.freeze([
  Object.freeze({
    cassette: "management-entry-first-failure.v1.json",
    owner: "e2e_access_entry_reentry_through_real_access_edge",
    path: "/",
    first_observed_outcome: Object.freeze({
      sequence: 1,
      status: 404,
      safe_error: "management_ui_bootstrap_not_found",
    }),
    recorded_response: Object.freeze({
      status: 404,
      body_sha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }),
    target_status: 200,
    cassette_digest: "sha256:31b9d43c4d650a23f7090088a47900aa19e560dfd478962ede0235c9e5921f3f",
  }),
  Object.freeze({
    cassette: "browser-access-reentry-first-failure.v1.json",
    owner: "e2e_browser_access_reentry_stops_mutations_and_uses_management_origin",
    path: "/?view=sessions",
    first_observed_outcome: Object.freeze({
      sequence: 1,
      status: 404,
      safe_error: "management_ui_bootstrap_not_found",
    }),
    recorded_response: Object.freeze({
      status: 404,
      body_sha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }),
    target_status: 200,
    cassette_digest: "sha256:24d486e36f1feeb09d17663a3a585b577d8a70aa8bd03b97c988ce8a21dc6633",
  }),
] as const);
const SHALLOW_CLASSIFICATION_DIGEST =
  "sha256:9e1c9e774168dbfd347e7d7336cb8712881324af5ded206214e0e3b51679f82c";

function annotateNonEvidence(testInfo: TestInfo, classification: string, description: string): void {
  testInfo.annotations.push({
    type: "failure-classification",
    description: `${classification}; evidence_status=non_evidence_only; ${description}`,
  });
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function cassetteDigest(value: unknown): string {
  return `sha256:${sha256(canonicalJson(value))}`;
}

async function loadShallowClassification(): Promise<ShallowNonEvidenceFixture> {
  const fixture = JSON.parse(await readFile(SHALLOW_CLASSIFICATION_PATH, "utf8")) as ShallowNonEvidenceFixture;
  const { whole_digest: _digest, ...withoutDigest } = fixture;
  expect(fixture.schema).toBe("zode.access-entry-shallow-non-evidence.v1");
  expect(fixture.version).toBe(1);
  expect(fixture.classification).toBe("PRODUCT_ROUTE_MISSING_SHALLOW_404");
  expect(fixture.evidence_status).toBe("shallow_non_evidence");
  expect(fixture.non_evidence).toBe(true);
  expect(fixture.replay_policy).toEqual({
    boundary: "browser->management-origin",
    shallow_404_is_non_evidence: true,
    readiness_is_non_evidence: true,
    continue_only_after_status: 200,
  });
  expect(fixture.sources).toEqual(SHALLOW_NON_EVIDENCE_SOURCES);
  expect(fixture.whole_digest).toBe(SHALLOW_CLASSIFICATION_DIGEST);
  expect(fixture.whole_digest).toBe(cassetteDigest(withoutDigest));
  return fixture;
}

function classificationSource(cassette: string): ShallowNonEvidenceSource {
  const source = SHALLOW_NON_EVIDENCE_SOURCES.find((candidate) => candidate.cassette === cassette);
  if (!source) throw new Error(`no immutable shallow-non-evidence source for ${cassette}`);
  return source;
}

function assertManagementUiResponse(
  response: { status(): number } | null,
  path: string,
  testInfo: TestInfo,
  expectedStatus = 200,
): void {
  const status = response?.status();
  if (status === 404) {
    const error = new ShallowNonEvidence(
      path,
      status,
      "the real management Server UI route is not bootstrapped",
    );
    annotateNonEvidence(testInfo, error.classification, error.message);
    testInfo.skip(true, error.message);
    return;
  }
  expect(status).toBe(expectedStatus);
}

async function loadCassette(path: string, expected: ShallowNonEvidenceSource): Promise<Cassette> {
  const cassette = JSON.parse(await readFile(path, "utf8")) as Cassette;
  const { whole_digest: _digest, ...withoutDigest } = cassette;
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.owner).toBe(expected.owner);
  expect(cassette.boundary).toBe("browser->management-origin");
  expect(cassette.target_contract.status).toBe(expected.target_status);
  expect(cassette.exchanges).toHaveLength(1);
  expect(cassette.exchanges.map((exchange) => exchange.sequence)).toEqual([1]);
  expect(cassette.whole_digest).toBe(cassetteDigest(withoutDigest));
  expect(cassette.whole_digest).toBe(expected.cassette_digest);
  expect(cassette.first_observed_outcome).toEqual(expected.first_observed_outcome);

  const firstExchange = cassette.exchanges[0];
  if (!firstExchange) throw new Error(`cassette ${expected.cassette} has no first exchange`);
  expect(firstExchange.sequence).toBe(expected.first_observed_outcome.sequence);
  expect(firstExchange.request.path).toBe(expected.path);
  expect(firstExchange.recorded_response.status).toBe(expected.recorded_response.status);
  expect(firstExchange.recorded_response.body_sha256).toBe(expected.recorded_response.body_sha256);
  expect(firstExchange.request.raw_body_hex).toMatch(/^(?:[0-9a-f]{2})*$/i);
  expect(`sha256:${sha256(Buffer.from(firstExchange.request.raw_body_hex, "hex"))}`).toBe(firstExchange.request.body_sha256);
  expect(firstExchange.request.semantic_headers).toEqual(
    firstExchange.request.semantic_headers.map((header) => ({
      name: header.name.toLowerCase(),
      value: header.value,
    })),
  );
  expect(new Set(firstExchange.request.semantic_headers.map((header) => header.name)).size).toBe(
    firstExchange.request.semantic_headers.length,
  );
  expect(firstExchange.recorded_response.semantic_headers).toEqual(
    [...firstExchange.recorded_response.semantic_headers].sort((left, right) => left.name.localeCompare(right.name)),
  );
  expect(new Set(firstExchange.recorded_response.semantic_headers.map((header) => header.name)).size).toBe(
    firstExchange.recorded_response.semantic_headers.length,
  );
  expect(firstExchange.recorded_response.chunks).toEqual(
    [...firstExchange.recorded_response.chunks].sort((left, right) => left.offset_us - right.offset_us),
  );
  expect(firstExchange.recorded_response.chunks.every((chunk) => chunk.offset_us >= 0)).toBe(true);
  expect(firstExchange.recorded_response.chunks.every((chunk) => /^[0-9a-f]*$/i.test(chunk.body_hex))).toBe(true);
  expect(firstExchange.recorded_response.completed).toBe(true);
  expect(firstExchange.recorded_response.termination).toBe("complete");
  expect(`sha256:${sha256(responseBodyFromChunks(firstExchange.recorded_response.chunks))}`).toBe(
    firstExchange.recorded_response.body_sha256,
  );

  const serialized = JSON.stringify(cassette);
  expect(serialized).not.toMatch(/eyJ[a-zA-Z0-9_-]{20,}/);
  expect(serialized).not.toMatch(/-----BEGIN|access[_-]?token|refresh[_-]?token/i);
  for (const exchange of cassette.exchanges) {
    expect(exchange.request.raw_body_hex).toBe("");
    expect(exchange.request.semantic_headers).toContainEqual({ name: "cf-access-jwt-assertion", value: "${ACCESS_ASSERTION}" });
    expect(exchange.recorded_response.semantic_headers.map((header) => header.name.toLowerCase())).not.toContain("set-cookie");
  }
  return cassette;
}

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

type SigningKey = ReturnType<typeof generateKeyPairSync>;

function signAccessJwt(keys: SigningKey, mode: AccessMode): SignedAssertion {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = mode === "expired" ? now - 3600 : mode === "expiring" ? now + 4 : now + 300;
  const payload = {
    iss: accessFixtureIssuer,
    aud: [ACCESS_AUDIENCE],
    sub: ACCESS_SUBJECT,
    email: ACCESS_EMAIL,
    type: "app",
    nbf: now - 30,
    exp: expiresAt,
  };
  const encodedHeader = base64Url(JSON.stringify({ alg: "RS256", kid: ACCESS_KID, typ: "JWT" }));
  const encodedPayload = base64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return {
    token: `${signingInput}.${signer.sign(keys.privateKey).toString("base64url")}`,
    expiresAtMs: expiresAt * 1000,
  };
}

let accessFixtureIssuer = "";

async function listen(server: ReturnType<typeof createServer>): Promise<string> {
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture did not receive a TCP address");
  return `http://127.0.0.1:${address.port}`;
}

async function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
}

async function readRequestBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > 2 * 1024 * 1024) throw new Error("fixture request body exceeds bound");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

const SEMANTIC_REQUEST_HEADER_NAMES = new Set(["cf-access-jwt-assertion", "content-type", "last-event-id"]);

function canonicalRequestSemanticHeaders(
  headers: Record<string, string | string[] | undefined>,
): SemanticHeader[] {
  return Object.entries(headers)
    .flatMap(([rawName, rawValue]) => {
      const name = rawName.toLowerCase();
      if (!SEMANTIC_REQUEST_HEADER_NAMES.has(name) || rawValue === undefined) return [];
      const values = Array.isArray(rawValue) ? rawValue : [rawValue];
      return values.map((value) => ({
        name,
        value: name === "cf-access-jwt-assertion" ? "${ACCESS_ASSERTION}" : value,
      }));
    })
    .sort((left, right) => left.name.localeCompare(right.name));
}

function responseHeaderSubset(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const allowed = ["content-length", "content-type", "cache-control", "location", "referrer-policy"];
  const result: Record<string, string> = {};
  for (const name of allowed) {
    const value = headers[name];
    if (typeof value === "string") result[name] = value;
  }
  return result;
}

function responseSemanticHeaders(headers: Record<string, string>): SemanticHeader[] {
  return Object.entries(headers)
    .map(([name, value]) => ({ name: name.toLowerCase(), value }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

function responseBodyFromChunks(chunks: ResponseChunk[]): Buffer {
  return Buffer.concat(
    chunks.map((chunk) => {
      if (!/^(?:[0-9a-f]{2})*$/i.test(chunk.body_hex)) {
        throw new Error(`response chunk is not complete hex at offset ${chunk.offset_us}`);
      }
      return Buffer.from(chunk.body_hex, "hex");
    }),
  );
}

function forwardHeaders(
  request: IncomingMessage,
  extraHeaders: Record<string, string>,
  body: Buffer,
): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (name === "host" || name === "connection" || name === "content-length") continue;
    if (typeof value === "string") headers[name] = value;
  }
  Object.assign(headers, extraHeaders);
  if (body.length > 0) headers["content-length"] = String(body.length);
  return headers;
}

function isMutation(request: IncomingMessage): boolean {
  return ["POST", "PUT", "PATCH", "DELETE"].includes((request.method ?? "GET").toUpperCase());
}

function isDocumentRequest(request: IncomingMessage): boolean {
  const destination = request.headers["sec-fetch-dest"];
  const accept = request.headers.accept ?? "";
  return request.method === "GET" && (destination === "document" || accept.includes("text/html"));
}

async function forwardRequest(
  request: IncomingMessage,
  response: ServerResponse,
  targetOrigin: string,
  extraHeaders: Record<string, string> = {},
  requestBody?: Buffer,
): Promise<{
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  chunks: ResponseChunk[];
  completed: boolean;
  termination: string;
}> {
  const body = requestBody ?? await readRequestBody(request);
  const target = new URL(request.url ?? "/", targetOrigin);
  const headers = forwardHeaders(request, extraHeaders, body);

  const result = await new Promise<{
    status: number;
    headers: Record<string, string>;
    body: Buffer;
    chunks: ResponseChunk[];
    completed: boolean;
    termination: string;
  }>((resolveForward, reject) => {
    const startedAt = performance.now();
    const targetRequest = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: request.method,
        headers,
      },
      (targetResponse: IncomingMessage) => {
        const chunks: Buffer[] = [];
        const responseChunks: ResponseChunk[] = [];
        targetResponse.on("data", (chunk: Buffer | string) => {
          const bytes = Buffer.from(chunk);
          chunks.push(bytes);
          responseChunks.push({
            offset_us: Math.round((performance.now() - startedAt) * 1000),
            body_hex: bytes.toString("hex"),
          });
        });
        targetResponse.on("end", () => {
          resolveForward({
            status: targetResponse.statusCode ?? 502,
            headers: responseHeaderSubset(targetResponse.headers),
            body: Buffer.concat(chunks),
            chunks: responseChunks,
            completed: true,
            termination: "complete",
          });
        });
        targetResponse.on("aborted", () => {
          resolveForward({
            status: targetResponse.statusCode ?? 502,
            headers: responseHeaderSubset(targetResponse.headers),
            body: Buffer.concat(chunks),
            chunks: responseChunks,
            completed: false,
            termination: "upstream_aborted",
          });
        });
      },
    );
    targetRequest.once("error", reject);
    targetRequest.end(body);
  });

  response.writeHead(result.status, result.headers);
  response.end(result.body);
  return result;
}

async function forwardStreamingRequest(
  request: IncomingMessage,
  response: ServerResponse,
  targetOrigin: string,
  extraHeaders: Record<string, string>,
  requestBody: Buffer,
  onOpen: (status: number, headers: Record<string, string>) => void,
  onChunk: (chunk: Buffer, offsetUs: number) => void,
  onClose: (completed: boolean, termination: string) => void,
): Promise<void> {
  const target = new URL(request.url ?? "/", targetOrigin);
  const headers = forwardHeaders(request, extraHeaders, requestBody);

  await new Promise<void>((resolveStream, rejectStream) => {
    const startedAt = performance.now();
    let settled = false;
    const finish = (completed: boolean, termination: string): void => {
      if (settled) return;
      settled = true;
      onClose(completed, termination);
      resolveStream();
    };
    const targetRequest = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: request.method,
        headers,
      },
      (targetResponse: IncomingMessage) => {
        const responseHeaders = responseHeaderSubset(targetResponse.headers);
        onOpen(targetResponse.statusCode ?? 502, responseHeaders);
        response.writeHead(targetResponse.statusCode ?? 502, responseHeaders);
        targetResponse.on("data", (chunk: Buffer) => {
          const bytes = Buffer.from(chunk);
          onChunk(bytes, Math.round((performance.now() - startedAt) * 1000));
          if (!response.writableEnded) response.write(bytes);
        });
        targetResponse.on("end", () => {
          if (!response.writableEnded) response.end();
          finish(true, "complete");
        });
        targetResponse.on("aborted", () => finish(false, "upstream_aborted"));
      },
    );
    targetRequest.once("error", (error: Error) => {
      if (!response.headersSent) rejectStream(error);
      else finish(false, "upstream_error");
    });
    response.once("close", () => {
      targetRequest.destroy();
      finish(false, "client_closed");
    });
    targetRequest.end(requestBody);
  });
}

class AccessEdgeFixture {
  readonly initialKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  readonly forgedKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  readonly exchanges: WireExchange[] = [];
  readonly mutationExchanges: WireExchange[] = [];
  readonly sseExchanges: SseExchange[] = [];
  private captureJournal: RecordingJournalContract | undefined;
  private captureSetId: string | undefined;
  private captureError: unknown;
  private readonly ingressByRequest = new WeakMap<IncomingMessage, unknown>();
  private readonly ingressByExchange = new WeakMap<WireExchange, unknown>();
  private forwardedAssertionCountValue = 0;
  private readonly server = createServer((request: IncomingMessage, response: ServerResponse) => {
    void this.handle(request, response).catch(() => {
      if (!response.headersSent) response.writeHead(500, { "content-type": "text/plain" });
      response.end();
    });
  });
  private mode: AccessMode = "valid";
  private targetOrigin = "";
  private holdNextMutation = false;
  private heldMutationResolve: (() => void) | undefined;
  private heldMutationPromise: Promise<void> | undefined;
  private heldMutationSeenResolve: (() => void) | undefined;
  private heldMutationSeen: Promise<void> | undefined;
  private sseOpenedResolve: (() => void) | undefined;
  private sseOpened: Promise<void> | undefined;
  private sseClosedResolve: (() => void) | undefined;
  private sseClosed: Promise<void> | undefined;
  private sseOpenedCountValue = 0;
  private expireNextMutation = false;
  private autoCompleteReentry = false;
  private reentryCountValue = 0;
  origin = "";

  setCapture(journal: RecordingJournalContract, captureSetId: string): void {
    this.captureJournal = journal;
    this.captureSetId = captureSetId;
  }

  assertCaptureHealthy(): void {
    if (this.captureError) throw this.captureError;
  }

  async start(): Promise<this> {
    this.origin = await listen(this.server);
    accessFixtureIssuer = `${this.origin}/`;
    return this;
  }

  setTarget(origin: string): void {
    this.targetOrigin = origin;
  }

  jwksUrl(): string {
    return `${this.origin}/cdn-cgi/access/certs`;
  }

  issuer(): string {
    return `${this.origin}/`;
  }

  async setMode(mode: AccessMode): Promise<void> {
    this.mode = mode;
    this.expireNextMutation = false;
  }

  enableAutoCompleteReentry(): void {
    this.autoCompleteReentry = true;
  }

  armSseLifecycle(): void {
    this.sseOpened = new Promise<void>((resolveOpened) => {
      this.sseOpenedResolve = resolveOpened;
    });
    this.sseClosed = new Promise<void>((resolveClosed) => {
      this.sseClosedResolve = resolveClosed;
    });
  }

  async waitForSseOpened(): Promise<void> {
    if (!this.sseOpened) throw new Error("SSE lifecycle was not armed");
    await this.sseOpened;
  }

  async waitForSseClosed(): Promise<void> {
    if (!this.sseClosed) throw new Error("SSE lifecycle was not armed");
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.sseClosed,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("ACCESS_ASSERTION_EXPIRY_SSE_NOT_CLOSED")), 8_000);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async waitForSseOpenedCount(count: number, timeoutMs = 8_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (this.sseOpenedCountValue < count) {
      if (Date.now() >= deadline) throw new Error(`ACCESS_SSE_RECONNECT_NOT_OPEN count=${count}`);
      await new Promise((resolveWait) => setTimeout(resolveWait, 25));
    }
  }

  reentryCount(): number {
    return this.reentryCountValue;
  }

  async armMutationBarrier(): Promise<void> {
    this.holdNextMutation = true;
    this.heldMutationPromise = new Promise<void>((resolveHeld) => {
      this.heldMutationResolve = resolveHeld;
    });
    this.heldMutationSeen = new Promise<void>((resolveSeen) => {
      this.heldMutationSeenResolve = resolveSeen;
    });
  }

  async waitForHeldMutation(): Promise<void> {
    if (!this.heldMutationSeen) throw new Error("mutation barrier was not armed");
    await this.heldMutationSeen;
  }

  async releaseHeldMutation(): Promise<void> {
    this.heldMutationResolve?.();
    this.heldMutationResolve = undefined;
    this.heldMutationPromise = undefined;
  }

  mutationAttemptCount(): number {
    return this.mutationExchanges.length;
  }

  forwardedAssertionCount(): number {
    return this.forwardedAssertionCountValue;
  }

  firstExchange(path: string): WireExchange | undefined {
    return this.exchanges.find((exchange) => exchange.path === path);
  }

  async reset(): Promise<void> {
    this.mode = "valid";
    this.holdNextMutation = false;
    this.heldMutationResolve?.();
    this.heldMutationResolve = undefined;
    this.heldMutationPromise = undefined;
    this.heldMutationSeenResolve = undefined;
    this.heldMutationSeen = undefined;
    this.sseOpenedResolve = undefined;
    this.sseOpened = undefined;
    this.sseClosedResolve = undefined;
    this.sseClosed = undefined;
    this.sseOpenedCountValue = 0;
    this.expireNextMutation = false;
    this.autoCompleteReentry = false;
    this.reentryCountValue = 0;
    this.exchanges.length = 0;
    this.mutationExchanges.length = 0;
    this.sseExchanges.length = 0;
    this.forwardedAssertionCountValue = 0;
  }

  async stop(): Promise<void> {
    // Force any long-lived SSE client sockets to emit `close` before waiting
    // for the listener itself.  Without this, a browser teardown can leave
    // the forwarding recorder context active even though the edge is no
    // longer accepting requests.
    (this.server as typeof this.server & { closeAllConnections?: () => void }).closeAllConnections?.();
    await closeServer(this.server);
  }

  private beginIngress(request: IncomingMessage): unknown {
    if (!this.captureJournal || !this.captureSetId) return undefined;
    try {
      const context = this.captureJournal.beginIngress({
        boundary: request.url?.startsWith("/cdn-cgi/access/certs")
          ? "access-jwks-fixture"
          : "management-access-edge",
        method: request.method ?? "GET",
        requestPath: request.url ?? "/",
        requestHeaders: request.headers,
        captureSetId: this.captureSetId,
      });
      this.ingressByRequest.set(request, context);
      return context;
    } catch (error) {
      this.captureError ||= error;
      throw error;
    }
  }

  private async readIngressBody(request: IncomingMessage, context: unknown): Promise<Buffer> {
    if (!context || !this.captureJournal) return readRequestBody(request);
    const chunks: Buffer[] = [];
    let length = 0;
    try {
      for await (const chunk of request) {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        length += bytes.length;
        if (length > 2 * 1024 * 1024) throw new Error("fixture request body exceeds bound");
        this.captureJournal.ingressChunk(context, bytes);
        chunks.push(bytes);
      }
      return this.captureJournal.endIngress(context);
    } catch (error) {
      this.captureError ||= error;
      throw error;
    }
  }

  private finishIngress(
    request: IncomingMessage,
    status: number,
    headers: Record<string, string>,
    chunks: Array<{ data: Buffer; offsetUs: number }>,
    outcome: string,
  ): void {
    const context = this.ingressByRequest.get(request);
    if (!context || !this.captureJournal) return;
    this.ingressByRequest.delete(request);
    try {
      this.captureJournal.responseStarted(context, { status, headers });
      for (const chunk of chunks) this.captureJournal.chunk(context, chunk.data, chunk.offsetUs);
      this.captureJournal.finish(context, outcome);
    } catch (error) {
      this.captureError ||= error;
    }
  }

  private captureExchange(
    exchange: WireExchange,
    requestHeaders: Record<string, unknown>,
  ): void {
    const context = this.ingressByExchange.get(exchange);
    if (!context || !this.captureJournal) return;
    this.ingressByExchange.delete(exchange);
    try {
      this.captureJournal.updateIngressHeaders(context, requestHeaders);
      this.captureJournal.responseStarted(context, {
        status: exchange.responseStatus || 502,
        headers: exchange.responseHeaders,
      });
      for (const chunk of exchange.responseChunks) {
        this.captureJournal.chunk(context, Buffer.from(chunk.body_hex, "hex"), chunk.offset_us);
      }
      const outcome = exchange.responseCompleted
        ? "completed"
        : exchange.responseTermination === "client_closed"
          ? "client_disconnected"
          : exchange.responseTermination === "upstream_error"
            ? "transport_error"
            : exchange.responseTermination === "upstream_aborted"
              ? "disconnected"
              : "timed_out";
      this.captureJournal.finish(context, outcome);
    } catch (error) {
      this.captureError ||= error;
    }
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const path = request.url ?? "/";
    const ingress = this.beginIngress(request);
    const body = await this.readIngressBody(request, ingress);
    if (path === "/__fixture/access/state" && request.method === "POST") {
      const state = JSON.parse(body.toString("utf8")) as { mode: AccessMode };
      await this.setMode(state.mode);
      const headers: Record<string, string> = {};
      response.writeHead(204, headers);
      response.end();
      this.finishIngress(request, 204, headers, [], "completed");
      return;
    }
    if (path.startsWith("/__fixture/access/reentry") && request.method === "GET") {
      const returnPath = new URL(path, `${this.origin}/`).searchParams.get("return") ?? "/";
      this.mode = "valid";
      const headers = { location: returnPath, "cache-control": "no-store" };
      response.writeHead(302, headers);
      response.end();
      this.finishIngress(request, 302, headers, [], "completed");
      return;
    }
    if (path === "/cdn-cgi/access/certs" && request.method === "GET") {
      const publicJwk = this.initialKeys.publicKey.export({ format: "jwk" }) as { n: string; e: string };
      const body = JSON.stringify({ keys: [{ kty: "RSA", kid: ACCESS_KID, use: "sig", alg: "RS256", n: publicJwk.n, e: publicJwk.e }] });
      const bytes = Buffer.from(body);
      const headers = { "content-type": "application/json", "cache-control": "no-store" };
      response.writeHead(200, headers);
      response.end(body);
      this.finishIngress(request, 200, headers, [{ data: bytes, offsetUs: 0 }], "completed");
      return;
    }

    const exchange: WireExchange = {
      sequence: this.exchanges.length + 1,
      method: request.method ?? "GET",
      path,
      requestSemanticHeaders: [],
      headerNames: Object.keys(request.headers).map((name) => name.toLowerCase()).sort(),
      bodySha256: `sha256:${sha256(body)}`,
      responseStatus: 0,
      responseHeaders: {},
      responseChunks: [],
      responseCompleted: false,
      responseTermination: "pending",
      responseBodySha256: "",
    };
    this.exchanges.push(exchange);
    if (ingress) this.ingressByExchange.set(exchange, ingress);
    if (isMutation(request)) this.mutationExchanges.push(exchange);

    if (isMutation(request) && this.holdNextMutation) {
      this.holdNextMutation = false;
      this.heldMutationSeenResolve?.();
      this.heldMutationSeenResolve = undefined;
      await this.heldMutationPromise;
    }

    if (!this.targetOrigin) throw new Error("Access edge target is not configured");
    if ((this.mode === "expired" || this.mode === "invalid") && isDocumentRequest(request)) {
      this.reentryCountValue += 1;
      if (this.autoCompleteReentry) {
        const location = `/__fixture/access/reentry?return=${encodeURIComponent(path)}`;
        response.writeHead(302, { location, "cache-control": "no-store" });
        response.end();
        exchange.responseStatus = 302;
        exchange.responseHeaders = { location, "cache-control": "no-store" };
        exchange.responseCompleted = true;
        exchange.responseTermination = "complete";
        exchange.responseBodySha256 = `sha256:${sha256(Buffer.alloc(0))}`;
        this.captureExchange(exchange, { ...request.headers, "cf-access-jwt-assertion": "${ACCESS_ASSERTION}" });
        return;
      }
      const html = "<!doctype html><html><head><title>Access re-entry</title></head><body><main data-access-reentry><h1>Access re-entry required</h1><p>Return through the management origin.</p></main></body></html>";
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      response.end(html);
      exchange.responseStatus = 200;
      exchange.responseHeaders = {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      };
      exchange.responseChunks = [{ offset_us: 0, body_hex: Buffer.from(html).toString("hex") }];
      exchange.responseCompleted = true;
      exchange.responseTermination = "complete";
      exchange.responseBodySha256 = `sha256:${sha256(Buffer.from(html))}`;
      this.captureExchange(exchange, { ...request.headers, "cf-access-jwt-assertion": "${ACCESS_ASSERTION}" });
      return;
    }

    const signingMode: AccessMode = isMutation(request) && this.expireNextMutation
      ? "expired"
      : this.mode;
    const signingKeys = signingMode === "invalid" ? this.forgedKeys : this.initialKeys;
    const signedAssertion = signAccessJwt(signingKeys, signingMode);
    const assertion = signedAssertion.token;
    const forwardedRequest = {
      method: request.method,
      url: request.url,
      headers: request.headers,
    } as IncomingMessage;
    exchange.requestSemanticHeaders = canonicalRequestSemanticHeaders(
      forwardHeaders(request, { "cf-access-jwt-assertion": assertion }, body),
    );
    if (request.headers.accept?.includes("text/event-stream")) {
      const lastEventId = typeof request.headers["last-event-id"] === "string" ? request.headers["last-event-id"] : "";
      const sseExchange: SseExchange = Object.assign(exchange, {
        lastEventId,
        eventIds: [] as string[],
        assertionExpiresAtMs: signedAssertion.expiresAtMs,
        openedAtMs: 0,
        closedAtMs: 0,
      });
      this.sseExchanges.push(sseExchange);
      this.forwardedAssertionCountValue += 1;
      let opened = false;
      try {
        await forwardStreamingRequest(
          forwardedRequest,
          response,
          this.targetOrigin,
          { "cf-access-jwt-assertion": assertion },
          body,
          (status, headers) => {
            opened = true;
            this.sseOpenedCountValue += 1;
            sseExchange.openedAtMs = Date.now();
            sseExchange.responseStatus = status;
            sseExchange.responseHeaders = headers;
            this.sseOpenedResolve?.();
            this.sseOpenedResolve = undefined;
          },
          (chunk, offsetUs) => {
            sseExchange.responseChunks.push({ offset_us: offsetUs, body_hex: chunk.toString("hex") });
            for (const match of chunk.toString("utf8").matchAll(/(?:^|\n)id:\s*([^\r\n]+)/g)) {
              const eventId = match[1];
              if (eventId !== undefined) sseExchange.eventIds.push(eventId);
            }
          },
          (completed, termination) => {
            sseExchange.closedAtMs = Date.now();
            sseExchange.responseCompleted = completed;
            sseExchange.responseTermination = termination;
            sseExchange.responseBodySha256 = `sha256:${sha256(responseBodyFromChunks(sseExchange.responseChunks))}`;
            if (this.mode === "expiring" && opened) this.expireNextMutation = true;
            this.sseClosedResolve?.();
            this.sseClosedResolve = undefined;
          },
        );
      } catch (error) {
        sseExchange.responseStatus ||= 502;
        sseExchange.responseTermination = "upstream_error";
        sseExchange.responseBodySha256 = `sha256:${sha256(responseBodyFromChunks(sseExchange.responseChunks))}`;
        this.captureExchange(sseExchange, { ...request.headers, "cf-access-jwt-assertion": assertion });
        throw error;
      }
      this.captureExchange(sseExchange, { ...request.headers, "cf-access-jwt-assertion": assertion });
      return;
    }
    this.forwardedAssertionCountValue += 1;
    const result = await forwardRequest(
      forwardedRequest,
      response,
      this.targetOrigin,
      { "cf-access-jwt-assertion": assertion },
      body,
    );
    exchange.responseStatus = result.status;
    exchange.responseHeaders = result.headers;
    exchange.responseChunks = result.chunks;
    exchange.responseCompleted = result.completed;
    exchange.responseTermination = result.termination;
    exchange.responseBodySha256 = `sha256:${sha256(result.body)}`;
    if (isMutation(request) && signingMode === "expired") this.mode = "expired";
    this.captureExchange(exchange, { ...request.headers, "cf-access-jwt-assertion": assertion });
  }
}

class CallbackOriginFixture {
  private readonly server = createServer((request: IncomingMessage, response: ServerResponse) => {
    void this.handle(request, response).catch(() => {
      if (!response.headersSent) response.writeHead(500, { "content-type": "text/plain" });
      response.end();
    });
  });
  origin = "";
  private targetOrigin = "";

  async start(targetOrigin: string): Promise<this> {
    this.targetOrigin = targetOrigin;
    this.origin = await listen(this.server);
    return this;
  }

  async stop(): Promise<void> {
    await closeServer(this.server);
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const path = request.url ?? "/";
    const callbackPath = /^\/v1\/endpoints\/[^/]+\/callbacks\/[^/]+(?:\?.*)?$/;
    if (request.method === "POST" && callbackPath.test(path)) {
      await forwardRequest(request, response, this.targetOrigin);
      return;
    }
    await readRequestBody(request);
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    response.end("callback route only\n");
  }
}

function binaryPath(name: "zode" | "zode-server"): string {
  const configured = name === "zode" ? process.env.ZODE_ENDPOINT_BIN : process.env.ZODE_SERVER_BIN;
  if (configured) return resolve(configured);
  const candidates = name === "zode"
    ? [resolve(REPO_ROOT, "target/debug/zode"), resolve(REPO_ROOT, "target/release/zode")]
    : [resolve(REPO_ROOT, "server/target/debug/zode-server"), resolve(REPO_ROOT, "server/target/release/zode-server")];
  const firstCandidate = candidates[0];
  if (!firstCandidate) throw new Error(`no binary candidate configured for ${name}`);
  return firstCandidate;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function buildTestOwnedUiDist(directory: string): Promise<void> {
  await execFileAsync(
    "vp",
    ["build", "--outDir", directory],
    { cwd: resolve(REPO_ROOT, "web"), env: { ...process.env }, timeout: 120_000 },
  );
  await access(join(directory, "index.html"));
}

async function writeProcessConfigs(root: string, edge: AccessEdgeFixture): Promise<{
  endpoint: string;
  server: string;
  controllerSecret: string;
}> {
  const endpointDir = join(root, "endpoint-secrets");
  const serverDir = join(root, "server-secrets");
  const replicaDir = join(root, "endpoint-replicas");
  const uiAssetsDirectory = join(root, "ui-dist");
  const serverConfigPath = join(root, "server.json");
  const uiAssetsDirectoryFromConfig = relative(dirname(serverConfigPath), uiAssetsDirectory);
  const portReservation = createServer();
  const reservedOrigin = await listen(portReservation);
  await closeServer(portReservation);
  const serverPort = new URL(reservedOrigin).port;
  const managementOrigin = `http://127.0.0.1:${serverPort}`;
  const callbackOrigin = `http://127.0.0.2:${serverPort}`;
  await mkdir(endpointDir, { recursive: true, mode: 0o700 });
  await mkdir(serverDir, { recursive: true, mode: 0o700 });
  await mkdir(replicaDir, { recursive: true, mode: 0o700 });
  await buildTestOwnedUiDist(uiAssetsDirectory);
  const controllerSecretPath = join(endpointDir, "controller.secret");
  const controllerSecret = `synthetic-controller-${randomUUID()}`;
  await writeFile(controllerSecretPath, controllerSecret, { mode: 0o600 });
  const subjectKey = join(root, "subject.key");
  await writeFile(subjectKey, randomBytes(32), { mode: 0o600 });

  const endpointConfigPath = join(root, "endpoint.json");
  const endpointConfig = {
    schema: "zode.config.v1",
    listen: "127.0.0.1:0",
    runtime_store: { kind: "sqlite", path: join(root, "endpoint.sqlite") },
    credential_replica_store: { kind: "files", directory: replicaDir },
    controller_auth: [{
      authority_id: "access-entry-e2e-server",
      revision: 1,
      kind: "bearer_secret_file",
      secret_file: controllerSecretPath,
    }],
  };
  await writeJson(endpointConfigPath, endpointConfig);

  const configuredTemplate = process.env.ZODE_ACCESS_SERVER_CONFIG;
  if (configuredTemplate) {
    const template = JSON.parse(
      (await readFile(resolve(configuredTemplate), "utf8"))
        .replaceAll("${ACCESS_ISSUER}", edge.issuer())
        .replaceAll("${ACCESS_JWKS_URL}", edge.jwksUrl())
        .replaceAll("${ACCESS_AUDIENCE}", ACCESS_AUDIENCE),
    ) as Record<string, unknown>;
    await writeJson(serverConfigPath, {
      ...template,
      ui_mode: "assets",
      ui_assets_directory: uiAssetsDirectoryFromConfig,
    });
  } else {
    await writeJson(serverConfigPath, {
      schema: "zode.server-config.v1",
      listen: `127.0.0.1:${serverPort}`,
      management_origin: managementOrigin,
      callback_origin: callbackOrigin,
      server_authority_id: "access-entry-e2e-server",
      deployment: "server_only",
      ui_mode: "assets",
      ui_assets_directory: uiAssetsDirectoryFromConfig,
      control_database: join(root, "server.sqlite"),
      secret_directory: serverDir,
      access: {
        issuer: edge.issuer(),
        audiences: [ACCESS_AUDIENCE],
        jwks_url: edge.jwksUrl(),
        subject_key_file: subjectKey,
        subject_key_version: 1,
      },
    });
  }
  return { endpoint: endpointConfigPath, server: serverConfigPath, controllerSecret };
}

async function isAllInOneConfig(path: string): Promise<boolean> {
  try {
    const config = JSON.parse(await readFile(path, "utf8")) as { deployment?: string };
    return config.deployment === "all_in_one";
  } catch {
    return false;
  }
}

async function seedAccessSession(
  accessEdge: AccessEdgeFixture,
  endpointOrigin: string,
  controllerSecret: string,
): Promise<string> {
  const endpointResponse = await fetch(`${accessEdge.origin}/v1/endpoints`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "idempotency-key": `access-expiry-endpoint-${randomUUID()}`,
    },
    body: JSON.stringify({
      label: "Access expiry Endpoint",
      base_url: endpointOrigin,
      control_auth: { kind: "bearer", secret: controllerSecret },
    }),
  });
  if (!endpointResponse.ok) {
    throw new ReadinessNonEvidence();
  }
  const endpoint = (await endpointResponse.json()) as { endpoint_id?: string };
  if (!endpoint.endpoint_id) throw new ReadinessNonEvidence();
  const sessionResponse = await fetch(
    `${accessEdge.origin}/v1/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/sessions`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "idempotency-key": `access-expiry-session-${randomUUID()}`,
      },
      body: JSON.stringify({ tools: [] }),
    },
  );
  if (!sessionResponse.ok) throw new ReadinessNonEvidence();
  const session = (await sessionResponse.json()) as { session_id?: string };
  if (!session.session_id) throw new ReadinessNonEvidence();
  return `/endpoints/${encodeURIComponent(endpoint.endpoint_id)}/sessions/${encodeURIComponent(session.session_id)}`;
}

class TestStack {
  private expiryRedObserved = false;

  private constructor(
    readonly root: string,
    readonly access: AccessEdgeFixture,
    readonly callback: CallbackOriginFixture,
    readonly server: CapturedProcess,
    readonly endpoint: CapturedProcess | undefined,
    readonly journal: RecordingJournalContract,
    readonly captureSetId: string,
    readonly captureRoot: string,
    readonly sessionPath: string,
  ) {}

  static async start(): Promise<TestStack> {
    const root = await mkdtemp(join(tmpdir(), "zode-access-entry-"));
    const captureRoot = resolve(
      REPO_ROOT,
      "target/test-recordings/quarantine",
      `access-entry-expiry-${Date.now()}-${randomUUID()}`,
    );
    const ledger = new SecretLedger();
    ledger.add("access_subject", ACCESS_SUBJECT);
    ledger.add("access_email", ACCESS_EMAIL);
    const journal = new RecordingJournal({ rootDir: captureRoot, ledger });
    const captureSetId = journal.beginCaptureSet({ e2eName: EXPIRY_E2E_NAME, maxMembers: 256 });
    const accessEdge = await new AccessEdgeFixture().start();
    accessEdge.setCapture(journal, captureSetId);
    let endpoint: CapturedProcess | undefined;
    try {
      const configs = await writeProcessConfigs(root, accessEdge);
      ledger.add("controller_secret", configs.controllerSecret);
      const allInOne = await isAllInOneConfig(configs.server);
      const environment = { ...process.env };
      const startupCaptureRoot = join(captureRoot, "startup");
      const e2eName = EXPIRY_E2E_NAME;
      if (!allInOne) {
        endpoint = await CapturedRealProcess.start({
          name: "endpoint",
          binary: binaryPath("zode"),
          args: ["--config", configs.endpoint],
          cwd: REPO_ROOT,
          env: environment,
          readyPrefix: "ZODE_READY ",
          ledger,
          logDir: join(root, "logs"),
          startupCaptureRoot,
          startupConfigBytes: await readFile(configs.endpoint),
          e2eName,
        });
      }
      const serverCwd = join(root, "server-cwd");
      await mkdir(serverCwd, { recursive: true, mode: 0o700 });
      const server = await CapturedRealProcess.start({
        name: "server",
        binary: binaryPath("zode-server"),
        args: ["--config", configs.server],
        cwd: serverCwd,
        env: environment,
        readyPrefix: "ZODE_SERVER_READY ",
        ledger,
        logDir: join(root, "logs"),
        startupCaptureRoot,
        startupConfigBytes: await readFile(configs.server),
        e2eName,
      });
      const serverOrigin = server.baseUrl;
      if (!serverOrigin) throw new ReadinessNonEvidence();
      accessEdge.setTarget(serverOrigin);
      const callback = await new CallbackOriginFixture().start(serverOrigin);
      const endpointOrigin = endpoint?.baseUrl;
      if (!endpointOrigin) throw new ReadinessNonEvidence();
      const sessionPath = await seedAccessSession(accessEdge, endpointOrigin, configs.controllerSecret);
      return new TestStack(root, accessEdge, callback, server, endpoint, journal, captureSetId, captureRoot, sessionPath);
    } catch (error) {
      await endpoint?.stop().catch(() => undefined);
      await accessEdge.stop().catch(() => undefined);
      try {
        accessEdge.assertCaptureHealthy();
        const flushed = journal.flushCaptureSet(captureSetId);
        await writeFile(
          join(captureRoot, "later-gap-metadata.json"),
          `${JSON.stringify({
            schema: "zode.access-entry-later-gap.v1",
            version: 1,
            owning_e2e: EXPIRY_E2E_NAME,
            relation: EXPIRY_LATER_RELATION,
            original_gap: EXPIRY_ORIGINAL_GAP,
            recording_id: null,
            capture_set_id: captureSetId,
            first_observed: "real-process or test setup did not reach the assertion-expiry path",
            raw_exchange_retained: Boolean(flushed.records?.length),
            source_digest: flushed.sourceDigest ?? null,
          }, null, 2)}\n`,
          { mode: 0o600 },
        );
      } catch {
        // The shared journal retains its open raw members for diagnosis when
        // a setup failure prevents a complete flush; never replace them with
        // a fabricated expiry observation.
      }
      await rm(root, { recursive: true, force: true });
      throw error;
    }
  }

  managementUrl(path = "/"): string {
    return new URL(path, `${this.access.origin}/`).toString();
  }

  beginCaptureSet(e2eName: string): string {
    const captureSetId = this.journal.beginCaptureSet({ e2eName, maxMembers: 64 });
    this.access.setCapture(this.journal, captureSetId);
    return captureSetId;
  }

  restoreCaptureSet(): void {
    this.access.setCapture(this.journal, this.captureSetId);
  }

  markExpiryRed(): void {
    this.expiryRedObserved = true;
  }

  callbackUrl(path = "/"): string {
    return new URL(path, `${this.callback.origin}/`).toString();
  }

  async stop(): Promise<void> {
    let firstError: unknown;
    try { await this.callback.stop(); } catch (error) { firstError ||= error; }
    try { await this.access.stop(); } catch (error) { firstError ||= error; }
    try { await this.server.stop(); } catch (error) { firstError ||= error; }
    try { await this.endpoint?.stop(); } catch (error) { firstError ||= error; }
    try { this.access.assertCaptureHealthy(); } catch (error) { firstError ||= error; }
    const firstSse = this.access.sseExchanges[0];
    const firstFailure = this.expiryRedObserved && firstSse
      ? this.journal.first({
          boundary: "management-access-edge",
          requestPath: firstSse.path,
          responseStatus: firstSse.responseStatus,
          captureSetId: this.captureSetId,
        })
      : undefined;
    try {
      const flushed = this.journal.flushCaptureSet(this.captureSetId, {
        firstFailureRecordingId: firstFailure?.recordingId,
      });
      await writeFile(
        join(this.captureRoot, "later-gap-metadata.json"),
        `${JSON.stringify({
          schema: "zode.access-entry-later-gap.v1",
          version: 1,
          owning_e2e: EXPIRY_E2E_NAME,
          relation: EXPIRY_LATER_RELATION,
          original_gap: EXPIRY_ORIGINAL_GAP,
          recording_id: firstFailure?.recordingId ?? null,
          capture_set_id: this.captureSetId,
          first_observed: firstFailure ? "management SSE remained open beyond Access assertion exp" : "no typed red observed",
          raw_exchange_retained: Boolean(firstFailure),
          source_digest: flushed.sourceDigest ?? null,
        }, null, 2)}\n`,
        { mode: 0o600 },
      );
    } catch (error) {
      firstError ||= error;
    }
    await rm(this.root, { recursive: true, force: true });
    if (firstError) throw firstError;
  }
}

async function replayRetainedFirst404(
  page: Page,
  stack: TestStack,
  cassette: Cassette,
  source: ShallowNonEvidenceSource,
): Promise<{ status: number; exactFirst404: boolean }> {
  const exchange = cassette.exchanges[0];
  if (!exchange) throw new Error(`cassette ${source.cassette} has no replay exchange`);
  const response = await page.goto(stack.managementUrl(source.path), {
    waitUntil: "commit",
    timeout: 12_000,
  });
  expect(stack.access.forwardedAssertionCount()).toBeGreaterThan(0);
  if (!response) throw new Error(`retained replay returned no response for ${source.cassette}`);
  expect(new URL(response.url()).origin).toBe(stack.access.origin);
  const body = await response.body();
  const status = response.status();
  if (status === source.first_observed_outcome.status) {
    expect(stack.access.exchanges).toHaveLength(1);
    const observed = stack.access.exchanges[0];
    if (!observed) throw new Error(`replay produced no observed exchange for ${source.cassette}`);
    expect(stack.access.exchanges.map((candidate) => candidate.sequence)).toEqual([exchange.sequence]);
    expect(observed.method).toBe(exchange.request.method);
    expect(observed.path).toBe(exchange.request.path);
    expect(observed.requestSemanticHeaders).toEqual(exchange.request.semantic_headers);
    expect(observed.bodySha256).toBe(exchange.request.body_sha256);
    expect(observed.responseStatus).toBe(exchange.recorded_response.status);
    expect(responseSemanticHeaders(observed.responseHeaders)).toEqual(exchange.recorded_response.semantic_headers);
    expect(observed.responseChunks).toHaveLength(exchange.recorded_response.chunks.length);
    // Correctness replay preserves chunk bytes and order; timing mode may
    // choose immediate emission, so offsets are checked for monotonicity only.
    expect(observed.responseChunks.map((chunk) => chunk.body_hex)).toEqual(
      exchange.recorded_response.chunks.map((chunk) => chunk.body_hex),
    );
    expect(observed.responseChunks.map((chunk) => chunk.offset_us)).toEqual(
      [...observed.responseChunks].sort((left, right) => left.offset_us - right.offset_us).map((chunk) => chunk.offset_us),
    );
    expect(observed.responseChunks.every((chunk) => chunk.offset_us >= 0)).toBe(true);
    expect(observed.responseCompleted).toBe(exchange.recorded_response.completed);
    expect(observed.responseTermination).toBe(exchange.recorded_response.termination);
    expect(observed.responseBodySha256).toBe(exchange.recorded_response.body_sha256);

    // `response.body()` above is the complete browser consumption barrier. The
    // retained response bytes must match before the caller may classify 404 as
    // shallow non-evidence.
    const recordedBody = responseBodyFromChunks(exchange.recorded_response.chunks);
    expect(body.toString("hex")).toBe(recordedBody.toString("hex"));
    expect(`sha256:${sha256(body)}`).toBe(source.recorded_response.body_sha256);
    return { status, exactFirst404: true };
  }
  expect(status).toBe(source.target_status);
  return { status, exactFirst404: false };
}

async function assertNoZodeAuthSurface(page: Page, context: BrowserContext): Promise<void> {
  const text = (await page.locator("body").innerText().catch(() => "")).toLowerCase();
  expect(text).not.toMatch(/zode\s+(login|logout)|application\s+login|account\s+settings|token\s+input/);
  const labels = await page.locator("a,button,input,label,[role=button]").evaluateAll((nodes) =>
    nodes.map((node) => `${node.textContent ?? ""} ${(node as HTMLInputElement).getAttribute("aria-label") ?? ""} ${(node as HTMLInputElement).getAttribute("name") ?? ""}`).join("\n"),
  );
  expect(labels).not.toMatch(/zode\s+(login|logout)|account\s+settings|token/i);
  expect(await page.locator('input[name*="token" i],input[aria-label*="token" i],input[placeholder*="token" i]').count()).toBe(0);

  const cookies = await context.cookies();
  expect(cookies.filter((cookie) => /^(zode|zode[-_]|zode.*(login|auth|session))/i.test(cookie.name))).toHaveLength(0);
  const storage = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));
  const serialized = JSON.stringify(storage);
  expect(serialized).not.toMatch(/cf_access|cf-authorization|access[_-]?jwt|access[_-]?token|refresh[_-]?token|password|secret/i);
}

async function assertManagementUi(page: Page): Promise<void> {
  await expect(page.getByRole("main")).toBeVisible();
  await expect(page.getByRole("navigation")).toBeVisible();
}

async function assertReentryPage(page: Page, context: BrowserContext, stack: TestStack, expectedPath: string, navigationCount: number): Promise<void> {
  await expect(page.locator("[data-access-reentry]")).toBeVisible();
  await expect.poll(() => page.url()).toContain(stack.access.origin);
  await expect.poll(() => page.url()).not.toContain(stack.callback.origin);
  expect(new URL(page.url()).pathname + new URL(page.url()).search).toBe(expectedPath);
  await assertNoZodeAuthSurface(page, context);
  expect(page.url()).not.toMatch(/eyJ[a-zA-Z0-9_-]{20,}|access[_-]?token|refresh[_-]?token/i);
  expect(navigationCount).toBeGreaterThan(0);
}

function assertSseCursorRecovery(stack: TestStack): void {
  expect(stack.access.sseExchanges.length).toBeGreaterThanOrEqual(2);
  const first = stack.access.sseExchanges[0];
  const recovered = stack.access.sseExchanges[1];
  if (!first || !recovered) throw new Error("SSE cursor recovery did not retain two exchanges");
  expect(first.lastEventId).toBe("");
  const firstPair = first.path.match(/^\/v1\/endpoints\/([^/]+)\/sessions\/([^/]+)\/events(?:\?.*)?$/);
  const recoveredPair = recovered.path.match(/^\/v1\/endpoints\/([^/]+)\/sessions\/([^/]+)\/events(?:\?.*)?$/);
  expect(firstPair).not.toBeNull();
  expect(recoveredPair).not.toBeNull();
  expect(recoveredPair?.[1]).toBe(firstPair?.[1]);
  expect(recoveredPair?.[2]).toBe(firstPair?.[2]);

  const cursor = first.eventIds.at(-1) ?? first.lastEventId;
  expect(cursor).toBeTruthy();
  expect(recovered.lastEventId).toBe(cursor);
  const firstIds = new Set(first.eventIds);
  const recoveredIds = new Set(recovered.eventIds);
  expect(firstIds.size).toBe(first.eventIds.length);
  expect(recoveredIds.size).toBe(recovered.eventIds.length);
  // The reconnect pair is the stream continuity contract.  A later full
  // document re-entry intentionally opens a fresh stream without a cursor
  // and may replay the initial session frame; it is not a Last-Event-ID
  // reconnect and must not be mistaken for a duplicate in that pair.
  expect([...firstIds].some((id) => recoveredIds.has(id))).toBe(false);
}

async function assertSessionAccessReentryCassette(): Promise<void> {
  const matches: string[] = [];
  for (const name of await readdir(INCIDENT_DIRECTORY)) {
    if (!name.endsWith(".v1.json")) continue;
    const path = join(INCIDENT_DIRECTORY, name);
    try {
      const value = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
      if (
        value.e2e_name === SESSION_ACCESS_REENTRY_E2E_NAME &&
        value.classification === SESSION_ACCESS_REENTRY_CLASSIFICATION
      ) {
        matches.push(path);
      }
    } catch {
      // Unrelated incident files are validated by their owning E2Es.
    }
  }
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(await readFile(matches[0]!, "utf8")) as {
    schema?: string;
    version?: number;
    boundary?: string;
    first_observed?: string;
    source_digest?: string;
    integrity_sha256?: string;
    exchanges?: Array<{ boundary?: string; method?: string; path?: string; response?: { status?: number } }>;
  };
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.boundary).toBe("browser-capture-set");
  expect(cassette.first_observed).toBe(SESSION_ACCESS_REENTRY_FIRST_OBSERVED);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  // Git tracks the promoted cassette bytes but not the immutable 0444 mode.
  // Normalize a regular checkout before asserting the promotion contract;
  // never follow or repair a symlink as a substitute for the cassette.
  const metadata = await lstat(matches[0]!);
  expect(metadata.isSymbolicLink()).toBe(false);
  if ((metadata.mode & 0o222) !== 0) await chmod(matches[0]!, 0o444);
  expect((await stat(matches[0]!)).mode & 0o777).toBe(0o444);
  expect(cassette.exchanges?.some((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "GET" &&
    exchange.path?.includes("/sessions") &&
    exchange.response?.status === 401,
  )).toBe(true);
}

test.describe("Access entry and re-entry", () => {
  test.describe.configure({ mode: "serial", retries: 0 });
  test.setTimeout(45_000);

  let stack: TestStack;
  let entryCassette: Cassette;
  let reentryCassette: Cassette;
  let shallowClassification: ShallowNonEvidenceFixture;
  let readinessNonEvidence: ReadinessNonEvidence | undefined;

  test.beforeAll(async () => {
    shallowClassification = await loadShallowClassification();
    entryCassette = await loadCassette(
      ENTRY_CASSETTE_PATH,
      classificationSource("management-entry-first-failure.v1.json"),
    );
    reentryCassette = await loadCassette(
      REENTRY_CASSETTE_PATH,
      classificationSource("browser-access-reentry-first-failure.v1.json"),
    );
    try {
      stack = await TestStack.start();
    } catch (error) {
      if (!(error instanceof ReadinessNonEvidence)) throw error;
      readinessNonEvidence = error;
    }
  });

  test.afterAll(async () => {
    await stack?.stop();
  });

  test.beforeEach(async ({}, testInfo) => {
    if (readinessNonEvidence) {
      annotateNonEvidence(testInfo, readinessNonEvidence.classification, readinessNonEvidence.message);
      testInfo.skip(true, readinessNonEvidence.message);
      return;
    }
    await stack.access.reset();
  });

  test("e2e_access_retained_first_404_replay_is_shallow_non_evidence", async ({ page }, testInfo) => {
    const cassettes = new Map([
      ["management-entry-first-failure.v1.json", entryCassette],
      ["browser-access-reentry-first-failure.v1.json", reentryCassette],
    ]);
    const retainedFirst404Paths: string[] = [];
    for (const source of shallowClassification.sources) {
      const cassette = cassettes.get(source.cassette);
      if (!cassette) throw new Error(`missing loaded cassette ${source.cassette}`);
      await stack.access.reset();
      const replay = await replayRetainedFirst404(page, stack, cassette, source);
      if (replay.exactFirst404) retainedFirst404Paths.push(source.path);
    }
    if (retainedFirst404Paths.length > 0) {
      annotateNonEvidence(
        testInfo,
        shallowClassification.classification,
        `public-boundary replay retains exact first 404 as shallow non-evidence (${retainedFirst404Paths.join(",")})`,
      );
      testInfo.skip(true, "retained management-origin 404 is non-evidence for Access UI behavior");
    }
  });

  test("e2e_access_entry_reentry_through_real_access_edge", async ({ page, context }, testInfo) => {
    const entryExchange = entryCassette.exchanges[0];
    if (!entryExchange) throw new Error("entry cassette has no retained exchange");
    const entryPath = entryExchange.request.path;
    const response = await page.goto(stack.managementUrl(entryPath), { waitUntil: "domcontentloaded" });
    const observed = stack.access.firstExchange(entryPath);
    expect(observed).toBeDefined();
    expect(observed?.method).toBe(entryExchange.request.method);
    expect(observed?.bodySha256).toBe(entryExchange.request.body_sha256);
    expect(stack.access.forwardedAssertionCount()).toBeGreaterThan(0);
    assertManagementUiResponse(response, entryPath, testInfo, entryCassette.target_contract.status);
    await assertManagementUi(page);
    expect(new URL(page.url()).origin).toBe(stack.access.origin);
    expect(new URL(page.url()).pathname).not.toBe("/login");
    await assertNoZodeAuthSurface(page, context);
  });

  test("e2e_access_reload_keeps_the_access_admitted_ui_without_zode_auth", async ({ page, context }, testInfo) => {
    const response = await page.goto(stack.managementUrl(), { waitUntil: "domcontentloaded" });
    assertManagementUiResponse(response, "/", testInfo);
    await assertManagementUi(page);
    const firstUrl = page.url();
    const reloadResponse = await page.reload({ waitUntil: "domcontentloaded" });
    assertManagementUiResponse(reloadResponse, "/", testInfo);
    expect(page.url()).toBe(firstUrl);
    await assertManagementUi(page);
    await assertNoZodeAuthSurface(page, context);
  });

  for (const mode of ["expired", "invalid"] as const) {
    test(`e2e_access_${mode}_assertion_reenters_management_origin_and_stops_mutation_retries`, async ({ page, context }, testInfo) => {
      // The sessions list is only a selection surface.  The mutation under
      // test must start from the real seeded session workspace where the
      // public composer is rendered.
      const viewUrl = stack.managementUrl(stack.sessionPath);
      const response = await page.goto(viewUrl, { waitUntil: "domcontentloaded" });
      assertManagementUiResponse(response, new URL(viewUrl).pathname + new URL(viewUrl).search, testInfo);
      await assertManagementUi(page);
      const navigations: string[] = [];
      page.on("framenavigated", (frame) => {
        if (frame === page.mainFrame()) navigations.push(frame.url());
      });

      const composer = page.getByRole("textbox", { name: /message|prompt|composer/i }).first();
      const send = page.getByRole("button", { name: /send|submit/i }).first();
      await expect(composer).toBeVisible();
      await expect(send).toBeVisible();
      await composer.fill(MUTATION_TEXT);
      await stack.access.armMutationBarrier();
      const click = send.click().catch(() => undefined);
      await stack.access.waitForHeldMutation();
      await stack.access.setMode(mode);
      await stack.access.releaseHeldMutation();
      await click;

      await expect(page.locator("[data-access-reentry]")).toBeVisible();
      await assertReentryPage(
        page,
        context,
        stack,
        new URL(viewUrl).pathname + new URL(viewUrl).search,
        navigations.length,
      );
      await expect.poll(() => stack.access.mutationAttemptCount()).toBe(1);
      expect(page.url()).not.toContain(MUTATION_TEXT);
    });
  }

  test(SESSION_ACCESS_REENTRY_E2E_NAME, async ({ page }) => {
    test.setTimeout(60_000);
    const captureMode = process.env.ZODE_CAPTURE_ACCESS_REENTRY_401 === "1";
    if (!captureMode) await assertSessionAccessReentryCassette();

    await page.goto(stack.managementUrl(stack.sessionPath), { waitUntil: "domcontentloaded" });
    await assertManagementUi(page);
    await expect(page.getByRole("heading", { name: "Session", exact: true })).toBeVisible();

    const captureSetId = stack.beginCaptureSet(SESSION_ACCESS_REENTRY_E2E_NAME);
    let primaryError: unknown;
    try {
      await stack.access.setMode("expired");
      await page.getByRole("link", { name: "Endpoints", exact: true }).click();
      await expect(page).toHaveURL(/\/endpoints$/u);
      await page.getByRole("link", { name: "Sessions", exact: true }).click();
      try {
        await expect(page.locator("[data-access-reentry]")).toBeVisible({ timeout: 10_000 });
      } catch (error) {
        throw new ProductBehaviorFailure(
          SESSION_ACCESS_REENTRY_CLASSIFICATION,
          SESSION_ACCESS_REENTRY_FIRST_OBSERVED,
          { cause: error instanceof Error ? error.message : String(error) },
        );
      }
    } catch (error) {
      primaryError = error;
    } finally {
      try {
        await stack.journal.waitForIdle();
        const firstFailure = stack.journal.first({
          boundary: "management-access-edge",
          responseStatus: 401,
          captureSetId,
        });
        if (!firstFailure) throw new Error("Access re-entry capture contained no HTTP 401 exchange");
        const capture = stack.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of capture.records ?? []) {
          if (record.rawPath) {
            expect((await stat(record.rawPath)).mode & 0o777).toBe(0o600);
          }
        }
        if (captureMode && primaryError) {
          const promoted = await stack.journal.promoteCaptureSet(captureSetId, {
            e2eName: SESSION_ACCESS_REENTRY_E2E_NAME,
            classification: SESSION_ACCESS_REENTRY_CLASSIFICATION,
            firstObserved: SESSION_ACCESS_REENTRY_FIRST_OBSERVED,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => stack.journal.replay(envelope, {
              baseUrl: stack.managementUrl(),
              boundaryBaseUrls: { "management-access-edge": stack.managementUrl() },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            SESSION_ACCESS_REENTRY_CLASSIFICATION,
            `${SESSION_ACCESS_REENTRY_FIRST_OBSERVED}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: firstFailure.recordingId },
          );
        }
      } catch (captureError) {
        primaryError = captureError;
      } finally {
        stack.restoreCaptureSet();
      }
    }
    if (primaryError) throw primaryError;
  });

  test("e2e_browser_access_reentry_stops_mutations_and_uses_management_origin", async ({ page, context }, testInfo) => {
    stack.access.enableAutoCompleteReentry();
    stack.access.armSseLifecycle();
    await stack.access.setMode("expiring");
    const reentryExchange = reentryCassette.exchanges[0];
    if (!reentryExchange) throw new Error("re-entry cassette has no retained exchange");
    // The retained pre-adoption cassette remains immutable historical evidence;
    // this later reproduction uses a real Endpoint-owned session route so the
    // browser exercises the production SSE proxy rather than an empty shell.
    const viewPath = stack.sessionPath;
    const viewUrl = stack.managementUrl(viewPath);
    const navigationUrls: string[] = [];
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) navigationUrls.push(frame.url());
    });
    const response = await page.goto(viewUrl, { waitUntil: "domcontentloaded" });
    assertManagementUiResponse(response, new URL(viewUrl).pathname + new URL(viewUrl).search, testInfo, reentryCassette.target_contract.status);
    await assertManagementUi(page);
    await stack.access.waitForSseOpened();

    const composer = page.getByRole("textbox", { name: /message|prompt|composer/i }).first();
    const send = page.getByRole("button", { name: /send|submit/i }).first();
    await expect(composer).toBeVisible();
    await expect(send).toBeVisible();
    await composer.fill(MUTATION_TEXT);
    await stack.access.armMutationBarrier();
    const click = send.click().catch(() => undefined);
    await stack.access.waitForHeldMutation();
    const navigationCountBeforeExpiry = navigationUrls.length;

    // The real Server proxy must close this response no later than the signed
    // assertion deadline; no wall-clock sleep is used as the test barrier.
    try {
      await stack.access.waitForSseClosed();
    } catch (error) {
      stack.markExpiryRed();
      throw error;
    }
    const initialSse = stack.access.sseExchanges[0];
    if (!initialSse) throw new Error("initial SSE exchange was not retained");
    expect(initialSse.openedAtMs).toBeGreaterThan(0);
    expect(initialSse.closedAtMs).toBeGreaterThanOrEqual(initialSse.openedAtMs);
    expect(initialSse.closedAtMs).toBeLessThanOrEqual(initialSse.assertionExpiresAtMs);
    // Allow the browser's native EventSource to perform one Access-admitted
    // reconnect while the page is still alive; only then force the held
    // mutation through the expired assertion and exercise re-entry.
    await stack.access.waitForSseOpenedCount(2);
    await stack.access.releaseHeldMutation();
    await click;

    await expect.poll(() => stack.access.reentryCount()).toBeGreaterThan(0);
    await expect.poll(() => navigationUrls.length).toBeGreaterThan(navigationCountBeforeExpiry);
    await expect(page.getByRole("main")).toBeVisible();
    await assertNoZodeAuthSurface(page, context);
    expect(new URL(page.url()).origin).toBe(stack.access.origin);
    expect(new URL(page.url()).pathname + new URL(page.url()).search).toBe(
      new URL(viewUrl).pathname + new URL(viewUrl).search,
    );
    expect(page.url()).not.toContain(MUTATION_TEXT);
    await expect.poll(() => stack.access.mutationAttemptCount()).toBe(1);
    await expect.poll(() => stack.access.sseExchanges.length).toBeGreaterThanOrEqual(2);
    assertSseCursorRecovery(stack);
  });

  test(SSE_ACCESS_REENTRY_E2E_NAME, async ({ page, context }, testInfo) => {
    test.setTimeout(60_000);
    const captureSetId = stack.beginCaptureSet(SSE_ACCESS_REENTRY_E2E_NAME);
    let primaryError: unknown;
    try {
      stack.access.enableAutoCompleteReentry();
      stack.access.armSseLifecycle();
      await stack.access.setMode("expiring");
      const viewUrl = stack.managementUrl(stack.sessionPath);
      const navigationUrls: string[] = [];
      page.on("framenavigated", (frame) => {
        if (frame === page.mainFrame()) navigationUrls.push(frame.url());
      });
      const response = await page.goto(viewUrl, { waitUntil: "domcontentloaded" });
      assertManagementUiResponse(response, new URL(viewUrl).pathname + new URL(viewUrl).search, testInfo);
      await assertManagementUi(page);
      await stack.access.waitForSseOpened();
      await stack.access.waitForSseClosed();

      // The next stream receives a real forged Access assertion and therefore a
      // real HTTP 401 from the management Server.  A browser must stop the SSE
      // retry loop and re-enter through the management origin, rather than
      // treating an admission failure as an Endpoint/network outage.
      await stack.access.setMode("invalid");
      const navigationCountBefore401 = navigationUrls.length;
      try {
        await expect
          .poll(
            () => stack.access.sseExchanges.filter((exchange) => exchange.responseStatus === 401).length,
            { timeout: 10_000 },
          )
          .toBe(1);
      } catch (error) {
        throw new ProductBehaviorFailure(
          SSE_ACCESS_REENTRY_CLASSIFICATION,
          SSE_ACCESS_REENTRY_FIRST_OBSERVED,
          {
            cause: error instanceof Error ? error.message : String(error),
            sse_statuses: stack.access.sseExchanges.map((exchange) => exchange.responseStatus),
          },
        );
      }
      const unauthorized = stack.access.sseExchanges.find((exchange) => exchange.responseStatus === 401);
      if (!unauthorized) {
        throw new ProductBehaviorFailure(
          SSE_ACCESS_REENTRY_CLASSIFICATION,
          `${SSE_ACCESS_REENTRY_FIRST_OBSERVED}; no retained HTTP 401 exchange`,
        );
      }
      expect(unauthorized.lastEventId).toBeTruthy();
      try {
        await expect.poll(() => stack.access.reentryCount()).toBeGreaterThan(0);
      } catch (error) {
        throw new ProductBehaviorFailure(
          SSE_ACCESS_REENTRY_CLASSIFICATION,
          SSE_ACCESS_REENTRY_FIRST_OBSERVED,
          {
            cause: error instanceof Error ? error.message : String(error),
            unauthorized_status: unauthorized.responseStatus,
            navigation_count: navigationUrls.length,
          },
        );
      }
      await expect.poll(() => navigationUrls.length).toBeGreaterThan(navigationCountBefore401);
      await expect(page.getByRole("main")).toBeVisible();
      await assertNoZodeAuthSurface(page, context);
      expect(new URL(page.url()).origin).toBe(stack.access.origin);
      expect(new URL(page.url()).pathname + new URL(page.url()).search).toBe(
        new URL(viewUrl).pathname + new URL(viewUrl).search,
      );
      expect(await page.locator("[data-access-reentry]").count()).toBe(0);
      await expect.poll(
        () => stack.access.sseExchanges.filter((exchange) => exchange.responseStatus === 401).length,
      ).toBe(1);
    } catch (error) {
      primaryError = error;
    } finally {
      // SSE_401_CAPTURE_FLUSH
      try {
        // The re-entry page opens a fresh admitted SSE stream.  Close the page
        // before flushing this capture set so that the journal observes the
        // stream's terminal disconnect instead of waiting on an open reader.
        await page.goto("about:blank", { waitUntil: "commit", timeout: 2_000 }).catch(() => undefined);
        await page.close().catch(() => undefined);
        // Stop the target before the edge so a target SSE cannot keep the
        // forwarding request alive while the edge is being sealed.
        await stack.server.stop().catch(() => undefined);
        await stack.endpoint?.stop().catch(() => undefined);
        await stack.access.stop().catch(() => undefined);
        try {
          await stack.journal.waitForIdle();
        } catch (error) {
          const journalState = stack.journal as unknown as { active?: Map<string, unknown> };
          const active = journalState.active ? [...journalState.active.keys()] : [];
          throw new Error(
            `${error instanceof Error ? error.message : String(error)} active_recordings=${active.join(",")}`,
          );
        }
        const firstFailure = stack.journal.first({
          boundary: "management-access-edge",
          responseStatus: 401,
          captureSetId,
        });
        const capture = stack.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure?.recordingId,
        });
        await writeFile(
          join(stack.captureRoot, "sse-401-reentry-first-occurrence.json"),
          `${JSON.stringify({
            schema: "zode.access-entry-sse-401-first-occurrence.v1",
            version: 1,
            owning_e2e: SSE_ACCESS_REENTRY_E2E_NAME,
            classification: SSE_ACCESS_REENTRY_CLASSIFICATION,
            first_observed: firstFailure
              ? SSE_ACCESS_REENTRY_FIRST_OBSERVED
              : "no typed red observed",
            recording_id: firstFailure?.recordingId ?? null,
            capture_set_id: captureSetId,
            raw_exchange_retained: Boolean(firstFailure),
            source_digest: capture.sourceDigest ?? null,
          }, null, 2)}\n`,
          { mode: 0o600 },
        );
        for (const record of capture.records ?? []) {
          if (record.rawPath) expect((await stat(record.rawPath)).mode & 0o777).toBe(0o600);
        }
      } catch (captureError) {
        primaryError ||= captureError;
      } finally {
        stack.restoreCaptureSet();
      }
    }
    if (primaryError) throw primaryError;
  });

  test("e2e_callback_origin_never_serves_management_ui_or_api", async ({ page, context }) => {
    const response = await page.goto(stack.callbackUrl(), { waitUntil: "domcontentloaded" });
    expect(new URL(page.url()).origin).toBe(stack.callback.origin);
    expect(response?.headers()["content-type"] ?? "").not.toContain("text/html");
    expect(await page.locator("script,link[rel=stylesheet],link[rel=modulepreload]").count()).toBe(0);
    expect(await page.locator("[data-zode-ui],nav,main[role=main]").count()).toBe(0);
    expect((await page.locator("body").innerText()).toLowerCase()).not.toContain("zode management");

    const managementApi = await context.request.get(stack.callbackUrl("/v1/system"), {
      headers: { "cf-access-jwt-assertion": "${ACCESS_ASSERTION}" },
    });
    expect(managementApi.status()).not.toBe(200);
    expect(managementApi.headers()["content-type"] ?? "").not.toContain("text/html");
    expect(await managementApi.text()).not.toContain("zode management");
  });
});
