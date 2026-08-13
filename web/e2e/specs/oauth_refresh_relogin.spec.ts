import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { createInterface } from "node:readline";
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { execFile, spawn, type ChildProcessByStdio } from "node:child_process";
import { once } from "node:events";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { type Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { expect, test, type Browser, type BrowserContext, type Page, type Response } from "@playwright/test";

const require = createRequire(import.meta.url);
const {
  RecordingJournal,
  SecretLedger,
  proxyHttp} = require("../support/harness.cjs") as {
  RecordingJournal: new (options: {
    rootDir: string;
    ledger: SecretLedgerContract;
  }) => RecordingJournalContract;
  SecretLedger: new () => SecretLedgerContract;
  proxyHttp: (options: Record<string, unknown>) => Promise<void>;
};

type SecretLedgerContract = {
  add: (label: string, value: string) => void;
};

type RecordingJournalContract = {
  currentCaptureSetId: string;
  beginCaptureSet: (options: { e2eName: string; maxMembers?: number }) => string;
  record: (options: Record<string, unknown>) => unknown;
  first: (options: {
    boundary?: string;
    requestPath?: string;
    responseStatus?: number;
  }) => { recordingId: string } | undefined;
  flushCaptureSet: (
    captureSetId: string,
    options?: { firstFailureRecordingId?: string },
  ) => unknown;
  promoteCaptureSet: (
    captureSetId: string,
    options: Record<string, unknown>,
  ) => Promise<{ cassettePath?: string }>;
  replay: (
    cassette: string | Record<string, unknown>,
    options: Record<string, unknown>,
  ) => Promise<Array<{ path: string; status: number }>>;
};

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

type FixtureMode =
  | "oauth_success"
  | "oauth_failed"
  | "oauth_cancelled"
  | "refresh_held"
  | "refresh_success"
  | "refresh_idempotent_drop_response"
  | "refresh_unknown";

type RefreshRecoveryMode = "same_operation_id_idempotent" | "none";

type FixtureState = {
  mode: FixtureMode;
  authorize_count: number;
  token_count: number;
  refresh_count: number;
  authorization_code_count: number;
  grant_types: string[];
  active_authorizations: number;
  consumed_refresh_count: number;
  idempotent_operation_count: number;
  held_refresh_count: number;
  model_request_count: number;
  oauth_credential_model_requests: number;
  refreshed_credential_model_requests: number;
  invalid_model_authorizations: number;
};

type IncidentCassette = {
  schema: string;
  version: number;
  recording_id: string;
  owner: string;
  boundary: string;
  secret_slots: string[];
  first_observed_outcome: {
    sequence: number;
    status: number;
    safe_error: string;
    response_fingerprint: string;
    classification: "PRODUCT_ROUTE_MISSING_SHALLOW_404";
    non_evidence: true;
  };
  exchanges: Array<{
    sequence: number;
    request: {
      method: string;
      path: string;
      semantic_headers: Array<{ name: string; value: string }>;
      raw_body_hex: string;
      canonical_json: JsonValue;
      body_sha256: string;
      fingerprint: string;
    };
    recorded_response: {
      status: number;
      semantic_headers: Array<{ name: string; value: string }>;
      body_hex: string;
      body_sha256: string;
      outcome: string;
      fingerprint: string;
    };
    contract: { status: number; kind: string };
  }>;
  expected_after_fix: {
    status: 200;
    safe_outcome: string;
  };
  replay_policy: {
    shallow_404_is_non_evidence: true;
    continue_only_after_status: 200;
  };
  whole_digest: string;
};

type RequestObservation = {
  method: string;
  url: string;
  headers: Record<string, string>;
  referer: string;
  postData: string;
};

type AuthAttemptObservation = RequestObservation & { body: JsonValue | null };

type BrowserAudit = {
  requests: RequestObservation[];
  authAttempts: AuthAttemptObservation[];
  ticketMints: string[];
  ticketMintUrls: string[];
  ticketRedemptions: string[];
  callbackUrls: string[];
  navigations: string[];
  consoleMessages: string[];
  consoleValueJobs: Promise<void>[];
  pageErrors: string[];
};

const SPEC_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SPEC_DIR, "../../..");
const WEB_ROOT = resolve(REPO_ROOT, "web");
const FIXTURE_DIR = resolve(SPEC_DIR, "../fixtures/oauth_refresh_relogin");
const INCIDENT_CASSETTE = resolve(
  FIXTURE_DIR,
  "oauth_refresh_relogin_first_browser_failure.v1.json",
);
const PROVIDER_DESCRIPTOR_E2E =
  "e2e_server_provider_descriptor_round_trips_non_secret_revision";
const PROVIDER_DESCRIPTOR_ID = "descriptor-roundtrip-provider";
const PROVIDER_DESCRIPTOR_PATH = `/v1/providers/${PROVIDER_DESCRIPTOR_ID}`;
const OAUTH_PROVIDER_ID = "oauth-browser-provider";
const PROVIDER_FIXTURE = resolve(FIXTURE_DIR, "provider_oauth_fixture.mjs");
const INCIDENT_RECORDING_ID = "oauth-refresh-relogin-browser-first-404-20260807";
const INCIDENT_PATH = "/v1/providers";
const EMPTY_BODY_SHA256 =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const INCIDENT_REQUEST_FINGERPRINT =
  "sha256:bb8207b9016400b9b92de3621428b95a5f5d65fc639f1f0ed63e27ec35b79c7f";
const INCIDENT_RESPONSE_FINGERPRINT =
  "sha256:60adbc991fbf8cb5d3c149b36c01cc20971a7cb820c171009be64a5ae09cc9c1";
const INCIDENT_WHOLE_DIGEST =
  "sha256:f45f65f6753440587d460b1ab61ee91a0133f4e7087b1f90d260897be588a454";
const READY_TIMEOUT = 15_000;
const HTTP_TIMEOUT = 15_000;
const UI_BUILD_TIMEOUT = 120_000;
const PROFILE_LABEL = "OAuth refresh browser E2E";
const ROUTE_MISSING_FOUNDATION_RED = "route-missing foundation red" as const;
const SYNTHETIC_SECRET_MARKER =
  process.env.ZODE_E2E_SYNTHETIC_SECRET_MARKER ??
  "zode-e2e-synthetic-oauth-refresh-secret-3a7d1c9e";
const execFileAsync = promisify(execFile);

class RouteMissingFoundationRed extends Error {
  readonly classification = "PRODUCT_ROUTE_MISSING_SHALLOW_404" as const;
  readonly nonEvidence = true as const;
  readonly stage = ROUTE_MISSING_FOUNDATION_RED;

  constructor(readonly path: string, readonly status: number, detail: string) {
    super(
      `${ROUTE_MISSING_FOUNDATION_RED}: ${path} is still HTTP ${status}; ${detail}; this is non-evidence for OAuth ticket behavior`,
    );
    this.name = "RouteMissingFoundationRed";
  }
}

// Ampere's marker scan is deliberately independent from the ticket assertions below.
// A ticket is a per-attempt capability held in this test only in memory; it is never a
// secret-marker input, persisted artifact, diagnostic string, or fixture response.
const SECRET_MARKERS = [
  SYNTHETIC_SECRET_MARKER,
  "fixture-access-token-oauth-1",
  "fixture-refresh-token-oauth-1",
  "fixture-access-token-refresh-success",
  "fixture-refresh-token-refresh-success",
  "fixture-access-token-refresh-idempotent",
  "fixture-refresh-token-refresh-idempotent",
  ...(process.env.ZODE_E2E_SECRET_MARKERS ?? "")
    .split(",")
    .map((marker) => marker.trim())
    .filter(Boolean)];

function jsonArgs(name: string, fallback: string[] | null): string[] {
  const raw = process.env[name];
  if (raw) {
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value) || value.some((argument) => typeof argument !== "string")) {
      throw new Error(`${name} must be a JSON string array`);
    }
    return value;
  }
  if (fallback) {
    return fallback;
  }
  throw new Error(`${name} or its config fallback is required for this E2E`);
}

function normalizeOrigin(value: string): string {
  return value.replace(/\/$/, "");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function readJsonFile<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function listenHttp(server: ReturnType<typeof createServer>): Promise<string> {
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("HTTP fixture did not receive a TCP address");
  }
  return `http://127.0.0.1:${address.port}`;
}

async function requestBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > 2 * 1024 * 1024) {
      request.destroy();
      throw new Error("Access fixture request body exceeded its bound");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

class AccessFixture {
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  private readonly kid = "oauth-refresh-browser-access";
  private readonly jwksServer: ReturnType<typeof createServer>;
  private edgeServer: ReturnType<typeof createServer> | undefined;
  private targetOrigin = "";
  private failGetPathPrefix = "";
  private failGetRemaining = 0;
  private failedGetCount = 0;
  private tokenSequence = 0;
  private readonly ledger: SecretLedgerContract | undefined;
  private readonly journal: RecordingJournalContract | undefined;
  private readonly captureSetId: string | undefined;
  issuer: string;
  jwksUrl: string;
  managementOrigin: string;
  callbackOrigin: string;

  private constructor(options: {
    ledger?: SecretLedgerContract;
    journal?: RecordingJournalContract;
    captureSetId?: string;
  } = {}) {
    this.ledger = options.ledger;
    this.journal = options.journal;
    this.captureSetId = options.captureSetId;
    const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.privateKey = keys.privateKey;
    this.publicKey = keys.publicKey;
    const publicJwk = this.publicKey.export({ format: "jwk" }) as Record<string, string>;
    if (publicJwk.n) {
      this.ledger?.add("provider_descriptor_jwks_modulus", publicJwk.n);
    }
    this.jwksServer = createServer((request, response) => {
      if (request.method !== "GET" || request.url !== "/jwks") {
        response.writeHead(404, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { code: "not_found" } }));
        return;
      }
      const responseBody = JSON.stringify({
        keys: [
          {
            ...(this.publicKey.export({ format: "jwk" }) as Record<string, string>),
            kid: this.kid,
            use: "sig",
            alg: "RS256"}]});
      this.journal?.record({
        boundary: "access-jwks-fixture",
        method: request.method,
        requestPath: request.url,
        requestHeaders: request.headers,
        requestBody: Buffer.alloc(0),
        responseStatus: 200,
        responseHeaders: { "cache-control": "no-store", "content-type": "application/json" },
        responseChunks: [{ offsetUs: 0, data: Buffer.from(responseBody) }],
        captureSetId: this.captureSetId});
      response.writeHead(200, {
        "cache-control": "no-store",
        "content-type": "application/json"});
      response.end(responseBody);
    });
    this.issuer = "";
    this.jwksUrl = "";
    this.managementOrigin = "";
    this.callbackOrigin = "";
  }

  static async start(options: {
    ledger?: SecretLedgerContract;
    journal?: RecordingJournalContract;
    captureSetId?: string;
  } = {}): Promise<AccessFixture> {
    const fixture = new AccessFixture(options);
    fixture.jwksServer.listen(0, "127.0.0.1");
    const jwksOrigin = await listenHttp(fixture.jwksServer);
    fixture.issuer = `${jwksOrigin}/`;
    fixture.jwksUrl = `${jwksOrigin}/jwks`;
    fixture.edgeServer = createServer((request, response) => {
      void fixture.forward(request, response);
    });
    fixture.edgeServer.listen(0, "127.0.0.1");
    fixture.managementOrigin = await listenHttp(fixture.edgeServer);
    const callback = new URL(fixture.managementOrigin);
    callback.hostname = "127.0.0.2";
    fixture.callbackOrigin = callback.origin;
    return fixture;
  }

  token(): string {
    const now = Math.floor(Date.now() / 1000);
    const header = base64Url(JSON.stringify({ alg: "RS256", kid: this.kid, typ: "JWT" }));
    const claims = base64Url(
      JSON.stringify({
        iss: this.issuer,
        aud: ["zode-web-oauth-refresh-e2e"],
        sub: "oauth-refresh-browser-human",
        type: "app",
        iat: now,
        nbf: now - 1,
        exp: now + 300}),
    );
    const input = `${header}.${claims}`;
    const token = `${input}.${base64Url(sign("RSA-SHA256", Buffer.from(input), this.privateKey))}`;
    this.tokenSequence += 1;
    this.ledger?.add(`provider_descriptor_access_assertion_${this.tokenSequence}`, token);
    return token;
  }

  async startEdge(targetOrigin: string): Promise<string> {
    this.setTarget(targetOrigin);
    return this.managementOrigin;
  }

  setTarget(targetOrigin: string): void {
    this.targetOrigin = normalizeOrigin(targetOrigin);
  }

  failNextGets(pathPrefix: string, count: number): void {
    this.failGetPathPrefix = pathPrefix;
    this.failGetRemaining = count;
    this.failedGetCount = 0;
  }

  get projectionFailures(): number {
    return this.failedGetCount;
  }

  private async forward(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (!this.targetOrigin) {
      response.writeHead(503);
      response.end();
      return;
    }
    const requestPath = new URL(request.url ?? "/", this.managementOrigin).pathname;
    if (
      request.method === "GET" &&
      this.failGetRemaining > 0 &&
      requestPath.startsWith(this.failGetPathPrefix)
    ) {
      this.failGetRemaining -= 1;
      this.failedGetCount += 1;
      response.writeHead(503, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "management_unavailable", retryable: true } }));
      return;
    }
    const assertion = this.token();
    if (this.journal) {
      await proxyHttp({
        targetBaseUrl: this.targetOrigin,
        request,
        response,
        extraHeaders: { "cf-access-jwt-assertion": assertion },
        boundary: "management-access-edge",
        journal: this.journal,
        ledger: this.ledger,
        captureSetId: this.captureSetId,
        canonicalOrigin: this.managementOrigin});
      return;
    }
    const body = await requestBody(request);
    const target = new URL(request.url ?? "/", this.targetOrigin);
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (value === undefined || name === "host" || name === "connection" || name === "content-length") {
        continue;
      }
      headers[name] = Array.isArray(value) ? value.join(", ") : value;
    }
    headers.host = new URL(this.managementOrigin).host;
    headers["cf-access-jwt-assertion"] = assertion;
    if (body.length > 0) headers["content-length"] = String(body.length);
    const upstream = httpRequest(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: request.method,
        headers},
      (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      },
    );
    upstream.once("error", () => {
      if (!response.headersSent) response.writeHead(502, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "management_unavailable", retryable: true } }));
    });
    upstream.end(body);
  }

  async stop(): Promise<void> {
    for (const server of [this.edgeServer, this.jwksServer]) {
      if (!server?.listening) continue;
      server.closeAllConnections?.();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    }
    this.edgeServer = undefined;
  }
}

class ReadyChild {
  readonly origin: string;

  private constructor(
    private readonly child: ChildProcessByStdio<null, Readable, Readable>,
    origin: string,
    private readonly lines: ReturnType<typeof createInterface>,
  ) {
    this.origin = normalizeOrigin(origin);
  }

  static async start(
    executable: string,
    args: string[],
    readyPrefix: string,
    environment: NodeJS.ProcessEnv,
  ): Promise<ReadyChild> {
    const child = spawn(executable, args, {
      env: { ...process.env, ...environment },
      stdio: ["ignore", "pipe", "pipe"]});
    // Retain only the Server's bounded typed startup code. Provider/OAuth
    // bodies and arbitrary stderr never become Playwright failure output.
    let startupFailure = "";
    let stderrRemainder = "";
    child.stderr.on("data", (chunk: Buffer | string) => {
      const lines = `${stderrRemainder}${chunk.toString()}`.split(/\r?\n/);
      stderrRemainder = lines.pop()?.slice(-512) ?? "";
      for (const line of lines) {
        const safe = line.match(/^ZODE_SERVER_STARTUP_FAILURE code=([a-z0-9_]+) phase=([a-z0-9_]+)/);
        if (safe) startupFailure = ` code=${safe[1]} phase=${safe[2]}`;
      }
    });
    const lines = createInterface({ input: child.stdout });
    return new Promise<ReadyChild>((resolveChild, reject) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          lines.close();
          child.kill("SIGTERM");
          reject(new Error(`${readyPrefix.trim()} readiness timed out`));
        }
      }, READY_TIMEOUT);
      const rejectExit = (code?: number | null, signal?: NodeJS.Signals | null) => {
        if (!settled) {
          settled = true;
          clearTimeout(timeout);
          lines.close();
          reject(
            new Error(
              `${readyPrefix.trim()} process exited before readiness (code=${code ?? "unknown"} signal=${signal ?? "none"})${startupFailure}`,
            ),
          );
        }
      };
      child.once("error", rejectExit);
      child.once("exit", (code, signal) => rejectExit(code, signal));
      lines.on("line", (line) => {
        if (settled || !line.startsWith(readyPrefix)) {
          return;
        }
        const origin = line.slice(readyPrefix.length).trim();
        if (!origin) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        resolveChild(new ReadyChild(child, origin, lines));
      });
    });
  }

  async stop(signal: NodeJS.Signals = "SIGTERM"): Promise<void> {
    if (this.child.exitCode !== null || this.child.signalCode !== null) {
      this.lines.close();
      return;
    }
    const exited = new Promise<void>((resolveExit) => {
      this.child.once("exit", () => resolveExit());
    });
    this.child.kill(signal);
    await Promise.race([
      exited,
      new Promise<void>((_, reject) =>
        setTimeout(() => reject(new Error("child process did not stop")), HTTP_TIMEOUT),
      )]);
    this.lines.close();
  }
}

class OAuthProviderFixture {
  private constructor(private readonly process: ReadyChild) {}

  static async start(): Promise<OAuthProviderFixture> {
    const process = await ReadyChild.start(
      processExecPath(),
      [PROVIDER_FIXTURE, "--port", "0"],
      "ZODE_OAUTH_FIXTURE_READY ",
      {},
    );
    return new OAuthProviderFixture(process);
  }

  get origin(): string {
    return this.process.origin;
  }

  async state(): Promise<FixtureState> {
    const response = await fetch(`${this.origin}/control/state`, { signal: timeoutSignal() });
    if (!response.ok) {
      throw new Error("OAuth fixture state request failed");
    }
    return (await response.json()) as FixtureState;
  }

  async setMode(mode: FixtureMode): Promise<void> {
    const response = await fetch(`${this.origin}/control/mode`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode }),
      signal: timeoutSignal()});
    if (!response.ok) {
      throw new Error("OAuth fixture mode change failed");
    }
  }

  async releaseRefresh(): Promise<void> {
    const response = await fetch(`${this.origin}/control/release-refresh`, {
      method: "POST",
      signal: timeoutSignal()});
    if (!response.ok) {
      throw new Error("OAuth fixture held refresh release failed");
    }
  }

  async waitFor(predicate: (state: FixtureState) => boolean, label: string): Promise<FixtureState> {
    const deadline = Date.now() + HTTP_TIMEOUT;
    while (Date.now() < deadline) {
      const current = await this.state();
      if (predicate(current)) {
        return current;
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 25));
    }
    throw new Error(`${label} fixture barrier timed out`);
  }

  async stop(): Promise<void> {
    await this.process.stop();
  }
}

async function writePrivateFile(path: string, content: string | Uint8Array): Promise<void> {
  await writeFile(path, content, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function buildTestOwnedUiDist(directory: string): Promise<void> {
  try {
    await execFileAsync(
      "vp",
      ["build", "--outDir", directory],
      { cwd: WEB_ROOT, env: { ...process.env }, timeout: UI_BUILD_TIMEOUT },
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `${ROUTE_MISSING_FOUNDATION_RED}: real Vite Plus UI build failed: ${detail}`,
    );
  }

  const indexPath = resolve(directory, "index.html");
  const indexMetadata = await stat(indexPath).catch(() => undefined);
  if (!indexMetadata?.isFile()) {
    throw new Error(
      `${ROUTE_MISSING_FOUNDATION_RED}: Vite Plus build omitted test-owned dist/index.html`,
    );
  }

  const index = await readFile(indexPath, "utf8");
  const candidates = [...index.matchAll(/(?:src|href)=["']([^"']+)["']/gi)]
    .map((match) => match[1])
    .filter((candidate): candidate is string => typeof candidate === "string");
  let assetPathname: string | undefined;
  for (const candidate of candidates) {
    try {
      const parsed = new URL(candidate, "http://zode.invalid");
      if (
        parsed.origin === "http://zode.invalid" &&
        /^\/assets\/[^/]+-[A-Za-z0-9_-]{8,}\.(?:js|mjs|css)$/i.test(parsed.pathname)
      ) {
        assetPathname = parsed.pathname;
        break;
      }
    } catch {
      // An unrelated malformed link does not count as the built asset.
    }
  }

  if (!assetPathname) {
    throw new Error(
      `${ROUTE_MISSING_FOUNDATION_RED}: Vite Plus index.html omitted a hashed asset reference`,
    );
  }
  const assetMetadata = await stat(resolve(directory, assetPathname.slice(1))).catch(
    () => undefined,
  );
  if (!assetMetadata?.isFile()) {
    throw new Error(
      `${ROUTE_MISSING_FOUNDATION_RED}: Vite Plus build omitted referenced asset ${assetPathname}`,
    );
  }
}

async function materializeProcessConfigs(
  root: string,
  provider: OAuthProviderFixture,
  access: AccessFixture,
): Promise<{ server: string; endpoint: string; controllerSecret: string }> {
  await mkdir(root, { recursive: true, mode: 0o700 });
  const configuredServer = process.env.ZODE_WEB_E2E_SERVER_CONFIG;
  const configuredEndpoint = process.env.ZODE_WEB_E2E_ENDPOINT_CONFIG;
  const serverTemplate = process.env.ZODE_WEB_E2E_SERVER_CONFIG_TEMPLATE;
  const endpointTemplate = process.env.ZODE_WEB_E2E_ENDPOINT_CONFIG_TEMPLATE;
  const serverPath = resolve(root, "server-config.json");
  const endpointPath = resolve(root, "endpoint-config.json");
  const uiAssetsDirectory = resolve(root, "ui-dist");
  await buildTestOwnedUiDist(uiAssetsDirectory);

  if (serverTemplate) {
    const template = await readFile(resolve(REPO_ROOT, serverTemplate), "utf8");
    const config = JSON.parse(
      template
        .replaceAll("${ACCESS_ISSUER}", access.issuer)
        .replaceAll("${ACCESS_JWKS_URL}", access.jwksUrl)
        .replaceAll("${ACCESS_AUDIENCE}", "zode-web-oauth-refresh-e2e")
        .replaceAll("${OAUTH_FIXTURE_ORIGIN}", provider.origin)
        .replaceAll("${ENDPOINT_CONFIG}", endpointPath)
        .replaceAll(
          "${ENDPOINT_BINARY}",
          process.env.ZODE_WEB_E2E_ENDPOINT_BIN ?? process.env.ZODE_ENDPOINT_BIN ?? resolve(REPO_ROOT, "target/debug/zode"),
        ),
    ) as Record<string, unknown>;
    config.ui_mode = "assets";
    config.ui_assets_directory = uiAssetsDirectory;
    config.management_origin = access.managementOrigin;
    config.callback_origin = access.callbackOrigin;
    config.provider_auth_adapters = [oauthAdapterConfig(provider)];
    await writePrivateFile(
      serverPath,
      JSON.stringify(config),
    );
  } else if (configuredServer) {
    const config = JSON.parse(
      await readFile(resolve(REPO_ROOT, configuredServer), "utf8"),
    ) as Record<string, unknown>;
    config.ui_mode = "assets";
    config.ui_assets_directory = uiAssetsDirectory;
    config.management_origin = access.managementOrigin;
    config.callback_origin = access.callbackOrigin;
    config.provider_auth_adapters = [oauthAdapterConfig(provider)];
    await writePrivateFile(serverPath, JSON.stringify(config));
  } else {
    const secretDirectory = resolve(root, "server-secrets");
    const subjectKey = resolve(root, "subject.key");
    await mkdir(secretDirectory, { recursive: true, mode: 0o700 });
    await writePrivateFile(subjectKey, Buffer.alloc(32, 0x5a));
    await writePrivateFile(
      serverPath,
      JSON.stringify({
        schema: "zode.server-config.v1",
        listen: "127.0.0.1:0",
        management_origin: access.managementOrigin,
        callback_origin: access.callbackOrigin,
        server_authority_id: "oauth-refresh-browser-server",
        deployment: "server_only",
        ui_mode: "assets",
        ui_assets_directory: uiAssetsDirectory,
        control_database: resolve(root, "server.sqlite"),
        secret_directory: secretDirectory,
        access: {
          issuer: access.issuer,
          audiences: ["zode-web-oauth-refresh-e2e"],
          jwks_url: access.jwksUrl,
          subject_key_file: subjectKey,
          subject_key_version: 1},
        provider_auth_adapters: [oauthAdapterConfig(provider)]}),
    );
  }

  if (endpointTemplate) {
    const template = await readFile(resolve(endpointTemplate), "utf8");
    await writePrivateFile(
      endpointPath,
      template.replaceAll("${OAUTH_FIXTURE_ORIGIN}", provider.origin),
    );
  } else if (configuredEndpoint) {
    await writePrivateFile(endpointPath, await readFile(resolve(REPO_ROOT, configuredEndpoint), "utf8"));
  } else {
    const replicas = resolve(root, "endpoint-replicas");
    const blobs = resolve(root, "endpoint-blobs");
    await mkdir(replicas, { recursive: true, mode: 0o700 });
    await mkdir(blobs, { recursive: true, mode: 0o700 });
    await writePrivateFile(
      endpointPath,
      JSON.stringify({
        schema: "zode.config.v1",
        listen: "127.0.0.1:0",
        runtime_store: { kind: "sqlite", path: resolve(root, "endpoint.sqlite") },
        credential_replica_store: { kind: "files", directory: replicas },
        blob_store: { kind: "files", directory: blobs },
        provider_execution: {
          adapter_kinds: ["openai_compatible"],
          allowed_base_url_origins: [provider.origin]},
        callback: { allowed_public_origins: [provider.origin] },
        tools: []}),
    );
  }
  return { server: serverPath, endpoint: endpointPath, controllerSecret: "" };
}

function oauthAdapterConfig(
  provider: OAuthProviderFixture,
  refreshRecovery: RefreshRecoveryMode = "same_operation_id_idempotent",
): Record<string, unknown> {
  return {
    provider: OAUTH_PROVIDER_ID,
    kind: "oauth2_authorization_code_pkce",
    authorization_endpoint: `${provider.origin}/oauth/authorize`,
    token_endpoint: `${provider.origin}/oauth/token`,
    client_id: "zode-oauth-browser-e2e",
    client_secret_file: null,
    scopes: ["models.execute"],
    refresh_recovery: refreshRecovery};
}

class ZodeBrowserHarness {
  private constructor(
    private readonly browserContext: BrowserContext,
    private readonly endpoint: ReadyChild | null,
    private server: ReadyChild,
    private readonly access: AccessFixture,
    private readonly serverArgs: string[],
    private readonly serverConfigPath: string,
    private readonly controllerSecret: string,
    private readonly tempRoot: string,
    readonly managementOrigin: string,
    readonly provider: OAuthProviderFixture,
    private readonly journal?: RecordingJournalContract,
    private readonly captureSetId?: string,
  ) {}

  static async start(
    browser: Browser,
    provider: OAuthProviderFixture,
    options: { recordE2EName?: string } = {},
  ): Promise<ZodeBrowserHarness> {
    const serverBinary =
      process.env.ZODE_WEB_E2E_SERVER_BIN ??
      process.env.ZODE_SERVER_BIN ??
      resolve(REPO_ROOT, "server/target/debug/zode-server");
    const endpointBinary =
      process.env.ZODE_WEB_E2E_ENDPOINT_BIN ??
      process.env.ZODE_ENDPOINT_BIN ??
      resolve(REPO_ROOT, "target/debug/zode");
    const allInOne = process.env.ZODE_WEB_E2E_ALL_IN_ONE === "1";
    if (!allInOne && !endpointBinary) {
      throw new Error("ZODE_WEB_E2E_ENDPOINT_BIN is required unless all-in-one is explicitly configured");
    }
    const tempRoot = await mkdtemp(resolve(tmpdir(), "zode-oauth-refresh-browser-"));
    const ledger = options.recordE2EName ? new SecretLedger() : undefined;
    ledger?.add("synthetic_oauth_refresh_marker", SYNTHETIC_SECRET_MARKER);
    const journal = options.recordE2EName
      ? new RecordingJournal({
          rootDir: resolve(
            REPO_ROOT,
            "target/test-recordings/quarantine",
            `provider-descriptor-${Date.now()}-${randomUUID()}`,
          ),
          ledger: ledger as SecretLedgerContract})
      : undefined;
    const captureSetId = journal?.beginCaptureSet({
      e2eName: options.recordE2EName as string,
      maxMembers: 16});
    const access = await AccessFixture.start({ ledger, journal, captureSetId });
    const configs = await materializeProcessConfigs(tempRoot, provider, access);
    const environment = {};
    const endpointArgs = jsonArgs(
      "ZODE_WEB_E2E_ENDPOINT_ARGS_JSON",
      configs.endpoint ? ["--config", configs.endpoint] : null,
    );
    const serverArgs = jsonArgs(
      "ZODE_WEB_E2E_SERVER_ARGS_JSON",
      configs.server ? ["--config", configs.server] : null,
    );
    const endpoint = allInOne
      ? null
      : await ReadyChild.start(
          endpointBinary as string,
          endpointArgs,
          "ZODE_READY ",
          environment,
        );
    const server = await ReadyChild.start(serverBinary, serverArgs, "ZODE_SERVER_READY ", environment);
    const edgeOrigin = await access.startEdge(server.origin);
    const configuredOrigin = process.env.ZODE_MANAGEMENT_ORIGIN;
    const managementOrigin = normalizeOrigin(configuredOrigin ?? edgeOrigin);
    const browserContext = await browser.newContext({
      baseURL: managementOrigin});
    return new ZodeBrowserHarness(
      browserContext,
      endpoint,
      server,
      access,
      serverArgs,
      configs.server,
      configs.controllerSecret,
      tempRoot,
      managementOrigin,
      provider,
      journal,
      captureSetId,
    );
  }

  get context(): BrowserContext {
    return this.browserContext;
  }

  async registerEndpoint(page: Page): Promise<string> {
    if (!this.endpoint) {
      throw new Error("OAuth distribution E2E requires a separate real Endpoint");
    }
    const registered = await browserApi(page, "/v1/endpoints", {
      method: "POST",
      idempotencyKey: `oauth-distribution-endpoint-${randomUUID()}`,
      body: {
        label: "OAuth distribution Endpoint",
        base_url: this.endpoint.origin }});
    expect(registered.status, registered.text).toBe(201);
    const endpointId = jsonObject(registered.value, "registered OAuth Endpoint").endpoint_id;
    if (typeof endpointId !== "string" || endpointId.length === 0) {
      throw new Error("registered OAuth Endpoint omitted its identity");
    }
    return endpointId;
  }

  failNextAuthRefreshProjections(count: number): void {
    this.access.failNextGets("/v1/auth-refresh-operations/", count);
  }

  get authRefreshProjectionFailures(): number {
    return this.access.projectionFailures;
  }

  async retainProviderDescriptorFailure(
    e2eName: string,
    requestPath: string,
    status: number,
  ): Promise<{ cassettePath?: string; rawPath?: string }> {
    if (!this.journal || !this.captureSetId) {
      throw new Error("provider descriptor recorder was not initialized before the request");
    }
    const record = this.journal.first({
      boundary: "management-access-edge",
      requestPath,
      responseStatus: status});
    if (!record) {
      throw new Error("provider descriptor failure exchange was not retained");
    }
    if (process.env.ZODE_CAPTURE_FIRST_OCCURRENCE !== "1") {
      const flushed = this.journal.flushCaptureSet(this.captureSetId, {
        firstFailureRecordingId: record.recordingId}) as { records?: Array<{ recordingId: string; rawPath?: string }> };
      return {
        rawPath: flushed.records?.find(
          (candidate) => candidate.recordingId === record.recordingId,
        )?.rawPath};
    }
    const promoted = await this.journal.promoteCaptureSet(this.captureSetId, {
      e2eName,
      classification: "PRODUCT_ROUTE_MISSING",
      firstObserved: `${requestPath} returned HTTP ${status}`,
      firstFailureRecordingId: record.recordingId,
      destinationDirectory: FIXTURE_DIR,
      replay: async (envelope: Record<string, unknown>) => {
        const results = await this.journal?.replay(envelope, {
          baseUrl: this.managementOrigin,
          boundaryBaseUrls: {
            "access-jwks-fixture": new URL(this.access.jwksUrl).origin}});
        const reproduced = results?.some(
          (result) =>
            result.path === requestPath &&
            result.status === status,
        );
        return { ok: reproduced === true, results };
      }});
    return { cassettePath: promoted.cassettePath };
  }

  async replayProviderDescriptorCassette(
    cassettePath: string,
  ): Promise<Array<{ path: string; status: number }>> {
    if (!this.journal) {
      throw new Error("provider descriptor recorder was not initialized for replay");
    }
    return this.journal.replay(cassettePath, {
      baseUrl: this.managementOrigin,
      boundaryBaseUrls: {
        "access-jwks-fixture": new URL(this.access.jwksUrl).origin}});
  }

  async restartServer(
    refreshRecovery?: RefreshRecoveryMode,
    whileStopped?: (serverConfigPath: string) => Promise<void>,
  ): Promise<void> {
    if (refreshRecovery !== undefined) {
      const config = JSON.parse(await readFile(this.serverConfigPath, "utf8")) as {
        provider_auth_adapters?: Array<Record<string, unknown>>;
      };
      const adapter = config.provider_auth_adapters?.find(
        (candidate) => candidate.provider === OAUTH_PROVIDER_ID,
      );
      if (!adapter) {
        throw new Error("OAuth browser harness Server config omitted its provider adapter");
      }
      adapter.refresh_recovery = refreshRecovery;
      await writePrivateFile(this.serverConfigPath, JSON.stringify(config));
    }
    await this.server.stop("SIGKILL");
    await whileStopped?.(this.serverConfigPath);
    const replacement = await ReadyChild.start(
      process.env.ZODE_WEB_E2E_SERVER_BIN ??
        process.env.ZODE_SERVER_BIN ??
        resolve(REPO_ROOT, "server/target/debug/zode-server"),
      this.serverArgs,
      "ZODE_SERVER_READY ",
      {},
    );
    this.access.setTarget(replacement.origin);
    this.server = replacement;
  }

  async close(): Promise<void> {
    await this.browserContext.close();
    await this.access.stop().catch(() => undefined);
    await this.server.stop().catch(() => undefined);
    await this.endpoint?.stop().catch(() => undefined);
    await rm(this.tempRoot, { recursive: true, force: true });
  }
}

function processExecPath(): string {
  return process.execPath;
}

function timeoutSignal(): AbortSignal {
  return AbortSignal.timeout(HTTP_TIMEOUT);
}

function installBrowserAudit(page: Page): BrowserAudit {
  const audit: BrowserAudit = {
    requests: [],
    authAttempts: [],
    ticketMints: [],
    ticketMintUrls: [],
    ticketRedemptions: [],
    callbackUrls: [],
    navigations: [],
    consoleMessages: [],
    consoleValueJobs: [],
    pageErrors: []};
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) {
      audit.navigations.push(frame.url());
    }
  });
  page.on("console", (message) => {
    audit.consoleMessages.push(message.text());
    audit.consoleValueJobs.push(
      Promise.all(
        message.args().map((argument) => argument.jsonValue().catch(() => "[unavailable-console-argument]")),
      ).then((values) => {
        audit.consoleMessages.push(...values.map((value) => safeSurfaceValue(value)));
      }),
    );
  });
  page.on("pageerror", (error) => {
    audit.pageErrors.push(error.message);
  });
  page.on("request", (request) => {
    const headers = request.headers();
    const observation: RequestObservation = {
      method: request.method(),
      url: request.url(),
      headers: { ...headers },
      referer: headers.referer ?? "",
      postData: request.postData() ?? ""};
    audit.requests.push(observation);
    const requestUrl = new URL(request.url());
    if (request.method() === "GET" && requestUrl.pathname.endsWith("/authorize")) {
      if (requestUrl.searchParams.has("ticket")) {
        audit.ticketRedemptions.push(request.url());
      }
    }
    if (request.method() === "GET" && requestUrl.pathname === "/v1/oauth/callback") {
      audit.callbackUrls.push(request.url());
    }
    if (request.method() === "POST" && requestUrl.pathname.endsWith("/auth-attempts")) {
      let body: JsonValue | null = null;
      try {
        body = JSON.parse(request.postData() ?? "null") as JsonValue;
      } catch {
        body = null;
      }
      audit.authAttempts.push({ ...observation, body });
    }
  });
  page.on("response", (response) => {
    const requestUrl = new URL(response.url());
    if (!requestUrl.pathname.endsWith("/authorize-tickets")) {
      return;
    }
    audit.ticketMintUrls.push(response.url());
    void response
      .json()
      .then((body: unknown) => {
        if (
          typeof body === "object" &&
          body !== null &&
          "ticket" in body &&
          typeof body.ticket === "string" &&
          body.ticket.length > 0
        ) {
          audit.ticketMints.push(body.ticket);
        }
      })
      .catch(() => undefined);
  });
  return audit;
}

function safeSurfaceValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function assertManagementOrigin(value: string, managementOrigin: string, label: string): URL {
  const parsed = new URL(value);
  expect(parsed.origin, `${label} must stay on the Access-protected management origin`).toBe(
    normalizeOrigin(managementOrigin),
  );
  return parsed;
}

function isManagementAuthorizePath(pathname: string): boolean {
  return /^\/v1\/auth-attempts\/[^/]+\/authorize$/.test(pathname);
}

function assertOAuthManagementOrigins(audit: BrowserAudit, managementOrigin: string): void {
  for (const request of audit.authAttempts) {
    assertManagementOrigin(request.url, managementOrigin, "OAuth attempt");
  }
  for (const url of audit.ticketMintUrls) {
    const parsed = assertManagementOrigin(url, managementOrigin, "authorize-ticket mint");
    expect(parsed.pathname).toMatch(/^\/v1\/auth-attempts\/[^/]+\/authorize-tickets$/);
  }
  for (const url of audit.ticketRedemptions) {
    const parsed = assertManagementOrigin(url, managementOrigin, "authorize-ticket redemption");
    expect(isManagementAuthorizePath(parsed.pathname)).toBe(true);
  }
  for (const url of audit.callbackUrls) {
    const parsed = assertManagementOrigin(url, managementOrigin, "OAuth callback");
    expect(parsed.pathname).toBe("/v1/oauth/callback");
  }
}

async function expectTicketMint(audit: BrowserAudit, previousCount: number): Promise<string> {
  await expect.poll(() => audit.ticketMints.length, { timeout: HTTP_TIMEOUT }).toBeGreaterThan(previousCount);
  const ticket = audit.ticketMints.at(-1);
  if (!ticket) {
    throw new Error("OAuth authorize-ticket response did not contain a ticket");
  }
  return ticket;
}

async function clickVisible(page: Page, role: "button" | "link", name: RegExp): Promise<void> {
  const candidate = page.getByRole(role, { name }).first();
  await expect(candidate).toBeVisible({ timeout: HTTP_TIMEOUT });
  await candidate.click();
}

async function fillIfVisible(page: Page, name: RegExp, value: string): Promise<void> {
  const candidate = page.getByRole("textbox", { name }).first();
  if (await candidate.isVisible().catch(() => false)) {
    await candidate.fill(value);
  }
}

async function pageDomSurface(page: Page): Promise<string> {
  return page.evaluate(() => {
    const collect = (root: Document | ShadowRoot): string => {
      let surface =
        root instanceof Document
          ? [
              document.body?.innerText ?? "",
              document.documentElement?.textContent ?? "",
              document.documentElement?.outerHTML ?? ""].join("\n")
          : root.innerHTML;
      const elements = root.querySelectorAll("*");
      for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
        const element = elements.item(elementIndex);
        if (!element) continue;
        surface += `\n${element.textContent ?? ""}\n${element.outerHTML}`;
        for (let attributeIndex = 0; attributeIndex < element.attributes.length; attributeIndex += 1) {
          const attribute = element.attributes.item(attributeIndex);
          if (attribute) {
            surface += `\n${attribute.name}=${attribute.value}`;
          }
        }
        if ("value" in element) {
          surface += `\nvalue=${String((element as HTMLInputElement).value)}`;
        }
        if (element.shadowRoot) {
          surface += element.shadowRoot.innerHTML;
          surface += collect(element.shadowRoot);
        }
      }
      return surface;
    };
    return collect(document);
  });
}

async function pageBrowserStorageSurface(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    const stringify = (value: unknown): string => {
      try {
        return JSON.stringify(value) ?? String(value);
      } catch {
        return String(value);
      }
    };
    const surface = [
      stringify(Object.fromEntries(Object.entries(localStorage))),
      stringify(Object.fromEntries(Object.entries(sessionStorage))),
      stringify(history.state),
      document.referrer,
      location.href,
      document.URL,
      window.name,
      String(history.length),
      ...performance
        .getEntriesByType("navigation")
        .map((entry) => entry.name)];
    if (typeof caches !== "undefined") {
      for (const name of await caches.keys()) {
        surface.push(name);
        const cache = await caches.open(name);
        for (const request of await cache.keys()) {
          surface.push(request.url);
        }
        for (const response of await cache.matchAll()) {
          surface.push((await response.clone().text().catch(() => "")).slice(0, 2 * 1024 * 1024));
        }
      }
    }
    if (typeof indexedDB !== "undefined" && "databases" in indexedDB) {
      const databases = await indexedDB.databases();
      for (const database of databases) {
        if (!database.name) continue;
        surface.push(database.name, stringify(database));
        await new Promise<void>((resolveDatabase) => {
          const openRequest = indexedDB.open(database.name as string);
          openRequest.onerror = () => resolveDatabase();
          openRequest.onsuccess = () => {
            const db = openRequest.result;
            const storeNames = Array.from(db.objectStoreNames);
            surface.push(...storeNames);
            if (storeNames.length === 0) {
              db.close();
              resolveDatabase();
              return;
            }
            let pending = storeNames.length;
            const finishStore = () => {
              pending -= 1;
              if (pending === 0) {
                db.close();
                resolveDatabase();
              }
            };
            let transaction: IDBTransaction;
            try {
              transaction = db.transaction(storeNames, "readonly");
            } catch {
              db.close();
              resolveDatabase();
              return;
            }
            for (const storeName of storeNames) {
              const getAllRequest = transaction.objectStore(storeName).getAll();
              getAllRequest.onsuccess = () => {
                surface.push(stringify(getAllRequest.result));
                finishStore();
              };
              getAllRequest.onerror = finishStore;
            }
            transaction.onerror = () => {
              db.close();
              resolveDatabase();
            };
          };
        });
      }
    }
    return surface;
  });
}

async function openProviders(page: Page, managementOrigin: string): Promise<void> {
  const response = await page.goto(`${managementOrigin}/providers`, {
    waitUntil: "domcontentloaded",
    timeout: HTTP_TIMEOUT});
  if (response) {
    assertManagementOrigin(response.url(), managementOrigin, "providers page");
  }
  if (response?.status() === 404) {
    throw new RouteMissingFoundationRed(
      "/providers",
      response.status(),
      "the real Server-backed providers page is not bootstrapped",
    );
  }
  expect(response?.status()).toBeLessThan(400);
  await expect(page.getByRole("heading", { name: /providers/i }).first()).toBeVisible({
    timeout: HTTP_TIMEOUT});
}

async function startOAuthAttempt(
  page: Page,
  audit: BrowserAudit,
  managementOrigin: string,
  label: string,
  replaceAuthProfileId?: string,
): Promise<string> {
  const previousAttempts = audit.authAttempts.length;
  const previousTickets = audit.ticketMints.length;
  await clickVisible(
    page,
    "button",
    replaceAuthProfileId === undefined
      ? /add\s+(an?\s+)?oauth|new\s+oauth|sign\s+in\s+with\s+provider/i
      : /relog ?in|log in again/i,
  );
  await fillIfVisible(page, /profile\s+label|account\s+label|label/i, label);
  await clickVisible(page, "button", /start\s+oauth|begin\s+oauth|create\s+oauth|continue(?!\s+to\s+provider)/i);
  await expect.poll(() => audit.authAttempts.length, { timeout: HTTP_TIMEOUT }).toBeGreaterThan(previousAttempts);
  const request = audit.authAttempts.at(-1);
  if (!request) {
    throw new Error("OAuth attempt request was not observed");
  }
  const attemptUrl = assertManagementOrigin(request.url, managementOrigin, "OAuth attempt");
  expect(attemptUrl.pathname).toMatch(/^\/v1\/providers\/[^/]+\/auth-attempts$/);
  if (replaceAuthProfileId !== undefined) {
    const body = request.body;
    const replacementProfileId =
      typeof body === "object" && body !== null && !Array.isArray(body)
        ? body.replace_auth_profile_id
        : undefined;
    if (
      replacementProfileId !== replaceAuthProfileId
    ) {
      throw new Error("relogin did not bind the auth attempt to the same profile");
    }
    if (
      typeof body !== "object" ||
      body === null ||
      Array.isArray(body) ||
      Object.keys(body).some((key) => /retry|new[_-]?profile/i.test(key))
    ) {
      throw new Error("refresh_unknown relogin used a generic retry or new-profile request");
    }
  }
  const ticket = await expectTicketMint(audit, previousTickets);
  const mintUrl = audit.ticketMintUrls.at(-1);
  if (!mintUrl) {
    throw new Error("OAuth authorize-ticket response URL was not observed");
  }
  const parsedMintUrl = assertManagementOrigin(mintUrl, managementOrigin, "authorize-ticket mint");
  expect(parsedMintUrl.pathname).toMatch(/^\/v1\/auth-attempts\/[^/]+\/authorize-tickets$/);
  return ticket;
}

async function assertNoTicketBeforeExplicitClick(page: Page, audit: BrowserAudit, ticket: string): Promise<void> {
  await Promise.all(audit.consoleValueJobs);
  const rendered = await pageDomSurface(page);
  const storage = await page.evaluate(() => ({
    local: JSON.stringify(localStorage),
    session: JSON.stringify(sessionStorage),
    history: JSON.stringify(history.state),
    historyLength: history.length,
    referrer: document.referrer}));
  const browserStorage = await pageBrowserStorageSurface(page);
  const cookies = await page.context().cookies();
  const requestContainsTicket = (request: RequestObservation): boolean =>
    request.url.includes(ticket) ||
    request.referer.includes(ticket) ||
    request.postData.includes(ticket) ||
    Object.values(request.headers).some((value) => value.includes(ticket));
  if (
    rendered?.includes(ticket) ||
    storage.local.includes(ticket) ||
    storage.session.includes(ticket) ||
    storage.history.includes(ticket) ||
    storage.referrer.includes(ticket) ||
    browserStorage.some((surface) => surface.includes(ticket)) ||
    page.url().includes(ticket) ||
    cookies.some((cookie) => `${cookie.name}=${cookie.value}`.includes(ticket)) ||
    audit.navigations.some((url) => url.includes(ticket)) ||
    audit.consoleMessages.some((message) => message.includes(ticket)) ||
    audit.pageErrors.some((message) => message.includes(ticket))
  ) {
    throw new Error("OAuth authorize ticket was exposed before the explicit action");
  }
  await expect(page.locator('a[href*="ticket="], link[href*="ticket="]').first()).toHaveCount(0);
  if (audit.requests.some(requestContainsTicket)) {
    throw new Error("OAuth authorize ticket was prefetched before the explicit action");
  }
}

async function redeemWithExplicitLocationReplaceButton(
  page: Page,
  audit: BrowserAudit,
  provider: OAuthProviderFixture,
  managementOrigin: string,
  ticket: string,
): Promise<{ historyLength: number; redemptionUrl: string }> {
  await assertNoTicketBeforeExplicitClick(page, audit, ticket);
  const before = await page.evaluate(() => ({ historyLength: history.length, url: location.href }));
  const providerBefore = await provider.state();
  const previousRedemptions = audit.ticketRedemptions.length;
  const previousNavigations = audit.navigations.length;
  await clickVisible(page, "button", /continue\s+to\s+provider|open\s+provider|authorize|proceed/i);
  await provider.waitFor(
    (current) => current.authorize_count > providerBefore.authorize_count,
    "provider authorize",
  );
  await expect.poll(() => audit.ticketRedemptions.length, { timeout: HTTP_TIMEOUT }).toBeGreaterThan(previousRedemptions);
  await expect
    .poll(() => audit.navigations.length, { timeout: HTTP_TIMEOUT })
    .toBeGreaterThan(previousNavigations);
  const navigationUrl = audit.navigations.at(-1);
  if (!navigationUrl) {
    throw new Error("explicit OAuth action did not produce a browser navigation");
  }
  const navigation = new URL(navigationUrl);
  expect(navigation.origin).toBe(provider.origin);
  expect(navigation.pathname).toBe("/oauth/authorize");
  expect(navigation.searchParams.has("ticket")).toBe(false);
  expect(navigationUrl).not.toBe(before.url);
  await expect(page.getByRole("heading", { name: /fixture provider authorization/i })).toBeVisible({
    timeout: HTTP_TIMEOUT});
  // A real top-level browser navigation happened only after the explicit
  // button click. Keeping the same history entry is the observable contract
  // of location.replace, rather than a mock or an in-app route transition.
  await expect
    .poll(() => page.evaluate(() => history.length), { timeout: HTTP_TIMEOUT })
    .toBe(before.historyLength);
  expect(page.url()).toBe(navigationUrl);
  const managementRedemptions = audit.ticketRedemptions
    .slice(previousRedemptions)
    .map((url) => ({ url, parsed: new URL(url) }))
    .filter(({ parsed }) => isManagementAuthorizePath(parsed.pathname));
  if (managementRedemptions.length !== 1) {
    throw new Error("explicit OAuth action did not use exactly one management-origin ticket redemption");
  }
  const redemption = managementRedemptions[0];
  const redemptionUrl = redemption.url;
  assertManagementOrigin(redemptionUrl, managementOrigin, "authorize-ticket redemption");
  expect(redemption.parsed.searchParams.get("ticket")).toBe(ticket);
  return { historyLength: before.historyLength, redemptionUrl };
}

async function finishProviderDecision(
  page: Page,
  audit: BrowserAudit,
  managementOrigin: string,
  ticket: string,
  decision: "approve" | "cancel",
  expectedUiText: RegExp,
  expectedCallback: "authorization_code" | "provider_error" | "access_denied" =
    decision === "approve" ? "authorization_code" : "access_denied",
): Promise<void> {
  const previousCallbacks = audit.callbackUrls.length;
  await clickVisible(page, "button", decision === "approve" ? /approve|allow/i : /cancel/i);
  await expect
    .poll(() => audit.callbackUrls.length, { timeout: HTTP_TIMEOUT })
    .toBeGreaterThan(previousCallbacks);
  const callbackUrl = audit.callbackUrls.at(-1);
  if (!callbackUrl) {
    throw new Error("OAuth provider decision did not navigate through the management callback");
  }
  const callback = assertManagementOrigin(callbackUrl, managementOrigin, "OAuth callback");
  expect(callback.pathname).toBe("/v1/oauth/callback");
  expect(callback.searchParams.has("state")).toBe(true);
  if (expectedCallback === "authorization_code") {
    expect(callback.searchParams.has("code")).toBe(true);
  } else if (expectedCallback === "access_denied") {
    expect(callback.searchParams.get("error")).toBe("access_denied");
  } else {
    expect(callback.searchParams.has("code")).toBe(false);
    expect(callback.searchParams.has("error")).toBe(true);
  }
  await expect(page.getByRole("heading", { name: /fixture provider authorization/i })).toHaveCount(0, {
    timeout: HTTP_TIMEOUT});
  await expect(page.getByText(expectedUiText).first()).toBeVisible({ timeout: HTTP_TIMEOUT });
  await assertTicketNotExposed(page, audit, managementOrigin, ticket);
  assertOAuthManagementOrigins(audit, managementOrigin);
}

async function assertTicketNotExposed(
  page: Page,
  audit: BrowserAudit,
  managementOrigin: string,
  ticket: string,
): Promise<void> {
  await Promise.all(audit.consoleValueJobs);
  const rendered = await pageDomSurface(page);
  const storage = await page.evaluate(() => ({
    local: JSON.stringify(localStorage),
    session: JSON.stringify(sessionStorage),
    history: JSON.stringify(history.state),
    referrer: document.referrer}));
  const browserStorage = await pageBrowserStorageSurface(page);
  const cookies = await page.context().cookies();
  const ticketRequests = audit.requests.filter(
    (request) =>
      request.url.includes(ticket) ||
      request.referer.includes(ticket) ||
      request.postData.includes(ticket) ||
      Object.values(request.headers).some((value) => value.includes(ticket)),
  );
  const redemptionUrls = ticketRequests.filter((request) => {
    const requestUrl = new URL(request.url);
    return (
      request.method === "GET" &&
      requestUrl.origin === normalizeOrigin(managementOrigin) &&
      isManagementAuthorizePath(requestUrl.pathname) &&
      requestUrl.searchParams.get("ticket") === ticket
    );
  });
  const unexpectedRequest = ticketRequests.find((request) => !redemptionUrls.includes(request));
  const analytics = ticketRequests.find((request) => /analytics|telemetry|track|beacon|collect/i.test(request.url));
  if (
    rendered?.includes(ticket) ||
    storage.local.includes(ticket) ||
    storage.session.includes(ticket) ||
    storage.history.includes(ticket) ||
    storage.referrer.includes(ticket) ||
    browserStorage.some((surface) => surface.includes(ticket)) ||
    page.url().includes(ticket) ||
    cookies.some((cookie) => `${cookie.name}=${cookie.value}`.includes(ticket)) ||
    audit.navigations.some((url) => url.includes(ticket)) ||
    unexpectedRequest ||
    redemptionUrls.length !== 1 ||
    analytics ||
    audit.consoleMessages.some((message) => message.includes(ticket)) ||
    audit.pageErrors.some((message) => message.includes(ticket))
  ) {
    throw new Error("OAuth authorize ticket was disclosed outside the explicit replace navigation");
  }
  await expect(page.locator('a[href*="ticket="], link[href*="ticket="]').first()).toHaveCount(0);
}

function assertEachMintedTicketRedeemedOnce(audit: BrowserAudit, managementOrigin: string): void {
  for (const ticket of new Set(audit.ticketMints)) {
    const redemptions = audit.ticketRedemptions.filter((url) => {
      try {
        const parsed = new URL(url);
        return (
          parsed.origin === normalizeOrigin(managementOrigin) &&
          isManagementAuthorizePath(parsed.pathname) &&
          parsed.searchParams.get("ticket") === ticket
        );
      } catch {
        return false;
      }
    });
    if (redemptions.length !== 1) {
      throw new Error("an OAuth authorize ticket was reused or never explicitly redeemed");
    }
  }
}

function findProfiles(value: JsonValue, label: string, profiles: Array<{ id: string; revision: number }> = []): Array<{ id: string; revision: number }> {
  if (Array.isArray(value)) {
    for (const child of value) {
      findProfiles(child, label, profiles);
    }
    return profiles;
  }
  if (typeof value !== "object" || value === null) {
    return profiles;
  }
  if (
    typeof value.auth_profile_id === "string" &&
    value.label === label &&
    typeof value.revision === "number"
  ) {
    profiles.push({ id: value.auth_profile_id, revision: value.revision });
  }
  for (const child of Object.values(value)) {
    findProfiles(child, label, profiles);
  }
  return profiles;
}

async function reloadProvidersAndReadProfiles(page: Page, managementOrigin: string, label: string): Promise<Array<{ id: string; revision: number }>> {
  const profilesPath =
    `/v1/providers/${encodeURIComponent(OAUTH_PROVIDER_ID)}/auth-profiles`;
  await page.reload({ waitUntil: "domcontentloaded", timeout: HTTP_TIMEOUT });
  const response = await browserApi(page, profilesPath);
  if (response.status === 404) {
    throw new RouteMissingFoundationRed(
      profilesPath,
      response.status,
      "the real Server provider catalog route is not bootstrapped",
    );
  }
  expect(new URL(page.url()).origin).toBe(normalizeOrigin(managementOrigin));
  expect(response.status).toBe(200);
  const value = response.value;
  const profiles = findProfiles(value, label);
  if (profiles.length === 0) {
    throw new Error("successful OAuth profile was not present in the Server provider response");
  }
  return profiles;
}

async function reloadProvidersAndReadProfile(page: Page, managementOrigin: string, label: string): Promise<{ id: string; revision: number }> {
  const profiles = await reloadProvidersAndReadProfiles(page, managementOrigin, label);
  for (const profile of profiles) {
    expect(profile.id).not.toBe("");
  }
  return profiles[0];
}

async function clickProfileAction(page: Page, action: RegExp): Promise<void> {
  await clickVisible(page, "button", action);
}

function refreshAdmissionCount(audit: BrowserAudit): number {
  return audit.requests.filter((request) => {
    try {
      const parsed = new URL(request.url);
      return request.method === "POST" && parsed.pathname.endsWith("/refresh-operations");
    } catch {
      return false;
    }
  }).length;
}

async function assertNoVisibleControl(page: Page, role: "button" | "link", name: RegExp, label: string): Promise<void> {
  const controls = page.getByRole(role, { name });
  const visibleCount = await controls.evaluateAll((elements) =>
    elements.filter((element) => {
      const style = window.getComputedStyle(element);
      return style.display !== "none" && style.visibility !== "hidden" && element.getClientRects().length > 0;
    }).length,
  );
  expect(visibleCount, label).toBe(0);
}

async function assertRefreshUnknownFencedUi(page: Page): Promise<void> {
  await expect(page.getByRole("button", { name: /refresh/i }).first()).toHaveCount(0);
  for (const role of ["button", "link"] as const) {
    await assertNoVisibleControl(page, role, /\bretry\b|\btry again\b/i, "refresh_unknown exposed a generic retry control");
    await assertNoVisibleControl(
      page,
      role,
      /new\s+oauth|add\s+(an?\s+)?oauth|sign\s+in\s+with\s+provider|new\s+profile|add\s+profile/i,
      "refresh_unknown exposed a new OAuth profile bypass",
    );
  }
  await expect(page.getByRole("button", { name: /relog ?in|log in again/i }).first()).toBeVisible({
    timeout: HTTP_TIMEOUT});
}

async function waitForSafeUiState(page: Page, pattern: RegExp): Promise<void> {
  await expect(page.getByText(pattern).first()).toBeVisible({ timeout: HTTP_TIMEOUT });
}

async function assertSecretMarkersAbsent(page: Page, context: BrowserContext, audit: BrowserAudit): Promise<void> {
  await Promise.all(audit.consoleValueJobs);
  const domSurface = await pageDomSurface(page);
  const urlAndHistorySurface = await page.evaluate(() => [
    location.href,
    document.URL,
    document.referrer,
    window.name,
    JSON.stringify(history.state),
    String(history.length),
    ...performance.getEntriesByType("navigation").map((entry) => entry.name)]);
  const browserSurface = [
    domSurface,
    ...urlAndHistorySurface,
    ...(await pageBrowserStorageSurface(page)),
    ...(await context.cookies()).map((cookie) => `${cookie.name}=${cookie.value}`),
    ...audit.consoleMessages,
    ...audit.pageErrors,
    ...audit.navigations,
    ...audit.requests.flatMap((request) => [
      request.url,
      request.referer,
      request.postData,
      ...Object.entries(request.headers).map(([name, value]) => `${name}=${value}`)])];
  if (browserSurface.some((surface) => SECRET_MARKERS.some((marker) => surface.includes(marker)))) {
    throw new Error("a provider secret marker crossed the browser boundary");
  }
}

type IncidentExchange = IncidentCassette["exchanges"][number];

function assertIncidentCassetteContract(
  cassette: IncidentCassette,
  verifyPinnedDigest = true,
): IncidentExchange {
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.recording_id).toBe(INCIDENT_RECORDING_ID);
  expect(cassette.owner).toBe("e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure");
  expect(cassette.boundary).toBe("management_http_browser");
  expect(cassette.secret_slots).toEqual([]);
  expect(cassette.first_observed_outcome).toEqual({
    sequence: 1,
    status: 404,
    safe_error: "missing_public_provider_route",
    response_fingerprint: INCIDENT_RESPONSE_FINGERPRINT,
    classification: "PRODUCT_ROUTE_MISSING_SHALLOW_404",
    non_evidence: true});
  expect(cassette.exchanges).toHaveLength(1);
  const exchange = cassette.exchanges[0];
  if (!exchange) {
    throw new Error("OAuth browser incident cassette has no exchange");
  }
  expect(exchange.sequence).toBe(1);
  expect(exchange.request).toEqual({
    method: "GET",
    path: INCIDENT_PATH,
    semantic_headers: [],
    raw_body_hex: "",
    canonical_json: null,
    body_sha256: EMPTY_BODY_SHA256,
    fingerprint: INCIDENT_REQUEST_FINGERPRINT});
  expect(exchange.recorded_response).toEqual({
    status: 404,
    semantic_headers: [],
    body_hex: "",
    body_sha256: EMPTY_BODY_SHA256,
    outcome: "complete",
    fingerprint: INCIDENT_RESPONSE_FINGERPRINT});
  expect(exchange.contract).toEqual({
    status: 404,
    kind: "missing_public_provider_route"});
  expect(cassette.expected_after_fix).toEqual({
    status: 200,
    safe_outcome: "management_ui_bootstrapped"});
  expect(cassette.replay_policy).toEqual({
    shallow_404_is_non_evidence: true,
    continue_only_after_status: 200});

  if (verifyPinnedDigest) {
    const { whole_digest: recordedDigest, ...withoutDigest } = cassette;
    expect(recordedDigest).toBe(INCIDENT_WHOLE_DIGEST);
    expect(recordedDigest).toBe(`sha256:${sha256(JSON.stringify(withoutDigest))}`);
  }
  return exchange;
}

function cloneIncidentCassette(cassette: IncidentCassette): IncidentCassette {
  return JSON.parse(JSON.stringify(cassette)) as IncidentCassette;
}

function refreshIncidentCassetteDigest(cassette: IncidentCassette): void {
  const { whole_digest: _recordedDigest, ...withoutDigest } = cassette;
  cassette.whole_digest = `sha256:${sha256(JSON.stringify(withoutDigest))}`;
}

function assertOfflineReplayContractRejectsMutations(cassette: IncidentCassette): void {
  // Constructible red E2E contract: each clone remains a self-consistent
  // envelope, but changes one public exchange fact. This runs before any
  // Server/Endpoint/provider starts, so a replay contract failure cannot hide
  // behind product behavior or a live request.
  const mutations: Array<{ label: string; apply: (clone: IncidentCassette) => void }> = [
    {
      label: "request semantic header",
      apply: (clone) => {
        clone.exchanges[0]!.request.semantic_headers = [
          { name: "x-replay-contract-mutation", value: "changed" }];
      }},
    {
      label: "request path/query",
      apply: (clone) => {
        clone.exchanges[0]!.request.path = `${INCIDENT_PATH}?replay_contract_mutation=1`;
      }},
    {
      label: "exchange sequence",
      apply: (clone) => {
        clone.exchanges[0]!.sequence = 2;
      }}];

  for (const mutation of mutations) {
    const clone = cloneIncidentCassette(cassette);
    mutation.apply(clone);
    refreshIncidentCassetteDigest(clone);
    let rejected = false;
    try {
      assertIncidentCassetteContract(clone, false);
    } catch {
      rejected = true;
    }
    expect(rejected, `${mutation.label} mutation was accepted by offline replay contract`).toBe(true);
  }

  assertIncidentCassetteContract(cassette);
}

async function replayFirstBrowserFailure(page: Page, managementOrigin: string): Promise<Response | null> {
  const cassette = await readJsonFile<IncidentCassette>(INCIDENT_CASSETTE);
  const exchange = assertIncidentCassetteContract(cassette);
  const response = await page.goto(`${managementOrigin}${exchange.request.path}`, {
    waitUntil: "commit",
    timeout: HTTP_TIMEOUT});
  if (response) {
    assertManagementOrigin(response.url(), managementOrigin, "first-failure replay");
  }
  const body = response ? await response.body() : Buffer.alloc(0);
  const observedBodyHex = body.toString("hex");
  const matchesRecordedFailure =
    response?.status() === exchange.recorded_response.status &&
    observedBodyHex === exchange.recorded_response.body_hex;
  if (response?.status() === 404 && matchesRecordedFailure) {
    throw new RouteMissingFoundationRed(
      exchange.request.path,
      response.status(),
      "the retained first real-browser exchange replayed exactly",
    );
  }
  if (response?.status() === exchange.recorded_response.status) {
    throw new Error("OAuth browser exchange changed without the recorded failure being fixed");
  }
  expect(response?.status()).toBe(cassette.expected_after_fix.status);
  return response;
}

async function configureOAuthProvider(page: Page, provider: OAuthProviderFixture): Promise<void> {
  const result = await page.evaluate(
    async ({ providerId, baseUrl }) => {
      const response = await fetch(`/v1/providers/${encodeURIComponent(providerId)}`, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "oauth-browser-provider-descriptor"},
        body: JSON.stringify({
          kind: "openai_compatible",
          base_url: baseUrl,
          models: ["oauth-browser-model"],
          options: {}})});
      return { status: response.status, body: await response.text() };
    },
    { providerId: OAUTH_PROVIDER_ID, baseUrl: provider.origin },
  );
  expect(result.status, result.body).toBe(200);
}

type BrowserApiResult = {
  status: number;
  text: string;
  value: JsonValue | null;
};

async function browserApi(
  page: Page,
  path: string,
  options: { method?: string; idempotencyKey?: string; body?: JsonValue } = {},
): Promise<BrowserApiResult> {
  return page.evaluate(
    async ({ requestPath, requestOptions }) => {
      const headers: Record<string, string> = { accept: "application/json" };
      if (requestOptions.idempotencyKey) {
        headers["idempotency-key"] = requestOptions.idempotencyKey;
      }
      if (requestOptions.body !== undefined) {
        headers["content-type"] = "application/json";
      }
      const response = await fetch(requestPath, {
        method: requestOptions.method ?? "GET",
        headers,
        body:
          requestOptions.body === undefined
            ? undefined
            : JSON.stringify(requestOptions.body)});
      const text = await response.text();
      let value: JsonValue | null = null;
      try {
        value = JSON.parse(text) as JsonValue;
      } catch {
        // The caller still receives the bounded raw text for a useful assertion.
      }
      return { status: response.status, text, value };
    },
    { requestPath: path, requestOptions: options },
  );
}

function jsonObject(value: JsonValue | null, label: string): { [key: string]: JsonValue } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} did not return a JSON object`);
  }
  return value;
}

async function runOAuthAttemptThroughPublicBrowser(
  page: Page,
  harness: ZodeBrowserHarness,
  label: string,
  options: {
    mode: "oauth_success" | "oauth_failed" | "oauth_cancelled";
    decision: "approve" | "cancel";
    replaceAuthProfileId?: string;
    expectedStatus: "succeeded" | "failed" | "cancelled";
    sharing?: { mode: "none" | "selected"; endpoint_ids: string[] };
  },
): Promise<{ attemptId: string; profileId: string; status: string }> {
  await harness.provider.setMode(options.mode);
  const attemptResponse = await browserApi(
    page,
    `/v1/providers/${encodeURIComponent(OAUTH_PROVIDER_ID)}/auth-attempts`,
    {
      method: "POST",
      idempotencyKey: `oauth-attempt-${randomUUID()}`,
      body: {
        label,
        make_default: true,
        sharing: options.sharing ?? { mode: "none", endpoint_ids: [] },
        ...(options.replaceAuthProfileId === undefined
          ? {}
          : { replace_auth_profile_id: options.replaceAuthProfileId })}},
  );
  expect(attemptResponse.status, attemptResponse.text).toBe(201);
  const attempt = jsonObject(attemptResponse.value, "OAuth attempt");
  if (typeof attempt.attempt_id !== "string" || typeof attempt.auth_profile_id !== "string") {
    throw new Error("OAuth attempt omitted its stable identities");
  }
  const attemptId = attempt.attempt_id;
  const profileId = attempt.auth_profile_id;

  const ticketResponse = await browserApi(
    page,
    `/v1/auth-attempts/${encodeURIComponent(attemptId)}/authorize-tickets`,
    { method: "POST", idempotencyKey: `oauth-ticket-${randomUUID()}` },
  );
  expect(ticketResponse.status, ticketResponse.text).toBe(201);
  const ticket = jsonObject(ticketResponse.value, "OAuth authorize ticket").ticket;
  if (typeof ticket !== "string" || ticket.length === 0) {
    throw new Error("OAuth authorize ticket was absent");
  }

  const authorizeUrl = `${harness.managementOrigin}/v1/auth-attempts/${encodeURIComponent(attemptId)}/authorize?ticket=${encodeURIComponent(ticket)}`;
  const historyLength = await page.evaluate(() => history.length);
  await page.evaluate((url) => location.replace(url), authorizeUrl);
  await expect(page.getByRole("heading", { name: /fixture provider authorization/i })).toBeVisible({
    timeout: HTTP_TIMEOUT});
  const providerUrl = new URL(page.url());
  expect(providerUrl.origin).toBe(harness.provider.origin);
  expect(providerUrl.pathname).toBe("/oauth/authorize");
  expect(providerUrl.searchParams.has("ticket")).toBe(false);
  await expect.poll(() => page.evaluate(() => history.length), { timeout: HTTP_TIMEOUT }).toBe(historyLength);

  await Promise.all([
    page.waitForURL(
      (url) =>
        url.origin === harness.managementOrigin &&
        url.pathname === "/providers" &&
        url.searchParams.get("oauth_attempt") === attemptId,
      { timeout: HTTP_TIMEOUT },
    ),
    page
      .getByRole("button", {
        name: options.decision === "approve" ? /approve|allow/i : /cancel/i})
      .click()]);

  await expect
    .poll(
      async () => {
        const current = await browserApi(
          page,
          `/v1/auth-attempts/${encodeURIComponent(attemptId)}`,
        );
        return jsonObject(current.value, "completed OAuth attempt").status;
      },
      { timeout: HTTP_TIMEOUT },
    )
    .toBe(options.expectedStatus);
  return { attemptId, profileId, status: options.expectedStatus };
}

async function createOAuthProfileThroughPublicBrowser(
  page: Page,
  harness: ZodeBrowserHarness,
  label: string,
  replaceAuthProfileId?: string,
): Promise<{ id: string; revision: number }> {
  const completed = await runOAuthAttemptThroughPublicBrowser(page, harness, label, {
    mode: "oauth_success",
    decision: "approve",
    replaceAuthProfileId,
    expectedStatus: "succeeded"});
  const profile = (await readOAuthProfiles(page)).find(
    (candidate) => candidate.id === completed.profileId,
  );
  if (!profile) {
    throw new Error("successful OAuth attempt did not expose its profile");
  }
  return { id: completed.profileId, revision: profile.revision };
}

type PublicOAuthProfile = {
  id: string;
  revision: number;
  refreshState: string;
  allowedActions: string[];
};

async function readOAuthProfiles(page: Page): Promise<PublicOAuthProfile[]> {
  const profiles = await browserApi(
    page,
    `/v1/providers/${encodeURIComponent(OAUTH_PROVIDER_ID)}/auth-profiles`,
  );
  expect(profiles.status, profiles.text).toBe(200);
  const items = jsonObject(profiles.value, "OAuth profiles").items;
  if (!Array.isArray(items)) {
    throw new Error("OAuth profile list omitted items");
  }
  return items.map((item) => {
    if (
      typeof item === "object" &&
      item !== null &&
      !Array.isArray(item) &&
      typeof item.auth_profile_id === "string" &&
      typeof item.revision === "number" &&
      typeof item.refresh_state === "string" &&
      Array.isArray(item.allowed_actions) &&
      item.allowed_actions.every((action) => typeof action === "string")
    ) {
      return {
        id: item.auth_profile_id,
        revision: item.revision,
        refreshState: item.refresh_state,
        allowedActions: item.allowed_actions};
    }
    throw new Error("OAuth profile projection was invalid");
  });
}

const FORBIDDEN_PROVIDER_LIST_FIELDS = [
  "api_key",
  "access_token",
  "refresh_token",
  "secret",
  "oauth_state",
  "pkce",
  "authorization_code",
  "ticket",
  "access_actor_key",
  "sub",
  "common_name",
  "email",
  "subject",
  "actor"] as const;

function assertEmptyProviderListProjection(value: JsonValue): void {
  expect(value).toEqual({ schema: "zode.providers.v1", providers: [] });
  const serialized = JSON.stringify(value);
  for (const field of FORBIDDEN_PROVIDER_LIST_FIELDS) {
    expect(serialized).not.toContain(`"${field}"`);
  }
  for (const marker of SECRET_MARKERS) {
    expect(serialized).not.toContain(marker);
  }
}

async function findProviderDescriptorCassette(): Promise<string | undefined> {
  const matches: string[] = [];
  for (const entry of await readdir(FIXTURE_DIR)) {
    if (!entry.endsWith(".v1.json")) continue;
    const pathname = resolve(FIXTURE_DIR, entry);
    const value = JSON.parse(await readFile(pathname, "utf8")) as {
      schema?: unknown;
      version?: unknown;
      e2e_name?: unknown;
      classification?: unknown;
      exchanges?: Array<{
        boundary?: unknown;
        method?: unknown;
        path?: unknown;
        response?: { status?: unknown };
      }>;
    };
    if (value.e2e_name !== PROVIDER_DESCRIPTOR_E2E) continue;
    const failure = value.exchanges?.find(
      (exchange) =>
        exchange.boundary === "management-access-edge" &&
        exchange.method === "PUT" &&
        exchange.path === PROVIDER_DESCRIPTOR_PATH,
    );
    if (
      value.schema !== "zode.http-incident-recording.v1" ||
      value.version !== 1 ||
      value.classification !== "PRODUCT_ROUTE_MISSING" ||
      failure?.response?.status !== 404
    ) {
      throw new Error("provider descriptor cassette contract is invalid");
    }
    matches.push(pathname);
  }
  if (matches.length > 1) {
    throw new Error("provider descriptor E2E found more than one immutable cassette");
  }
  return matches[0];
}

function assertProviderDescriptor(
  value: JsonValue,
  providerBaseUrl: string,
): asserts value is { [key: string]: JsonValue } {
  expect(value).toEqual({
    schema: "zode.provider-descriptor.v1",
    provider: PROVIDER_DESCRIPTOR_ID,
    revision: 1,
    kind: "openai_compatible",
    base_url: providerBaseUrl,
    models: ["descriptor-model-a", "descriptor-model-b"],
    model_limits: {},
    options: { organization: "descriptor-org" }});
  const serialized = JSON.stringify(value);
  for (const forbidden of FORBIDDEN_PROVIDER_LIST_FIELDS) {
    expect(serialized).not.toContain(`"${forbidden}"`);
  }
  for (const marker of SECRET_MARKERS) {
    expect(serialized).not.toContain(marker);
  }
}

test.describe("Server provider-list foundation", () => {
  test(
    "e2e_server_provider_list_returns_versioned_empty_authority_projection",
    async ({ browser }, testInfo) => {
      test.setTimeout(180_000);
      const provider = await OAuthProviderFixture.start();
      const harness = await ZodeBrowserHarness.start(browser, provider);
      const page = await harness.context.newPage();
      try {
        const response = await replayFirstBrowserFailure(page, harness.managementOrigin);
        if (!response) {
          throw new Error("real Access/Server provider-list response was not observed");
        }
        const body = await response.text();
        const value = JSON.parse(body) as JsonValue;
        expect(response.status()).toBe(200);
        assertEmptyProviderListProjection(value);
      } catch (error) {
        if (error instanceof RouteMissingFoundationRed) {
          testInfo.annotations.push({
            type: "failure-classification",
            description: `${error.stage}:${error.classification}`});
        }
        throw error;
      } finally {
        await page.close().catch(() => undefined);
        await harness.close().catch(() => undefined);
        await provider.stop().catch(() => undefined);
      }
    },
  );

  test(
    PROVIDER_DESCRIPTOR_E2E,
    async ({ browser }) => {
      test.setTimeout(180_000);
      const cassette = await findProviderDescriptorCassette();
      const provider = await OAuthProviderFixture.start();
      const harness = await ZodeBrowserHarness.start(browser, provider, {
        recordE2EName: PROVIDER_DESCRIPTOR_E2E});
      const page = await harness.context.newPage();
      const providerBaseUrl = "https://models.descriptor-roundtrip.test/v1";
      const requestBody = {
        kind: "openai_compatible",
        base_url: providerBaseUrl,
        models: ["descriptor-model-a", "descriptor-model-b"],
        options: { organization: "descriptor-org" }};
      try {
        const system = await page.goto(`${harness.managementOrigin}/v1/system`, {
          waitUntil: "commit",
          timeout: HTTP_TIMEOUT});
        expect(system?.status()).toBe(200);
        const mutation = await page.evaluate(
          async ({ path, body }) => {
            const response = await fetch(path, {
              method: "PUT",
              headers: {
                "content-type": "application/json",
                "idempotency-key": "provider-descriptor-roundtrip"},
              body: JSON.stringify(body)});
            return {
              status: response.status,
              text: await response.text()};
          },
          { path: PROVIDER_DESCRIPTOR_PATH, body: requestBody },
        );

        if (mutation.status !== 200) {
          if (cassette && mutation.status === 404) {
            const replay = await harness.replayProviderDescriptorCassette(cassette);
            expect(
              replay.some(
                (result) =>
                  result.path === PROVIDER_DESCRIPTOR_PATH &&
                result.status === 404,
              ),
            ).toBe(true);
            throw new Error("provider descriptor route still replays its retained HTTP 404");
          }
          const retained = await harness.retainProviderDescriptorFailure(
            PROVIDER_DESCRIPTOR_E2E,
            PROVIDER_DESCRIPTOR_PATH,
            mutation.status,
          );
          throw new Error(
            `provider descriptor mutation returned ${mutation.status}; retained=${retained.cassettePath ?? retained.rawPath ?? "unavailable"}`,
          );
        }

        const descriptor = JSON.parse(mutation.text) as JsonValue;
        assertProviderDescriptor(descriptor, providerBaseUrl);

        const replayMutation = await page.evaluate(
          async ({ path, body }) => {
            const response = await fetch(path, {
              method: "PUT",
              headers: {
                "content-type": "application/json",
                "idempotency-key": "provider-descriptor-roundtrip"},
              body: JSON.stringify(body)});
            return { status: response.status, text: await response.text() };
          },
          { path: PROVIDER_DESCRIPTOR_PATH, body: requestBody },
        );
        expect(replayMutation.status).toBe(200);
        expect(replayMutation.text).toBe(mutation.text);

        const list = await page.evaluate(async () => {
          const response = await fetch("/v1/providers", {
            headers: { accept: "application/json" }});
          return { status: response.status, value: await response.json() };
        });
        expect(list.status).toBe(200);
        expect(list.value).toEqual({
          schema: "zode.providers.v1",
          providers: [
            {
              provider: PROVIDER_DESCRIPTOR_ID,
              descriptor: {
                revision: 1,
                kind: "openai_compatible",
                base_url: providerBaseUrl,
                models: ["descriptor-model-a", "descriptor-model-b"],
                model_limits: {},
                options: { organization: "descriptor-org" }},
              auth_methods: ["api_key"],
              default_profile_id: null,
              auth_status: "unconfigured",
              auth_profile_count: 0}]});

        await harness.restartServer();
        const restarted = await page.evaluate(async () => {
          const response = await fetch("/v1/providers", {
            headers: { accept: "application/json" }});
          return { status: response.status, value: await response.json() };
        });
        expect(restarted).toEqual(list);

        if (cassette) {
          let fixedReplayObserved = false;
          try {
            await harness.replayProviderDescriptorCassette(cassette);
          } catch (error) {
            const replayError = error as {
              classification?: unknown;
              details?: { actualStatus?: unknown };
            };
            if (
              replayError.classification === "REPLAY_MISMATCH" &&
              replayError.details?.actualStatus === 200
            ) {
              fixedReplayObserved = true;
            } else if (replayError.classification === "REPLAY_RESPONSE_HEADER_MISMATCH") {
              // The exact 200 body, list projection, idempotent replay, and restart
              // were already asserted above. A new JSON content type is the first
              // strict mismatch encountered against the retained empty 404.
              fixedReplayObserved = true;
            } else {
              throw error;
            }
          }
          expect(fixedReplayObserved).toBe(true);
        }
      } finally {
        await page.close().catch(() => undefined);
        await harness.close().catch(() => undefined);
        await provider.stop().catch(() => undefined);
      }
    },
  );

  test(
    "e2e_oauth_replay_integrity_404_body_mismatch_is_not_shallow_non_evidence",
    async ({ browser }) => {
      const mismatchServer = createServer((_request, response) => {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        response.end("replay-integrity-body-mismatch");
      });
      mismatchServer.listen(0, "127.0.0.1");
      const mismatchOrigin = await listenHttp(mismatchServer);
      const page = await browser.newPage();
      let observedError: unknown;
      try {
        await replayFirstBrowserFailure(page, mismatchOrigin);
      } catch (error) {
        observedError = error;
      } finally {
        await page.close().catch(() => undefined);
        mismatchServer.closeAllConnections?.();
        await new Promise<void>((resolveClose) => mismatchServer.close(() => resolveClose()));
      }

      expect(observedError).toBeDefined();
      expect(observedError).not.toBeInstanceOf(RouteMissingFoundationRed);
    },
  );
});

test.describe("OAuth refresh public operation boundary", () => {
  test(
    "e2e_oauth_profile_and_refresh_distribute_current_revision_to_endpoint",
    async ({ browser }) => {
      test.setTimeout(180_000);
      const provider = await OAuthProviderFixture.start();
      const harness = await ZodeBrowserHarness.start(browser, provider);
      const page = await harness.context.newPage();
      try {
        const system = await page.goto(`${harness.managementOrigin}/v1/system`, {
          waitUntil: "commit",
          timeout: HTTP_TIMEOUT});
        expect(system?.status()).toBe(200);
        const endpointId = await harness.registerEndpoint(page);
        await configureOAuthProvider(page, provider);
        const completed = await runOAuthAttemptThroughPublicBrowser(
          page,
          harness,
          "OAuth distributed credential E2E",
          {
            mode: "oauth_success",
            decision: "approve",
            expectedStatus: "succeeded",
            sharing: { mode: "selected", endpoint_ids: [endpointId] }},
        );

        const replicaState = async (): Promise<string> => {
          const response = await browserApi(
            page,
            `/v1/auth-profiles/${encodeURIComponent(completed.profileId)}/replicas`,
          );
          expect(response.status, response.text).toBe(200);
          const items = jsonObject(response.value, "OAuth replica projection").items;
          if (!Array.isArray(items) || items.length !== 1) {
            return `items:${Array.isArray(items) ? items.length : "invalid"}`;
          }
          const replica = jsonObject(items[0], "OAuth replica");
          return `${replica.endpoint_id}:${replica.revision}:${replica.installed_revision}:${replica.status}`;
        };
        await expect
          .poll(replicaState, { timeout: HTTP_TIMEOUT })
          .toBe(`${endpointId}:1:1:ready`);

        const created = await browserApi(
          page,
          `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions`,
          {
            method: "POST",
            idempotencyKey: `oauth-distributed-session-${randomUUID()}`,
            body: {
              model: {
                provider: OAUTH_PROVIDER_ID,
                provider_execution: {
                  schema: "zode.provider-execution.v1",
                  revision: 1,
                  kind: "openai_compatible",
                  base_url: provider.origin,
                  options: {}},
                model: "oauth-browser-model",
                auth_profile_id: completed.profileId,
                minimum_auth_revision: 1},
              tools: []}},
        );
        expect(created.status, created.text).toBe(201);
        const sessionId = jsonObject(created.value, "OAuth credential session").session_id;
        if (typeof sessionId !== "string") {
          throw new Error("OAuth credential session omitted its identity");
        }
        const sendAndAwait = async (content: string, expectedAssistant: string): Promise<void> => {
          const message = await browserApi(
            page,
            `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}/messages`,
            {
              method: "POST",
              idempotencyKey: `oauth-distributed-message-${randomUUID()}`,
              body: { content }},
          );
          expect(message.status, message.text).toBe(202);
          await expect
            .poll(
              async () => {
                const current = await browserApi(
                  page,
                  `/v1/endpoints/${encodeURIComponent(endpointId)}/sessions/${encodeURIComponent(sessionId)}`,
                );
                expect(current.status, current.text).toBe(200);
                const transcript = jsonObject(current.value, "OAuth credential session").transcript;
                if (!Array.isArray(transcript)) return 0;
                return transcript.filter(
                  (entry) =>
                    typeof entry === "object" &&
                    entry !== null &&
                    !Array.isArray(entry) &&
                    entry.role === "assistant" &&
                    entry.content === expectedAssistant,
                ).length;
              },
              { timeout: HTTP_TIMEOUT },
            )
            .toBe(1);
        };
        await sendAndAwait("use the first distributed OAuth credential", "OAUTH_REVISION_1");
        let providerState = await provider.state();
        expect(providerState.oauth_credential_model_requests).toBe(1);
        expect(providerState.invalid_model_authorizations).toBe(0);

        await provider.setMode("refresh_success");
        const accepted = await browserApi(
          page,
          `/v1/auth-profiles/${encodeURIComponent(completed.profileId)}/refresh-operations`,
          {
            method: "POST",
            idempotencyKey: `oauth-distributed-refresh-${randomUUID()}`},
        );
        expect(accepted.status, accepted.text).toBe(202);
        const operationId = jsonObject(accepted.value, "distributed OAuth refresh").operation_id;
        if (typeof operationId !== "string") {
          throw new Error("distributed OAuth refresh omitted its operation ID");
        }
        await expect
          .poll(
            async () => {
              const current = await browserApi(
                page,
                `/v1/auth-refresh-operations/${encodeURIComponent(operationId)}`,
              );
              return jsonObject(current.value, "distributed OAuth refresh status").status;
            },
            { timeout: HTTP_TIMEOUT },
          )
          .toBe("succeeded");
        await expect
          .poll(replicaState, { timeout: HTTP_TIMEOUT })
          .toBe(`${endpointId}:2:2:ready`);
        await sendAndAwait("use the refreshed distributed OAuth credential", "OAUTH_REFRESHED_REVISION");
        providerState = await provider.state();
        expect(providerState.refreshed_credential_model_requests).toBe(1);
        expect(providerState.invalid_model_authorizations).toBe(0);
      } finally {
        await page.close().catch(() => undefined);
        await harness.close().catch(() => undefined);
        await provider.stop().catch(() => undefined);
      }
    },
  );

  test(
    "e2e_oauth_refresh_admission_precedes_provider_completion",
    async ({ browser }) => {
      test.setTimeout(180_000);
      const provider = await OAuthProviderFixture.start();
      const harness = await ZodeBrowserHarness.start(browser, provider);
      const page = await harness.context.newPage();
      let admission: Promise<BrowserApiResult> | undefined;
      try {
        const system = await page.goto(`${harness.managementOrigin}/v1/system`, {
          waitUntil: "commit",
          timeout: HTTP_TIMEOUT});
        expect(system?.status()).toBe(200);
        await configureOAuthProvider(page, provider);
        const profile = await createOAuthProfileThroughPublicBrowser(
          page,
          harness,
          "OAuth held refresh E2E",
        );

        await provider.setMode("refresh_held");
        let admissionSettled = false;
        admission = browserApi(
          page,
          `/v1/auth-profiles/${encodeURIComponent(profile.id)}/refresh-operations`,
          {
            method: "POST",
            idempotencyKey: `oauth-held-refresh-${randomUUID()}`},
        );
        void admission.then(
          () => {
            admissionSettled = true;
          },
          () => {
            admissionSettled = true;
          },
        );
        await provider.waitFor(
          (state) => state.refresh_count === 1 && state.held_refresh_count === 1,
          "held refresh provider request",
        );
        await expect
          .poll(() => admissionSettled, {
            timeout: 2_000,
            message: "HTTP 202 must follow durable admission without waiting for provider completion"})
          .toBe(true);
        const accepted = await admission;
        expect(accepted.status, accepted.text).toBe(202);
        const operation = jsonObject(accepted.value, "accepted OAuth refresh");
        if (typeof operation.operation_id !== "string") {
          throw new Error("accepted OAuth refresh omitted its stable operation ID");
        }
        expect(["prepared", "dispatching"]).toContain(operation.status);

        await provider.releaseRefresh();
        await expect
          .poll(
            async () => {
              const current = await browserApi(
                page,
                `/v1/auth-refresh-operations/${encodeURIComponent(operation.operation_id as string)}`,
              );
              return jsonObject(current.value, "OAuth refresh operation").status;
            },
            { timeout: HTTP_TIMEOUT },
          )
          .toBe("succeeded");
        const profiles = await browserApi(
          page,
          `/v1/providers/${encodeURIComponent(OAUTH_PROVIDER_ID)}/auth-profiles`,
        );
        const items = jsonObject(profiles.value, "OAuth profiles after refresh").items;
        if (!Array.isArray(items)) {
          throw new Error("OAuth profile list omitted items after refresh");
        }
        const refreshed = items.find(
          (item) =>
            typeof item === "object" &&
            item !== null &&
            !Array.isArray(item) &&
            item.auth_profile_id === profile.id,
        );
        if (
          typeof refreshed !== "object" ||
          refreshed === null ||
          Array.isArray(refreshed) ||
          typeof refreshed.revision !== "number"
        ) {
          throw new Error("refreshed OAuth profile disappeared");
        }
        expect(refreshed.revision).toBeGreaterThan(profile.revision);
      } finally {
        await provider.releaseRefresh().catch(() => undefined);
        await admission?.catch(() => undefined);
        await page.close().catch(() => undefined);
        await harness.close().catch(() => undefined);
        await provider.stop().catch(() => undefined);
      }
    },
  );

  test(
    "e2e_oauth_refresh_retries_uncertain_idempotent_operation_without_server_restart",
    async ({ browser }) => {
      test.setTimeout(180_000);
      const provider = await OAuthProviderFixture.start();
      const harness = await ZodeBrowserHarness.start(browser, provider);
      const page = await harness.context.newPage();
      try {
        const system = await page.goto(`${harness.managementOrigin}/v1/system`, {
          waitUntil: "commit",
          timeout: HTTP_TIMEOUT});
        expect(system?.status()).toBe(200);
        await configureOAuthProvider(page, provider);
        const profile = await createOAuthProfileThroughPublicBrowser(
          page,
          harness,
          "OAuth in-process recovery E2E",
        );

        await provider.setMode("refresh_idempotent_drop_response");
        const accepted = await browserApi(
          page,
          `/v1/auth-profiles/${encodeURIComponent(profile.id)}/refresh-operations`,
          {
            method: "POST",
            idempotencyKey: `oauth-in-process-refresh-${randomUUID()}`},
        );
        expect(accepted.status, accepted.text).toBe(202);
        const operation = jsonObject(accepted.value, "in-process refresh");
        if (typeof operation.operation_id !== "string") {
          throw new Error("in-process refresh omitted its operation ID");
        }

        await provider.waitFor(
          (state) => state.refresh_count === 1 && state.idempotent_operation_count === 1,
          "first uncertain idempotent refresh dispatch",
        );
        await expect
          .poll(
            async () => {
              const current = await browserApi(
                page,
                `/v1/auth-refresh-operations/${encodeURIComponent(operation.operation_id as string)}`,
              );
              return jsonObject(current.value, "in-process refresh operation").status;
            },
            { timeout: HTTP_TIMEOUT },
          )
          .toBe("succeeded");
        const recoveredProviderState = await provider.state();
        expect(recoveredProviderState.refresh_count).toBe(2);
        expect(recoveredProviderState.idempotent_operation_count).toBe(1);
        const refreshed = (await readOAuthProfiles(page)).find(
          (candidate) => candidate.id === profile.id,
        );
        if (!refreshed) {
          throw new Error("in-process refresh recovery lost the profile");
        }
        expect(refreshed.revision).toBeGreaterThan(profile.revision);
      } finally {
        await page.close().catch(() => undefined);
        await harness.close().catch(() => undefined);
        await provider.stop().catch(() => undefined);
      }
    },
  );

  test(
    "e2e_oauth_refresh_recovers_same_operation_and_fences_unknown_until_same_profile_relogin",
    async ({ browser }) => {
      test.setTimeout(180_000);
      const provider = await OAuthProviderFixture.start();
      const harness = await ZodeBrowserHarness.start(browser, provider);
      const page = await harness.context.newPage();
      try {
        const system = await page.goto(`${harness.managementOrigin}/v1/system`, {
          waitUntil: "commit",
          timeout: HTTP_TIMEOUT});
        expect(system?.status()).toBe(200);
        await configureOAuthProvider(page, provider);
        let profile = await createOAuthProfileThroughPublicBrowser(
          page,
          harness,
          "OAuth recovery E2E",
        );

        await provider.setMode("refresh_idempotent_drop_response");
        const lostResponse = await browserApi(
          page,
          `/v1/auth-profiles/${encodeURIComponent(profile.id)}/refresh-operations`,
          {
            method: "POST",
            idempotencyKey: `oauth-idempotent-refresh-${randomUUID()}`},
        );
        expect(lostResponse.status, lostResponse.text).toBe(202);
        const lostOperation = jsonObject(lostResponse.value, "response-loss refresh");
        if (typeof lostOperation.operation_id !== "string") {
          throw new Error("response-loss refresh omitted its operation ID");
        }
        await provider.waitFor(
          (state) => state.refresh_count === 1,
          "first same-operation refresh dispatch",
        );
        await expect
          .poll(
            async () => {
              const current = await browserApi(
                page,
                `/v1/auth-refresh-operations/${encodeURIComponent(lostOperation.operation_id as string)}`,
              );
              return jsonObject(current.value, "response-loss refresh before restart").status;
            },
            { timeout: HTTP_TIMEOUT },
          )
          .toBe("dispatching");

        await harness.restartServer();
        await expect
          .poll(
            async () => {
              const current = await browserApi(
                page,
                `/v1/auth-refresh-operations/${encodeURIComponent(lostOperation.operation_id as string)}`,
              );
              return jsonObject(current.value, "response-loss refresh after restart").status;
            },
            { timeout: HTTP_TIMEOUT },
          )
          .toBe("succeeded");
        const recoveredProviderState = await provider.state();
        expect(recoveredProviderState.refresh_count).toBe(2);
        expect(recoveredProviderState.idempotent_operation_count).toBe(1);
        const recoveredProfile = (await readOAuthProfiles(page)).find(
          (candidate) => candidate.id === profile.id,
        );
        if (!recoveredProfile) {
          throw new Error("same-operation refresh recovery lost the profile");
        }
        expect(recoveredProfile.revision).toBeGreaterThan(profile.revision);
        profile = recoveredProfile;

        await harness.restartServer("none");
        await provider.setMode("refresh_unknown");
        const unknownResponse = await browserApi(
          page,
          `/v1/auth-profiles/${encodeURIComponent(profile.id)}/refresh-operations`,
          {
            method: "POST",
            idempotencyKey: `oauth-unknown-refresh-${randomUUID()}`},
        );
        expect(unknownResponse.status, unknownResponse.text).toBe(202);
        const unknownOperation = jsonObject(unknownResponse.value, "unknown refresh");
        if (typeof unknownOperation.operation_id !== "string") {
          throw new Error("unknown refresh omitted its operation ID");
        }
        await provider.waitFor(
          (state) => state.refresh_count === 1,
          "unknown refresh dispatch",
        );
        await expect
          .poll(
            async () => {
              const current = await browserApi(
                page,
                `/v1/auth-refresh-operations/${encodeURIComponent(unknownOperation.operation_id as string)}`,
              );
              return jsonObject(current.value, "unknown refresh operation").status;
            },
            { timeout: HTTP_TIMEOUT },
          )
          .toBe("refresh_unknown");
        let fenced = (await readOAuthProfiles(page)).find(
          (candidate) => candidate.id === profile.id,
        );
        if (!fenced) {
          throw new Error("unknown refresh lost the fenced profile");
        }
        expect(fenced.revision).toBe(profile.revision);
        expect(fenced.refreshState).toBe("reauth_required");
        expect(fenced.allowedActions).toEqual(["relogin"]);

        const blocked = await browserApi(
          page,
          `/v1/auth-profiles/${encodeURIComponent(profile.id)}/refresh-operations`,
          {
            method: "POST",
            idempotencyKey: `oauth-blocked-refresh-${randomUUID()}`},
        );
        expect(blocked.status, blocked.text).toBe(409);
        const blockedError = jsonObject(
          jsonObject(blocked.value, "blocked refresh").error as JsonValue,
          "blocked refresh error",
        );
        expect(blockedError.code).toBe("reauth_required");
        expect((await provider.state()).refresh_count).toBe(1);

        await runOAuthAttemptThroughPublicBrowser(page, harness, "failed same-profile relogin", {
          mode: "oauth_failed",
          decision: "approve",
          replaceAuthProfileId: profile.id,
          expectedStatus: "failed"});
        fenced = (await readOAuthProfiles(page)).find(
          (candidate) => candidate.id === profile.id,
        );
        expect(fenced?.revision).toBe(profile.revision);
        expect(fenced?.refreshState).toBe("reauth_required");

        await runOAuthAttemptThroughPublicBrowser(
          page,
          harness,
          "cancelled same-profile relogin",
          {
            mode: "oauth_success",
            decision: "cancel",
            replaceAuthProfileId: profile.id,
            expectedStatus: "cancelled"},
        );
        fenced = (await readOAuthProfiles(page)).find(
          (candidate) => candidate.id === profile.id,
        );
        expect(fenced?.revision).toBe(profile.revision);
        expect(fenced?.refreshState).toBe("reauth_required");

        const relogged = await createOAuthProfileThroughPublicBrowser(
          page,
          harness,
          "successful same-profile relogin",
          profile.id,
        );
        expect(relogged.id).toBe(profile.id);
        expect(relogged.revision).toBeGreaterThan(profile.revision);
        const profilesAfterRelogin = await readOAuthProfiles(page);
        expect(profilesAfterRelogin).toHaveLength(1);
        const ready = profilesAfterRelogin[0];
        expect(ready.id).toBe(profile.id);
        expect(ready.refreshState).toBe("ready");
        expect(ready.allowedActions).toEqual(["refresh", "relogin"]);
      } finally {
        await page.close().catch(() => undefined);
        await harness.close().catch(() => undefined);
        await provider.stop().catch(() => undefined);
      }
    },
  );

  test(
    "e2e_server_restart_removes_unreferenced_provider_secret_without_losing_profile",
    async ({ browser }) => {
      test.setTimeout(180_000);
      const provider = await OAuthProviderFixture.start();
      const harness = await ZodeBrowserHarness.start(browser, provider);
      const page = await harness.context.newPage();
      let orphanPath: string | undefined;
      try {
        const system = await page.goto(`${harness.managementOrigin}/v1/system`, {
          waitUntil: "commit",
          timeout: HTTP_TIMEOUT});
        expect(system?.status()).toBe(200);
        await configureOAuthProvider(page, provider);
        const profile = await createOAuthProfileThroughPublicBrowser(
          page,
          harness,
          "OAuth orphan cleanup E2E",
        );

        await harness.restartServer(undefined, async (serverConfigPath) => {
          const config = JSON.parse(await readFile(serverConfigPath, "utf8")) as {
            secret_directory?: unknown;
          };
          if (typeof config.secret_directory !== "string") {
            throw new Error("OAuth cleanup E2E Server config omitted secret_directory");
          }
          const secretDirectory = resolve(dirname(serverConfigPath), config.secret_directory);
          const providerDirectory = resolve(secretDirectory, "providers");
          const references = (await readdir(providerDirectory)).filter((entry) =>
            /^[0-9a-f]{64}$/.test(entry),
          );
          if (references.length !== 1) {
            throw new Error("OAuth cleanup E2E expected one referenced provider secret");
          }
          const orphanReference = references[0] === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64);
          orphanPath = resolve(providerDirectory, orphanReference);
          await copyFile(resolve(providerDirectory, references[0]), orphanPath);
          await chmod(orphanPath, 0o600);
        });

        if (!orphanPath) {
          throw new Error("OAuth cleanup E2E did not create its test-owned orphan");
        }
        const orphan = await stat(orphanPath).catch(() => undefined);
        expect(orphan, "Server restart retained an unreferenced provider secret").toBeUndefined();
        const profiles = await readOAuthProfiles(page);
        expect(profiles).toHaveLength(1);
        expect(profiles[0].id).toBe(profile.id);
        expect(profiles[0].revision).toBe(profile.revision);
      } finally {
        await page.close().catch(() => undefined);
        await harness.close().catch(() => undefined);
        await provider.stop().catch(() => undefined);
      }
    },
  );
});

test.describe("OAuth and refresh browser boundary", () => {
  test("e2e_browser_write_only_secrets_and_oauth_ticket_non_disclosure", async ({ browser }, testInfo) => {
    test.setTimeout(180_000);
    await test.step("offline replay contract rejects request/header/sequence mutations before product boundary", async () => {
      const cassette = await readJsonFile<IncidentCassette>(INCIDENT_CASSETTE);
      assertOfflineReplayContractRejectsMutations(cassette);
    });
    const provider = await OAuthProviderFixture.start();
    const harness = await ZodeBrowserHarness.start(browser, provider);
    const page = await harness.context.newPage();
    const audit = installBrowserAudit(page);
    let consumedTicket: string | undefined;
    try {
      await test.step(
        `${ROUTE_MISSING_FOUNDATION_RED}: replay the first real-browser /v1/providers 404 before ticket behavior`,
        async () => {
          await replayFirstBrowserFailure(page, harness.managementOrigin);
        },
      );
      await configureOAuthProvider(page, provider);

      await test.step("cancel OAuth after the provider prompt", async () => {
        await openProviders(page, harness.managementOrigin);
        await provider.setMode("oauth_cancelled");
        const ticket = await startOAuthAttempt(page, audit, harness.managementOrigin, `${PROFILE_LABEL} cancelled`);
        consumedTicket = ticket;
        await redeemWithExplicitLocationReplaceButton(page, audit, provider, harness.managementOrigin, ticket);
        await expect(page.getByText(/prompt|authorization/i).first()).toBeVisible({ timeout: HTTP_TIMEOUT });
        await finishProviderDecision(page, audit, harness.managementOrigin, ticket, "cancel", /cancelled|canceled|access denied/i);
        const state = await provider.state();
        expect(state.token_count).toBe(0);
        await assertSecretMarkersAbsent(page, harness.context, audit);
      });

      await test.step("complete OAuth success and keep the ticket write-only", async () => {
        await openProviders(page, harness.managementOrigin);
        await provider.setMode("oauth_success");
        const ticket = await startOAuthAttempt(page, audit, harness.managementOrigin, PROFILE_LABEL);
        // The previous ticket was consumed by the cancelled redirect. A new
        // visible attempt must mint a distinct ticket; it may not reuse the
        // consumed/expired capability from browser history or storage.
        expect(ticket).not.toBe(consumedTicket);
        await redeemWithExplicitLocationReplaceButton(page, audit, provider, harness.managementOrigin, ticket);
        await finishProviderDecision(page, audit, harness.managementOrigin, ticket, "approve", /success|ready|connected/i);
        await assertSecretMarkersAbsent(page, harness.context, audit);
      });

      let profile = await reloadProvidersAndReadProfile(page, harness.managementOrigin, PROFILE_LABEL);
      expect(profile.revision).toBeGreaterThan(0);
      const fencedProfileId = profile.id;
      let refreshAdmissionsAfterUnknown: number | undefined;

      await test.step("refresh success advances one profile revision", async () => {
        await provider.setMode("refresh_held");
        const previousRevision = profile.revision;
        await clickProfileAction(page, /refresh/i);
        await provider.waitFor(
          (state) => state.refresh_count === 1 && state.held_refresh_count === 1,
          "held refresh before terminal projection failure",
        );
        harness.failNextAuthRefreshProjections(3);
        await provider.releaseRefresh();
        await expect
          .poll(() => harness.authRefreshProjectionFailures, { timeout: HTTP_TIMEOUT })
          .toBe(3);
        await expect(page.getByRole("status").filter({ hasText: "Credentials refreshed" })).toBeVisible({
          timeout: HTTP_TIMEOUT});
        profile = await reloadProvidersAndReadProfile(page, harness.managementOrigin, PROFILE_LABEL);
        expect(profile.id).toBe(fencedProfileId);
        expect(profile.revision).toBeGreaterThan(previousRevision);
        expect((await provider.state()).refresh_count).toBe(1);
        await assertSecretMarkersAbsent(page, harness.context, audit);
      });

      await test.step("refresh response loss recovers after a real Server crash", async () => {
        await provider.setMode("refresh_idempotent_drop_response");
        const previousRevision = profile.revision;
        await clickProfileAction(page, /refresh/i);
        await provider.waitFor(
          (state) => state.refresh_count === 1,
          "refresh dispatch before Server crash",
        );
        await harness.restartServer();
        await page.reload({ waitUntil: "domcontentloaded", timeout: HTTP_TIMEOUT });
        await waitForSafeUiState(page, /succeeded|refreshed|ready/i);
        profile = await reloadProvidersAndReadProfile(page, harness.managementOrigin, PROFILE_LABEL);
        const state = await provider.state();
        expect(profile.id).toBe(fencedProfileId);
        expect(profile.revision).toBeGreaterThan(previousRevision);
        expect(state.refresh_count).toBe(2);
        expect(state.idempotent_operation_count).toBe(1);
        await assertSecretMarkersAbsent(page, harness.context, audit);
      });

      await test.step("refresh_unknown fences refresh and exposes only same-profile relogin", async () => {
        await harness.restartServer("none");
        await provider.setMode("refresh_unknown");
        const refreshCountBefore = (await provider.state()).refresh_count;
        await clickProfileAction(page, /refresh/i);
        await waitForSafeUiState(page, /refresh_unknown|reauth_required|re-?login required|provider may have consumed/i);
        const state = await provider.state();
        expect(state.refresh_count).toBe(refreshCountBefore + 1);
        refreshAdmissionsAfterUnknown = refreshAdmissionCount(audit);
        await assertRefreshUnknownFencedUi(page);
        await assertSecretMarkersAbsent(page, harness.context, audit);
      });

      await test.step("failed relogin keeps the refresh warning fenced", async () => {
        await provider.setMode("oauth_failed");
        const refreshCountBeforeFailedRelogin = (await provider.state()).refresh_count;
        const ticket = await startOAuthAttempt(page, audit, harness.managementOrigin, "failed relogin", fencedProfileId);
        await redeemWithExplicitLocationReplaceButton(page, audit, provider, harness.managementOrigin, ticket);
        await finishProviderDecision(
          page,
          audit,
          harness.managementOrigin,
          ticket,
          "approve",
          /failed|rejected|reauth_required|re-?login required/i,
          "provider_error",
        );
        await waitForSafeUiState(page, /refresh_unknown|reauth_required|re-?login required|provider may have consumed/i);
        await assertRefreshUnknownFencedUi(page);
        expect((await provider.state()).refresh_count).toBe(refreshCountBeforeFailedRelogin);
        expect(refreshAdmissionCount(audit)).toBe(refreshAdmissionsAfterUnknown);
        await assertSecretMarkersAbsent(page, harness.context, audit);
        const failedProfile = await reloadProvidersAndReadProfile(page, harness.managementOrigin, PROFILE_LABEL);
        expect(failedProfile.id).toBe(fencedProfileId);
        expect(failedProfile.revision).toBe(profile.revision);
      });

      await test.step("cancelled relogin keeps the refresh warning fenced", async () => {
        await provider.setMode("oauth_success");
        const refreshCountBeforeCancelledRelogin = (await provider.state()).refresh_count;
        const ticket = await startOAuthAttempt(page, audit, harness.managementOrigin, "cancelled relogin", fencedProfileId);
        await redeemWithExplicitLocationReplaceButton(page, audit, provider, harness.managementOrigin, ticket);
        await finishProviderDecision(page, audit, harness.managementOrigin, ticket, "cancel", /cancelled|canceled|reauth_required|re-?login required/i);
        await waitForSafeUiState(page, /refresh_unknown|reauth_required|re-?login required|provider may have consumed/i);
        await assertRefreshUnknownFencedUi(page);
        expect((await provider.state()).refresh_count).toBe(refreshCountBeforeCancelledRelogin);
        expect(refreshAdmissionCount(audit)).toBe(refreshAdmissionsAfterUnknown);
        await assertSecretMarkersAbsent(page, harness.context, audit);
        const cancelledProfile = await reloadProvidersAndReadProfile(page, harness.managementOrigin, PROFILE_LABEL);
        expect(cancelledProfile.id).toBe(fencedProfileId);
        expect(cancelledProfile.revision).toBe(profile.revision);
      });

      await test.step("successful relogin replaces the same profile and clears the warning", async () => {
        await provider.setMode("oauth_success");
        const previousRevision = profile.revision;
        const ticket = await startOAuthAttempt(page, audit, harness.managementOrigin, "successful relogin", fencedProfileId);
        await redeemWithExplicitLocationReplaceButton(page, audit, provider, harness.managementOrigin, ticket);
        await finishProviderDecision(page, audit, harness.managementOrigin, ticket, "approve", /success|ready|connected/i);
        const reloggedProfiles = await reloadProvidersAndReadProfiles(page, harness.managementOrigin, PROFILE_LABEL);
        expect(reloggedProfiles).toHaveLength(1);
        profile = reloggedProfiles[0];
        expect(profile.id).toBe(fencedProfileId);
        expect(profile.revision).toBeGreaterThan(previousRevision);
        await expect(page.getByText(/refresh_unknown|reauth_required|provider may have consumed/i).first()).toHaveCount(0);
        await expect(page.getByRole("button", { name: /refresh/i }).first()).toBeVisible({ timeout: HTTP_TIMEOUT });
        await assertSecretMarkersAbsent(page, harness.context, audit);
      });

      assertEachMintedTicketRedeemedOnce(audit, harness.managementOrigin);
      await testInfo.attach("oauth-refresh-browser-boundary", {
        body: Buffer.from(
          JSON.stringify({
            cassette: "oauth_refresh_relogin_first_browser_failure.v1.json",
            ticket_mints: audit.ticketMints.length,
            ticket_redemptions: audit.ticketRedemptions.length,
            refresh_requests: (await provider.state()).refresh_count}),
          "utf8",
        ),
        contentType: "application/json"});
    } catch (error) {
      if (error instanceof RouteMissingFoundationRed) {
        testInfo.annotations.push({
          type: "failure-classification",
          description: `${error.stage}:${error.classification}`});
      }
      throw error;
    } finally {
      await page.close().catch(() => undefined);
      await harness.close().catch(() => undefined);
      await provider.stop().catch(() => undefined);
    }
  });
});
