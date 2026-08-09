import { createHash, createHmac, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { chmod, mkdir, mkdtemp, open, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export type AccessActor = "actor-a" | "actor-b";

export const PROVIDER_NAME = "two-actor-fixture-provider";
export const PROVIDER_MODEL = "two-actor-fixture-model";
export const PROVIDER_SECRET = "two-actor-provider-secret-e2e";
export const ENDPOINT_CONTROL_SECRET = "two-actor-endpoint-control-secret-e2e";
export const ASSISTANT_MARKER = "TWO_ACTOR_ISOLATION_OK";
export const SERVER_AUTHORITY = "two-actor-server-authority";
export const ENDPOINT_AUTHORITY = SERVER_AUTHORITY;
export const ACCESS_AUDIENCE = "zode-web-two-actor-e2e";

const READY_TIMEOUT_MS = 15_000;
const CHILD_STOP_TIMEOUT_MS = 5_000;
const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

type Address = { baseUrl: string; close: () => Promise<void> };

type Edge = Address & {
  setTarget(target: string): void;
};

type RunningChild = Address & {
  stop(): Promise<void>;
  logs(): string;
};

type Provider = Address & {
  requestCount(): number;
  waitForRequests(count: number): Promise<void>;
};

export type StackPaths = {
  root: string;
  endpointRoot: string;
  initialServerRoot: string;
  serverRoots: string[];
  endpointDatabase: string;
  subjectKey: string;
};

export type EndpointObservation = {
  method: string;
  path: string;
  subject: string | null;
  controllerAuthMatched: boolean;
  idempotencyKey: string | null;
  requestHeaders: Record<string, string>;
  requestBodyHex: string;
  requestBodyDigest: string;
  status: number;
  responseHeaders: Record<string, string>;
  responseBodyHex: string | null;
  responseBodyDigest: string | null;
  responseChunks: CassetteChunk[];
  termination: CassetteTermination;
  responseCode: string | null;
  completed: boolean;
};

export type CassetteChunk = {
  sequence: number;
  bodyHex: string;
  bodySha256: string;
  offsetMs: number;
};

export type CassetteTermination = "complete" | "disconnect" | "error";

export type EndpointCassetteExchange = {
  sequence: number;
  method: string;
  path: string;
  subjectSlot: string;
  controllerAuth: "shared" | "unexpected";
  idempotencyKey: string | null;
  requestHeaders: Record<string, string>;
  requestBodyHex: string;
  requestBodyDigest: string;
  status: number;
  responseHeaders: Record<string, string>;
  responseBodyHex: string | null;
  responseBodyDigest: string | null;
  responseChunks: CassetteChunk[];
  termination: CassetteTermination;
  responseCode: string | null;
  completed: boolean;
};

export type EndpointTransport = Address & {
  arm(dynamicIds: string[]): void;
  observations(): EndpointObservation[];
  cassetteExchanges(): EndpointCassetteExchange[];
  flush(): Promise<void>;
  assertReplayConsumed(): void;
};

export type TwoActorStack = {
  paths: StackPaths;
  access: AccessFixture;
  provider: Provider;
  endpoint: RunningChild;
  server: RunningChild;
  actorA: Edge;
  actorB: Edge;
  endpointTransport: EndpointTransport;
  endpointControlSecret: string;
  providerSecret: string;
  endpointBaseUrl: string;
  providerBaseUrl: string;
  restartServerWithFreshStore(): Promise<void>;
  stopServer(): Promise<void>;
  dispose(): Promise<void>;
};

export type AccessFixture = Address & {
  issuer: string;
  jwksUrl: string;
  sign(actor: AccessActor): string;
};

function json(value: Json): string {
  return JSON.stringify(value);
}

function base64Url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function digestBytes(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function isSessionEndpointPath(path: string): boolean {
  return path === "/v1/sessions" || /^\/v1\/sessions\/[^/]+(?:\/messages|\/events)?$/.test(path);
}

function normalizeText(value: string, dynamicIds: string[]): string {
  let normalized = value;
  for (const id of dynamicIds.filter(Boolean)) normalized = normalized.replaceAll(id, "{{OPAQUE_ID}}");
  normalized = normalized.replace(/http:\/\/127\.0\.0\.1:\d+/g, "http://127.0.0.1:{{PORT}}");
  normalized = normalized.replace(/\b[0-9A-HJKMNP-TV-Z]{26}\b/g, "{{SESSION_ID}}");
  normalized = normalized.replace(/("(?:created_at_ms|updated_at_ms|last_observed_at_ms)"\s*:)\d+/g, "$1{{TIMESTAMP_MS}}");
  return normalized;
}

function redactText(value: string, secrets: string[], dynamicIds: string[]): string {
  let redacted = normalizeText(value, dynamicIds);
  for (const secret of secrets.filter(Boolean)) {
    const slot = secret === PROVIDER_SECRET
      ? "<secret:SLOT_PROVIDER_SECRET>"
      : secret === ENDPOINT_CONTROL_SECRET
        ? "<secret:SLOT_ENDPOINT_CONTROL_SECRET>"
        : `[synthetic:${digest(secret).slice(0, 12)}]`;
    redacted = redacted.replaceAll(secret, slot);
  }
  return redacted;
}

export function redactForCassette(value: string, secrets: string[], dynamicIds: string[] = []): string {
  return redactText(value, secrets, dynamicIds);
}

export type CapturedBody = {
  bodyHex: string;
  bodySha256: string;
  canonicalJson: Json | null;
};

export function captureBody(
  value: string | Buffer | undefined,
  secrets: string[],
  dynamicIds: string[] = [],
): CapturedBody {
  const source = value === undefined ? "" : typeof value === "string" ? value : value.toString("utf8");
  const redacted = redactText(source, secrets, dynamicIds);
  let canonicalJson: Json | null = null;
  if (redacted.length > 0) {
    try {
      canonicalJson = JSON.parse(redacted) as Json;
    } catch {
      canonicalJson = null;
    }
  }
  const bytes = Buffer.from(redacted, "utf8");
  return {
    bodyHex: bytes.toString("hex"),
    bodySha256: `sha256:${digestBytes(bytes)}`,
    canonicalJson,
  };
}

export function normalizePath(path: string, dynamicIds: string[]): string {
  const normalized = normalizeText(path, dynamicIds);
  const parts = normalized.split("/");
  if (parts[1] === "v1" && parts[2] === "sessions" && parts[3]) parts[3] = "{{SESSION_ID}}";
  return parts.join("/");
}

function normalizedBodyDigest(body: Buffer, dynamicIds: string[]): string {
  return digest(normalizeText(body.toString("utf8"), dynamicIds));
}

function safeResponseCode(body: Buffer): string | null {
  try {
    const value = JSON.parse(body.toString("utf8")) as unknown;
    if (value && typeof value === "object" && "error" in value) {
      const error = value.error;
      if (error && typeof error === "object" && "code" in error && typeof error.code === "string") return error.code;
    }
  } catch {
    // SSE and non-JSON responses intentionally have no safe error code.
  }
  return null;
}

async function readRequestBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function safeError(message: string): Error {
  return new Error(message.replaceAll(PROVIDER_SECRET, "[provider-secret]").replaceAll(ENDPOINT_CONTROL_SECRET, "[endpoint-secret]"));
}

async function listen(server: Server): Promise<string> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw safeError("fixture listener did not expose a TCP address");
  }
  return `http://127.0.0.1:${address.port}`;
}

async function reserveLoopbackPort(): Promise<number> {
  const server = createServer();
  const baseUrl = await listen(server);
  const port = Number(new URL(baseUrl).port);
  await closeServer(server);
  return port;
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolveClose, reject) => {
    server.close((error) => (error ? reject(error) : resolveClose()));
  });
}

function responseJson(response: ServerResponse, status: number, body: Json): void {
  const bytes = Buffer.from(json(body));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": bytes.byteLength,
    "cache-control": "no-store",
  });
  response.end(bytes);
}

function responseText(response: ServerResponse, status: number, contentType: string, body: string): void {
  const bytes = Buffer.from(body);
  response.writeHead(status, {
    "content-type": contentType,
    "content-length": bytes.byteLength,
    "cache-control": "no-store",
  });
  response.end(bytes);
}

function actorClaims(actor: AccessActor, issuer: string): Json {
  const subject = actor === "actor-a" ? "two-actor-human-a" : "two-actor-human-b";
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: issuer,
    aud: [ACCESS_AUDIENCE],
    sub: subject,
    type: "app",
    iat: now,
    nbf: now - 1,
    exp: now + 300,
  };
}

async function startAccessFixture(): Promise<AccessFixture> {
  const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKey = keyPair.privateKey;
  const publicJwk = keyPair.publicKey.export({ format: "jwk" }) as Record<string, string> & {
    n: string;
    e: string;
  };
  const kid = "two-actor-access-key";
  const server = createServer((request, response) => {
    if (request.method !== "GET" || !["/jwks", "/cdn-cgi/access/certs"].includes(request.url ?? "")) {
      responseJson(response, 404, { error: { code: "not_found" } });
      return;
    }
    responseJson(response, 200, {
      keys: [{ ...publicJwk, kid, use: "sig", alg: "RS256" }],
    });
  });
  const baseUrl = await listen(server);
  const issuer = `${baseUrl}/`;
  const jwksUrl = `${baseUrl}/jwks`;
  return {
    baseUrl,
    issuer,
    jwksUrl,
    sign(actor) {
      const header = base64Url(json({ alg: "RS256", kid, typ: "JWT" }));
      const payload = base64Url(json(actorClaims(actor, issuer)));
      const signingInput = `${header}.${payload}`;
      const signer = createSign("RSA-SHA256");
      signer.update(signingInput);
      return `${signingInput}.${signer.sign(privateKey).toString("base64url")}`;
    },
    close: () => closeServer(server),
  };
}

function hopByHopHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string | string[] | undefined> {
  const result = { ...headers };
  for (const name of [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]) {
    delete result[name];
  }
  return result;
}

function semanticHeaders(
  headers: Record<string, string | string[] | undefined>,
  dynamicIds: string[],
  secrets: string[],
): Record<string, string> {
  const allowed = new Set([
    "accept",
    "cache-control",
    "content-length",
    "content-type",
    "idempotency-key",
    "last-event-id",
    "location",
  ]);
  const result: Record<string, string> = {};
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (!allowed.has(name)) continue;
    const value = Array.isArray(rawValue) ? rawValue.join(",") : rawValue;
    if (value === undefined) continue;
    result[name] = redactText(value, secrets, dynamicIds);
  }
  return result;
}

async function startAccessEdge(access: AccessFixture, actor: AccessActor, initialTarget: string): Promise<Edge> {
  let target = initialTarget;
  const server = createServer((incoming, outgoing) => {
    const destination = new URL(incoming.url ?? "/", `${target}/`);
    const headers = hopByHopHeaders(incoming.headers);
    headers.host = destination.host;
    headers["cf-access-jwt-assertion"] = access.sign(actor);
    if (headers.origin) headers.origin = target;
    if (headers.referer) headers.referer = `${target}/`;
    const upstream = httpRequest(destination, {
      method: incoming.method,
      headers,
    }, (response) => {
      outgoing.writeHead(response.statusCode ?? 502, hopByHopHeaders(response.headers));
      response.pipe(outgoing);
    });
    upstream.on("error", () => {
      if (!outgoing.headersSent) responseJson(outgoing, 502, { error: { code: "server_unavailable" } });
      else outgoing.destroy();
    });
    incoming.pipe(upstream);
  });
  const baseUrl = await listen(server);
  return {
    baseUrl,
    setTarget(nextTarget) {
      target = nextTarget;
    },
    close: () => closeServer(server),
  };
}

async function startEndpointTransport(
  target: string,
  replayExpected: EndpointCassetteExchange[] | undefined,
): Promise<EndpointTransport> {
  let dynamicIds: string[] = [];
  let replayIndex = 0;
  let replayError: string | null = null;
  const observations: EndpointObservation[] = [];
  const subjectSlots = new Map<string, string>();
  let pendingRequests = 0;
  const idleWaiters: (() => void)[] = [];

  function subjectSlot(subject: string | null): string {
    if (subject === null) return "none";
    const existing = subjectSlots.get(subject);
    if (existing) return existing;
    const slot = `subject-${subjectSlots.size + 1}`;
    subjectSlots.set(subject, slot);
    return slot;
  }

  function requestMismatch(expected: EndpointCassetteExchange, actual: EndpointObservation): string | null {
    const actualSlot = subjectSlot(actual.subject);
    if (expected.method !== actual.method) return `method ${actual.method} != ${expected.method}`;
    if (expected.path !== normalizePath(actual.path, dynamicIds)) return `path ${normalizePath(actual.path, dynamicIds)} != ${expected.path}`;
    if (expected.subjectSlot !== actualSlot) return `subject slot ${actualSlot} != ${expected.subjectSlot}`;
    if (expected.controllerAuth !== (actual.controllerAuthMatched ? "shared" : "unexpected")) {
      return "controller authority changed";
    }
    if (expected.idempotencyKey !== actual.idempotencyKey) return "idempotency key changed";
    if (JSON.stringify(expected.requestHeaders) !== JSON.stringify(actual.requestHeaders)) return "request semantic headers changed";
    if (expected.requestBodyHex !== actual.requestBodyHex) return "request body changed";
    if (expected.requestBodyDigest !== actual.requestBodyDigest) return "request body digest changed";
    return null;
  }

  function responseMismatch(expected: EndpointCassetteExchange, actual: EndpointObservation): string | null {
    if (expected.status !== actual.status) return `status ${actual.status} != ${expected.status}`;
    if (JSON.stringify(expected.responseHeaders) !== JSON.stringify(actual.responseHeaders)) return "response semantic headers changed";
    if (expected.responseBodyHex !== actual.responseBodyHex) return "response body changed";
    if (expected.responseCode !== actual.responseCode) return "safe response code changed";
    if (expected.responseBodyDigest !== actual.responseBodyDigest) return "response body digest changed";
    const expectedChunks = expected.responseChunks.map(({ sequence, bodyHex, bodySha256 }) => ({ sequence, bodyHex, bodySha256 }));
    const actualChunks = actual.responseChunks.map(({ sequence, bodyHex, bodySha256 }) => ({ sequence, bodyHex, bodySha256 }));
    if (JSON.stringify(expectedChunks) !== JSON.stringify(actualChunks)) return "response chunks changed";
    if (expected.termination !== actual.termination) return "response termination changed";
    if (expected.completed !== actual.completed) return "response completion changed";
    return null;
  }

  function noteReplayError(sequence: number, detail: string): void {
    replayError ??= `Endpoint cassette exchange ${sequence} changed: ${detail}`;
  }

  function captureRequest(incoming: IncomingMessage, body: Buffer): EndpointObservation {
    const subjectHeader = incoming.headers["zode-subject"];
    const subject = Array.isArray(subjectHeader) ? subjectHeader[0] ?? null : subjectHeader ?? null;
    const authorization = incoming.headers.authorization;
    const authorizationValue = Array.isArray(authorization) ? authorization[0] : authorization;
    const idempotency = incoming.headers["idempotency-key"];
    const requestHeaders = semanticHeaders(incoming.headers, dynamicIds, [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET]);
    const requestBody = captureBody(body, [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET], dynamicIds);
    return {
      method: incoming.method ?? "GET",
      path: new URL(incoming.url ?? "/", `${target}/`).pathname,
      subject,
      controllerAuthMatched: authorizationValue === `Bearer ${ENDPOINT_CONTROL_SECRET}`,
      idempotencyKey: Array.isArray(idempotency) ? idempotency[0] ?? null : idempotency ?? null,
      requestHeaders,
      requestBodyHex: requestBody.bodyHex,
      requestBodyDigest: requestBody.bodySha256.replace(/^sha256:/, ""),
      status: 0,
      responseHeaders: {},
      responseBodyHex: null,
      responseBodyDigest: null,
      responseChunks: [],
      termination: "disconnect",
      responseCode: null,
      completed: false,
    };
  }

  function consumeRequest(actual: EndpointObservation): EndpointCassetteExchange | undefined {
    if (!replayExpected) return undefined;
    const expected = replayExpected[replayIndex];
    if (!expected) {
      noteReplayError(replayIndex, "unexpected extra session exchange");
      return undefined;
    }
    const mismatch = requestMismatch(expected, actual);
    if (mismatch) {
      noteReplayError(expected.sequence, mismatch);
      return expected;
    }
    replayIndex += 1;
    return expected;
  }

  async function handle(incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> {
    const body = await readRequestBody(incoming);
    const destination = new URL(incoming.url ?? "/", `${target}/`);
    const headers = hopByHopHeaders(incoming.headers);
    headers.host = destination.host;
    const observation = captureRequest(incoming, body);
    observations.push(observation);
    const expected = consumeRequest(observation);
    const upstream = httpRequest(destination, {
      method: incoming.method,
      headers,
    });
    let responseStarted = false;
    let settled = false;
    let clientClosed = false;
    const responseChunks: Buffer[] = [];
    const responseChunkTimes: number[] = [];
    const responseStartedAt = Date.now();
    let resolveCompletion: (() => void) | undefined;
    const completion = new Promise<void>((resolve) => {
      resolveCompletion = resolve;
    });

    outgoing.on("close", () => {
      clientClosed = true;
      if (!settled && responseStarted) upstream.destroy();
    });

    const finish = (completed: boolean, status: number, responseBody: Buffer): void => {
      if (settled) return;
      settled = true;
      observation.status = status;
      const captured = captureBody(responseBody, [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET], dynamicIds);
      observation.responseBodyHex = captured.bodyHex;
      observation.responseBodyDigest = captured.bodySha256.replace(/^sha256:/, "");
      observation.responseCode = safeResponseCode(responseBody);
      observation.responseChunks = responseChunks.map((chunk, sequence) => {
        const safeChunk = captureBody(chunk, [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET], dynamicIds);
        return {
          sequence,
          bodyHex: safeChunk.bodyHex,
          bodySha256: safeChunk.bodySha256,
          offsetMs: Math.max(0, (responseChunkTimes[sequence] ?? Date.now()) - responseStartedAt),
        };
      });
      observation.termination = completed ? "complete" : "disconnect";
      observation.completed = completed;
      if (expected) {
        const mismatch = responseMismatch(expected, observation);
        if (mismatch) noteReplayError(expected.sequence, mismatch);
      }
      resolveCompletion?.();
    };

    upstream.on("response", (response) => {
      responseStarted = true;
      observation.status = response.statusCode ?? 502;
      observation.responseHeaders = semanticHeaders(
        response.headers,
        dynamicIds,
        [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET],
      );
      outgoing.writeHead(response.statusCode ?? 502, hopByHopHeaders(response.headers));
      response.on("data", (chunk: Buffer | string) => {
        const bytes = Buffer.from(chunk);
        responseChunks.push(bytes);
        responseChunkTimes.push(Date.now());
        if (!clientClosed && !outgoing.destroyed) outgoing.write(bytes);
      });
      response.on("end", () => {
        finish(true, response.statusCode ?? 502, Buffer.concat(responseChunks));
        if (!outgoing.destroyed && !outgoing.writableEnded) outgoing.end();
      });
      response.on("close", () => {
        if (!settled) {
          finish(false, response.statusCode ?? 502, Buffer.concat(responseChunks));
          if (!outgoing.destroyed && !outgoing.writableEnded) outgoing.end();
        }
      });
      response.on("error", () => {
        if (!settled) {
          finish(false, response.statusCode ?? 502, Buffer.concat(responseChunks));
          outgoing.destroy();
        }
      });
    });
    upstream.on("error", () => {
      if (!responseStarted) {
        const errorBody = Buffer.from(json({ error: { code: "endpoint_unavailable" } }));
        observation.status = 502;
        finish(true, 502, errorBody);
        if (!outgoing.headersSent) responseJson(outgoing, 502, { error: { code: "endpoint_unavailable" } });
        else outgoing.destroy();
        return;
      }
      outgoing.destroy();
    });
    if (body.length > 0) upstream.write(body);
    upstream.end();
    await completion;
  }

  const server = createServer((incoming, outgoing) => {
    pendingRequests += 1;
    void handle(incoming, outgoing).catch(() => {
      if (!outgoing.headersSent) responseJson(outgoing, 502, { error: { code: "endpoint_unavailable" } });
      else outgoing.destroy();
    }).finally(() => {
      pendingRequests -= 1;
      if (pendingRequests === 0) {
        while (idleWaiters.length > 0) idleWaiters.shift()?.();
      }
    });
  });
  const baseUrl = await listen(server);
  return {
    baseUrl,
    arm(ids) {
      dynamicIds = ids.filter(Boolean);
    },
    observations() {
      return observations.map((observation) => ({ ...observation }));
    },
    cassetteExchanges() {
      return observations
        .map((observation, sequence) => ({
          sequence,
          method: observation.method,
          path: normalizePath(observation.path, dynamicIds),
          subjectSlot: subjectSlot(observation.subject),
          controllerAuth: observation.controllerAuthMatched ? "shared" : "unexpected",
          idempotencyKey: observation.idempotencyKey,
          requestHeaders: { ...observation.requestHeaders },
          requestBodyHex: observation.requestBodyHex,
          requestBodyDigest: observation.requestBodyDigest,
          status: observation.status,
          responseHeaders: { ...observation.responseHeaders },
          responseBodyHex: observation.responseBodyHex,
          responseBodyDigest: observation.responseBodyDigest,
          responseChunks: observation.responseChunks.map((chunk) => ({ ...chunk })),
          termination: observation.termination,
          responseCode: observation.responseCode,
          completed: observation.completed,
        }));
    },
    async flush() {
      if (pendingRequests === 0) return;
      await new Promise<void>((resolveIdle) => idleWaiters.push(resolveIdle));
    },
    assertReplayConsumed() {
      if (!replayExpected) return;
      if (replayError) throw safeError(replayError);
      if (replayIndex !== replayExpected.length) {
        throw safeError(`Endpoint cassette consumed ${replayIndex}/${replayExpected.length} exchanges`);
      }
    },
    close: () => closeServer(server),
  };
}

async function startProviderFixture(): Promise<Provider> {
  let requests = 0;
  let wake: (() => void) | undefined;
  const server = createServer((request, response) => {
    if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
      responseJson(response, 404, { error: { code: "not_found" } });
      return;
    }
    request.on("end", () => {
      requests += 1;
      wake?.();
      const body = [
        `data: ${json({ choices: [{ delta: { content: ASSISTANT_MARKER }, finish_reason: null }] })}\n\n`,
        `data: ${json({ choices: [{ delta: {}, finish_reason: "stop" }] })}\n\n`,
        "data: [DONE]\n\n",
      ].join("");
      responseText(response, 200, "text/event-stream", body);
    });
  });
  const baseUrl = await listen(server);
  return {
    baseUrl,
    requestCount: () => requests,
    async waitForRequests(count) {
      const deadline = Date.now() + READY_TIMEOUT_MS;
      while (requests < count) {
        if (Date.now() >= deadline) throw safeError(`provider fixture did not receive ${count} requests`);
        await new Promise<void>((resolveWait) => {
          wake = resolveWait;
          setTimeout(resolveWait, 100).unref();
        });
      }
    },
    close: () => closeServer(server),
  };
}

function childExecutable(name: string, fallback: string): string {
  const configured = process.env[name];
  const path = configured ? resolve(configured) : resolve(MODULE_DIRECTORY, "../../../../", fallback);
  return path;
}

async function spawnReady(program: string, args: string[], prefix: string): Promise<RunningChild> {
  const child = spawn(program, args, { stdio: ["ignore", "pipe", "pipe"] });
  let stdoutBuffer = "";
  let logs = "";
  let readyResolve: (url: string) => void = () => undefined;
  let readyReject: (error: Error) => void = () => undefined;
  let settled = false;
  const ready = new Promise<string>((resolveReady, rejectReady) => {
    readyResolve = resolveReady;
    readyReject = rejectReady;
  });
  const consume = (chunk: Buffer) => {
    logs = `${logs}${chunk.toString("utf8")}`.slice(-16_384);
    stdoutBuffer += chunk.toString("utf8");
    const lines = stdoutBuffer.split(/\r?\n/);
    stdoutBuffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!settled && line.startsWith(prefix)) {
        settled = true;
        const baseUrl = line.slice(prefix.length).trim();
        if (baseUrl) readyResolve(baseUrl);
        else readyReject(safeError(`${prefix.trim()} omitted a base URL`));
      }
    }
  };
  child.stdout?.on("data", consume);
  child.stderr?.on("data", (chunk: Buffer) => {
    // Keep only bounded diagnostics in memory; never surface them in an assertion.
    logs = `${logs}${chunk.toString("utf8")}`.slice(-16_384);
  });
  child.once("error", (error) => {
    if (!settled) {
      settled = true;
      readyReject(safeError(`real process could not start: ${error.message}`));
    }
  });
  child.once("exit", (code, signal) => {
    if (!settled) {
      settled = true;
      readyReject(safeError(`real process exited before readiness (${code ?? signal ?? "unknown"}): ${logs.slice(-2_000)}`));
    }
  });
  const timer = setTimeout(() => {
    if (!settled) {
      settled = true;
      readyReject(safeError(`real process did not emit ${prefix.trim()} readiness`));
    }
  }, READY_TIMEOUT_MS);
  timer.unref();
  const baseUrl = await ready.finally(() => clearTimeout(timer));
  return {
    baseUrl,
    logs: () => logs,
    async stop() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      await new Promise<void>((resolveStop) => {
        const timeout = setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
          resolveStop();
        }, CHILD_STOP_TIMEOUT_MS);
        timeout.unref();
        child.once("exit", () => {
          clearTimeout(timeout);
          resolveStop();
        });
      });
    },
    close: async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    },
  };
}

async function writeEndpointConfig(root: string, providerOrigin: string): Promise<{ config: string; database: string }> {
  await mkdir(join(root, "credentials"), { recursive: true });
  await mkdir(join(root, "blobs"), { recursive: true });
  const secret = join(root, "controller.secret");
  await writeFile(secret, ENDPOINT_CONTROL_SECRET, { mode: 0o600 });
  await chmod(secret, 0o600);
  const database = join(root, "endpoint.sqlite3");
  const config = join(root, "endpoint-config.json");
  await writeFile(config, json({
    schema: "zode.config.v1",
    listen: "127.0.0.1:0",
    runtime_store: { kind: "sqlite", path: database },
    credential_replica_store: { kind: "files", directory: "credentials" },
    blob_store: { kind: "files", directory: "blobs" },
    controller_auth: [{
      authority_id: ENDPOINT_AUTHORITY,
      revision: 1,
      kind: "bearer_secret_file",
      secret_file: "controller.secret",
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
      adapter_kinds: ["openai_compatible"],
      allowed_base_url_origins: [providerOrigin],
    },
    callback: { allowed_public_origins: [providerOrigin] },
    tools: [],
  }));
  return { config, database };
}

async function writeServerConfig(
  root: string,
  access: AccessFixture,
  subjectKey: string,
  controlDatabase: string,
  secretDirectory: string,
  serverPort: number,
): Promise<string> {
  await mkdir(secretDirectory, { recursive: true });
  const config = join(root, "server-config.json");
  await writeFile(config, json({
    schema: "zode.server-config.v1",
    listen: `127.0.0.1:${serverPort}`,
    management_origin: `http://127.0.0.1:${serverPort}`,
    callback_origin: `http://127.0.0.2:${serverPort}`,
    server_authority_id: SERVER_AUTHORITY,
    deployment: "server_only",
    ui_mode: "api_only",
    control_database: controlDatabase,
    secret_directory: secretDirectory,
    access: {
      issuer: access.issuer,
      audiences: [ACCESS_AUDIENCE],
      jwks_url: access.jwksUrl,
      subject_key_file: subjectKey,
      subject_key_version: 1,
    },
  }));
  return config;
}

type StoreMarker = string | Buffer;

async function fileContainsAny(root: string, markers: readonly StoreMarker[]): Promise<boolean> {
  const markerBytes = markers.map((marker) => typeof marker === "string" ? Buffer.from(marker) : marker);
  const markerNames = markers.filter((marker): marker is string => typeof marker === "string");
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch (error) {
    throw safeError(`session mirror scan could not read its store root (${error instanceof Error ? error.name : "read_error"})`);
  }
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (markerNames.some((marker) => entry.name.includes(marker))) return true;
    if (entry.isDirectory()) {
      if (await fileContainsAny(path, markers)) return true;
    } else {
      let bytes: Buffer;
      try {
        bytes = await readFile(path);
      } catch (error) {
        throw safeError(`session mirror scan could not read a store entry (${error instanceof Error ? error.name : "read_error"})`);
      }
      if (markerBytes.some((marker) => bytes.includes(marker))) return true;
    }
  }
  return false;
}

function lengthPrefixedHmac(key: Buffer, domain: string, fields: Array<string | Buffer>): Buffer {
  const mac = createHmac("sha256", key);
  const update = (value: string | Buffer): void => {
    const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.byteLength));
    mac.update(length);
    mac.update(bytes);
  };
  update(domain);
  for (const field of fields) update(field);
  return mac.digest();
}

function lengthPrefixedSha256(domain: string, fields: Array<string | Buffer>): Buffer {
  const hash = createHash("sha256");
  const update = (value: string | Buffer): void => {
    const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.byteLength));
    hash.update(length);
    hash.update(bytes);
  };
  hash.update(Buffer.from(domain, "utf8"));
  hash.update(Buffer.from([0]));
  for (const field of fields) update(field);
  return hash.digest();
}

function encodedMarkers(value: Buffer): string[] {
  return [
    value.toString("hex"),
    value.toString("base64url"),
    value.toString("base64"),
  ];
}

async function sessionMirrorMarkers(stack: TwoActorStack, sessionId: string): Promise<StoreMarker[]> {
  const subjectKey = await readFile(stack.paths.subjectKey);
  const textValues = new Set<string>();
  const byteValues = new Map<string, Buffer>();
  const addBytes = (value: Buffer): void => {
    byteValues.set(value.toString("hex"), value);
    for (const encoded of encodedMarkers(value)) textValues.add(encoded);
  };
  const addText = (value: string): void => {
    textValues.add(value);
    addBytes(Buffer.from(value, "utf8"));
  };
  addText(sessionId);
  const sessionHash = createHash("sha256").update(sessionId).digest();
  addBytes(sessionHash);
  textValues.add(`sha256:${sessionHash.toString("hex")}`);
  textValues.add(`sha256:${sessionHash.toString("base64url")}`);
  const domains = [
    "session-id-v1",
    "session-owner-v1",
    "session-acl-v1",
    "session-route-v1",
    "session-mirror-v1",
    "zode.session-owner.v1",
  ];
  const actorKeys = ["two-actor-human-a", "two-actor-human-b"].map((actor) =>
    lengthPrefixedHmac(subjectKey, "access-actor-v1", ["human", actor]),
  );
  const actorSubjects = actorKeys.map((actorKey) => `v1:${actorKey.toString("hex")}`);
  const fieldSets = [
    [sessionId],
    [SERVER_AUTHORITY, sessionId],
    [sessionId, SERVER_AUTHORITY],
    ...actorSubjects.flatMap((subject) => [
      [subject, sessionId],
      [SERVER_AUTHORITY, subject, sessionId],
      [sessionId, subject],
    ]),
    ...actorKeys.flatMap((actorKey) => [
      [actorKey, sessionId],
      [SERVER_AUTHORITY, actorKey, sessionId],
      [sessionId, actorKey],
    ]),
  ];
  for (const domain of domains) {
    for (const fields of fieldSets) {
      const value = lengthPrefixedHmac(subjectKey, domain, fields);
      addBytes(value);
      textValues.add(`v1:${value.toString("hex")}`);
      textValues.add(`${domain}:${value.toString("hex")}`);
    }
  }
  const ownerDigests = actorSubjects.flatMap((subject) => [
    lengthPrefixedSha256("zode.session-owner.v1", [SERVER_AUTHORITY, subject]),
    lengthPrefixedSha256("zode.session-owner.v1", [SERVER_AUTHORITY, subject, sessionId]),
    lengthPrefixedSha256("zode.session-owner.v1", [subject, SERVER_AUTHORITY, sessionId]),
  ]);
  for (const value of ownerDigests) {
    addBytes(value);
    textValues.add(`sha256:v1:${value.toString("hex")}`);
    textValues.add(`zode.session-owner.v1:${value.toString("hex")}`);
  }
  return [...textValues, ...byteValues.values()].filter(Boolean);
}

export async function serverStoresContainSessionMirrors(stack: TwoActorStack, sessionIds: string[]): Promise<boolean> {
  if (stack.paths.serverRoots.length === 0) {
    throw safeError("session mirror scan has no server store roots");
  }
  const markers = (await Promise.all(sessionIds.filter(Boolean).map((sessionId) => sessionMirrorMarkers(stack, sessionId)))).flat();
  for (const root of stack.paths.serverRoots) {
    if (await fileContainsAny(root, markers)) return true;
  }
  return false;
}

export type TwoActorStackOptions = {
  replayEndpointExchanges?: EndpointCassetteExchange[];
};

export async function createTwoActorStack(options: TwoActorStackOptions = {}): Promise<TwoActorStack> {
  const root = await mkdtemp(join(tmpdir(), "zode-web-two-actor-"));
  const endpointRoot = join(root, "endpoint");
  const initialServerRoot = join(root, "server-1");
  const subjectKey = join(root, "subject.key");
  await mkdir(endpointRoot, { recursive: true });
  await mkdir(initialServerRoot, { recursive: true });
  await writeFile(subjectKey, randomBytes(32), { mode: 0o600 });
  await chmod(subjectKey, 0o600);

  const access = await startAccessFixture();
  const provider = await startProviderFixture();
  const endpointConfig = await writeEndpointConfig(endpointRoot, provider.baseUrl);
  const endpointBinary = childExecutable("ZODE_ENDPOINT_BIN", "target/debug/zode");
  const serverBinary = childExecutable("ZODE_SERVER_BIN", "server/target/debug/zode-server");
  const endpoint = await spawnReady(endpointBinary, [
    "--config", endpointConfig.config,
    "--database", endpointConfig.database,
    "--listen", "127.0.0.1:0",
  ], "ZODE_READY ");
  const endpointTransport = await startEndpointTransport(endpoint.baseUrl, options.replayEndpointExchanges);
  const serverRoots = [initialServerRoot];
  const initialServerDatabase = join(initialServerRoot, "server.sqlite3");
  const initialServerSecrets = join(initialServerRoot, "server-secrets");
  const serverPort = await reserveLoopbackPort();
  const initialServerConfig = await writeServerConfig(
    initialServerRoot,
    access,
    subjectKey,
    initialServerDatabase,
    initialServerSecrets,
    serverPort,
  );
  const server = await spawnReady(serverBinary, ["--config", initialServerConfig], "ZODE_SERVER_READY ");
  const actorA = await startAccessEdge(access, "actor-a", server.baseUrl);
  const actorB = await startAccessEdge(access, "actor-b", server.baseUrl);

  const stack: TwoActorStack = {
    paths: {
      root,
      endpointRoot,
      initialServerRoot,
      serverRoots,
      endpointDatabase: endpointConfig.database,
      subjectKey,
    },
    access,
    provider,
    endpoint,
    server,
    actorA,
    actorB,
    endpointTransport,
    endpointControlSecret: ENDPOINT_CONTROL_SECRET,
    providerSecret: PROVIDER_SECRET,
    endpointBaseUrl: endpointTransport.baseUrl,
    providerBaseUrl: `${provider.baseUrl}/v1`,
    async restartServerWithFreshStore() {
      await server.stop();
      const freshRoot = join(root, `server-${serverRoots.length + 1}`);
      await mkdir(freshRoot, { recursive: true });
      serverRoots.push(freshRoot);
      const database = join(freshRoot, "server.sqlite3");
      const secrets = join(freshRoot, "server-secrets");
      const config = await writeServerConfig(freshRoot, access, subjectKey, database, secrets, serverPort);
      const restarted = await spawnReady(serverBinary, ["--config", config], "ZODE_SERVER_READY ");
      stack.server = restarted;
      actorA.setTarget(restarted.baseUrl);
      actorB.setTarget(restarted.baseUrl);
    },
    async stopServer() {
      await stack.server.stop();
    },
    async dispose() {
      await Promise.allSettled([
        actorA.close(),
        actorB.close(),
        endpointTransport.close(),
        stack.server.stop(),
        endpoint.stop(),
        provider.close(),
        access.close(),
      ]);
      await rm(root, { recursive: true, force: true });
    },
  };
  return stack;
}

export type RecordedExchange = {
  sequence: number;
  actor: AccessActor;
  method: string;
  path: string;
  request: {
    semanticHeaders: Record<string, string>;
    bodyHex: string;
    bodySha256: string;
    canonicalJson: Json | null;
  };
  response: {
    status: number;
    semanticHeaders: Record<string, string>;
    bodyHex: string;
    bodySha256: string;
    canonicalJson: Json | null;
    chunks: CassetteChunk[];
    termination: CassetteTermination;
    responseCode: string | null;
    completed: boolean;
  };
};

export type CassetteFirstObserved = {
  actor: AccessActor;
  method: string;
  path: string;
  status: number;
  safeCode: string | null;
  message: string;
  classification: CassetteClassificationKind;
  exchangeSequence: number;
};

export type CassetteClassificationKind =
  | "behavioral"
  | "shallow_non_evidence"
  | "evidence_gap_no_positive_catalog_barrier";

export type CassetteExactResponse = {
  status: number;
  semantic_headers: Record<string, string>;
  body_sha256: string;
  response_fingerprint: string;
  response_code: string | null;
  termination: CassetteTermination;
  completed: boolean;
};

export type CassetteClassification = {
  kind: CassetteClassificationKind;
  exact_response: CassetteExactResponse;
  positive_catalog_barrier: {
    required: true;
    expected_status: 200;
    observed: boolean;
    exchange_sequence: number | null;
    exact_response: CassetteExactResponse | null;
    reason: string | null;
  };
};

export type CassetteSecretSlot = {
  name: string;
  kind: string;
  semantic_sha256: string;
};

export type CassetteProvenance = {
  source_recording_id: string;
  source_digest: string;
  source_path: string;
  source_verified: boolean;
  promotion: "create_new_from_verified_raw" | "quarantine_only";
  redaction: "named_synthetic_slots_and_loopback_port_normalization";
};

export type IncidentCassette = {
  schema: "zode.web-two-actor-session-isolation-complete.v2";
  version: 2;
  recording_id: string;
  purpose: string;
  source_recording_id: string;
  owner: string;
  boundary: "browser_management_http_sse";
  secret_slots: CassetteSecretSlot[];
  provenance: CassetteProvenance;
  first_observed: CassetteFirstObserved;
  classification: CassetteClassification;
  exchanges: RecordedExchange[];
  endpointExchanges: EndpointCassetteExchange[];
  whole_digest?: string;
};

function responseFingerprint(response: RecordedExchange["response"]): string {
  return `sha256:${digest(JSON.stringify({
    status: response.status,
    semanticHeaders: response.semanticHeaders,
    bodyHex: response.bodyHex,
    bodySha256: response.bodySha256,
    chunks: response.chunks.map(({ sequence, bodyHex, bodySha256 }) => ({ sequence, bodyHex, bodySha256 })),
    responseCode: response.responseCode,
    termination: response.termination,
    completed: response.completed,
  }))}`;
}

function exactResponse(response: RecordedExchange["response"]): CassetteExactResponse {
  return {
    status: response.status,
    semantic_headers: response.semanticHeaders,
    body_sha256: response.bodySha256,
    response_fingerprint: responseFingerprint(response),
    response_code: response.responseCode,
    termination: response.termination,
    completed: response.completed,
  };
}

export function cassetteExactResponseMatches(
  response: RecordedExchange["response"],
  expected: CassetteExactResponse,
): boolean {
  return response.status === expected.status
    && JSON.stringify(response.semanticHeaders) === JSON.stringify(expected.semantic_headers)
    && response.bodySha256 === expected.body_sha256
    && responseFingerprint(response) === expected.response_fingerprint
    && response.responseCode === expected.response_code
    && response.termination === expected.termination
    && response.completed === expected.completed;
}

export function bodyDigest(body: unknown, secrets: string[], dynamicIds: string[] = []): string {
  let value = body === undefined ? "" : JSON.stringify(body) ?? "";
  for (const id of dynamicIds.filter(Boolean)) value = value.replaceAll(id, "{{OPAQUE_ID}}");
  value = value.replace(/\b[0-9A-HJKMNP-TV-Z]{26}\b/g, "{{SESSION_ID}}");
  for (const secret of secrets) {
    const slot = secret === PROVIDER_SECRET
      ? "<secret:SLOT_PROVIDER_SECRET>"
      : secret === ENDPOINT_CONTROL_SECRET
        ? "<secret:SLOT_ENDPOINT_CONTROL_SECRET>"
        : `[synthetic:${digest(secret).slice(0, 12)}]`;
    value = value.replaceAll(secret, slot);
  }
  return digest(value);
}

export function jsonDigest(value: unknown): string {
  return `sha256:${digest(JSON.stringify(value))}`;
}

function findSafeCode(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  if ("error" in value && value.error && typeof value.error === "object" && "code" in value.error && typeof value.error.code === "string") {
    return value.error.code;
  }
  return null;
}

export function exchange(
  actor: AccessActor,
  method: string,
  path: string,
  requestBody: unknown,
  status: number,
  responseBody: unknown,
  dynamicIds: string[],
  secrets: string[],
): RecordedExchange {
  const request = captureBody(
    requestBody === undefined ? undefined : JSON.stringify(requestBody),
    secrets,
    dynamicIds,
  );
  const response = captureBody(JSON.stringify(responseBody), secrets, dynamicIds);
  return {
    sequence: 0,
    actor,
    method,
    path: normalizePath(path, dynamicIds),
    request: {
      semanticHeaders: {},
      bodyHex: request.bodyHex,
      bodySha256: request.bodySha256,
      canonicalJson: request.canonicalJson,
    },
    response: {
      status,
      semanticHeaders: {},
      bodyHex: response.bodyHex,
      bodySha256: response.bodySha256,
      canonicalJson: response.canonicalJson,
      chunks: [{ sequence: 0, bodyHex: response.bodyHex, bodySha256: response.bodySha256, offsetMs: 0 }],
      termination: "complete",
      responseCode: findSafeCode(responseBody),
      completed: true,
    },
  };
}

export function firstObservedMessage(
  exchange: RecordedExchange,
  classification: CassetteFirstObserved["classification"],
): string {
  const code = exchange.response.responseCode ? ` ${exchange.response.responseCode}` : "";
  return `${exchange.actor} ${exchange.method} ${exchange.path} -> ${exchange.response.status}${code} [${classification}]`;
}

export async function writeFirstFailureCassette(cassette: IncidentCassette): Promise<string> {
  if (cassette.first_observed.classification === "behavioral" && cassette.first_observed.status === 404) {
    throw safeError("a behavioral first occurrence cannot be an unclassified 404");
  }
  const safetyText = JSON.stringify(cassette).toLowerCase();
  for (const forbidden of [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET, "cf-access-jwt-assertion", "authorization", "cookie"]) {
    if (safetyText.includes(forbidden.toLowerCase())) {
      throw safeError("first-failure cassette contains forbidden credential material");
    }
  }
  const quarantineRoot = resolve(
    process.env.ZODE_TEST_RECORDING_ROOT ?? join(MODULE_DIRECTORY, "../../../../target/test-recordings/quarantine"),
  );
  await mkdir(quarantineRoot, { recursive: true, mode: 0o700 });
  const runRoot = await mkdtemp(join(quarantineRoot, "two-actor-"));
  await chmod(runRoot, 0o700);
  const path = join(runRoot, `${cassette.recording_id}.v2.json`);
  const handle = await open(path, "wx");
  try {
    const { whole_digest: _wholeDigest, ...withoutDigest } = cassette;
    const persisted = {
      ...withoutDigest,
      whole_digest: `sha256:${digest(JSON.stringify(withoutDigest))}`,
    };
    await handle.writeFile(`${JSON.stringify(persisted, null, 2)}\n`, "utf8");
  } finally {
    await handle.close();
  }
  await chmod(path, 0o400);
  return path;
}

export async function readCassette(path: string, owner: string, recordingId: string): Promise<IncidentCassette> {
  let parsed: IncidentCassette;
  try {
    parsed = JSON.parse(await readFile(path, "utf8")) as IncidentCassette;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      throw safeError(`two-actor complete cassette is missing for ${owner}`);
    }
    throw error;
  }
  if (
    parsed.schema !== "zode.web-two-actor-session-isolation-complete.v2"
    || parsed.version !== 2
    || parsed.recording_id !== recordingId
    || typeof parsed.purpose !== "string"
    || parsed.purpose.length === 0
    || typeof parsed.source_recording_id !== "string"
    || parsed.owner !== owner
    || parsed.boundary !== "browser_management_http_sse"
    || !Array.isArray(parsed.secret_slots)
    || parsed.secret_slots.some((slot) =>
      !slot || typeof slot.name !== "string" || typeof slot.kind !== "string" || !/^sha256:[0-9a-f]{64}$/.test(slot.semantic_sha256)
    )
    || typeof parsed.provenance !== "object"
    || parsed.provenance === null
    || parsed.provenance.source_recording_id !== parsed.source_recording_id
    || !/^sha256:[0-9a-f]{64}$/.test(parsed.provenance.source_digest)
    || parsed.provenance.source_verified !== true
    || parsed.provenance.promotion !== "create_new_from_verified_raw"
    || parsed.provenance.redaction !== "named_synthetic_slots_and_loopback_port_normalization"
    || typeof parsed.provenance.source_path !== "string"
    || !Array.isArray(parsed.endpointExchanges)
    || parsed.endpointExchanges.some((exchange, index) => exchange.sequence !== index)
    || !Array.isArray(parsed.exchanges)
    || parsed.exchanges.some((exchange, index) => exchange.sequence !== index)
    || parsed.exchanges.some((exchange) => !["complete", "disconnect", "error"].includes(exchange.response.termination))
    || parsed.endpointExchanges.some((exchange) => !["complete", "disconnect", "error"].includes(exchange.termination))
    || typeof parsed.whole_digest !== "string"
  ) {
    throw safeError("two-actor complete cassette metadata is invalid");
  }
  const firstObserved = parsed.first_observed;
  const firstExchange = parsed.exchanges[firstObserved?.exchangeSequence ?? -1];
  const classification = parsed.classification;
  if (
    !firstObserved
    || !firstExchange
    || !classification
    || !["behavioral", "shallow_non_evidence", "evidence_gap_no_positive_catalog_barrier"].includes(classification.kind)
    || firstObserved.classification !== classification.kind
    || firstObserved.actor !== firstExchange.actor
    || firstObserved.method !== firstExchange.method
    || firstObserved.path !== firstExchange.path
    || firstObserved.status !== firstExchange.response.status
    || firstObserved.safeCode !== firstExchange.response.responseCode
    || !cassetteExactResponseMatches(firstExchange.response, classification.exact_response)
    || firstObserved.status !== classification.exact_response.status
    || firstObserved.safeCode !== classification.exact_response.response_code
    || firstObserved.exchangeSequence < 0
    || firstObserved.exchangeSequence >= parsed.exchanges.length
    || (firstObserved.status === 404 && classification.kind === "behavioral")
    || classification.positive_catalog_barrier.required !== true
    || classification.positive_catalog_barrier.expected_status !== 200
  ) {
    throw safeError("two-actor complete cassette first-response classification changed");
  }
  const barrier = classification.positive_catalog_barrier;
  if (barrier.observed) {
    const barrierExchange = parsed.exchanges[barrier.exchange_sequence ?? -1];
    if (
      !barrierExchange
      || barrier.exchange_sequence === null
      || barrier.exact_response === null
      || barrierExchange.response.status !== barrier.expected_status
      || !cassetteExactResponseMatches(barrierExchange.response, barrier.exact_response)
    ) {
      throw safeError("two-actor complete cassette positive catalog barrier changed");
    }
  } else if (
    classification.kind !== "evidence_gap_no_positive_catalog_barrier"
    || barrier.exchange_sequence !== null
    || barrier.exact_response !== null
  ) {
    throw safeError("two-actor complete cassette lacks a valid positive catalog barrier classification");
  }
  const safetyText = JSON.stringify(parsed).toLowerCase();
  for (const forbidden of [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET, "cf-access-jwt-assertion", "authorization", "cookie"]) {
    if (safetyText.includes(forbidden.toLowerCase())) {
      throw safeError("two-actor complete cassette contains forbidden credential material");
    }
  }
  const { whole_digest: wholeDigest, ...withoutDigest } = parsed;
  if (wholeDigest !== `sha256:${digest(JSON.stringify(withoutDigest))}`) {
    throw safeError("two-actor complete cassette integrity digest changed");
  }
  return parsed;
}
