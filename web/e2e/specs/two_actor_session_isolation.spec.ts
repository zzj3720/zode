import { expect, test, type Page } from "@playwright/test";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ASSISTANT_MARKER,
  ENDPOINT_CONTROL_SECRET,
  PROVIDER_MODEL,
  PROVIDER_NAME,
  PROVIDER_SECRET,
  cassetteExactResponseMatches,
  captureBody,
  redactForCassette,
  type AccessActor,
  type CassetteClassification,
  type CassetteTermination,
  type EndpointObservation,
  type IncidentCassette,
  type RecordedExchange,
  createTwoActorStack,
  exchange,
  normalizePath,
  firstObservedMessage,
  jsonDigest,
  readCassette,
  serverStoresContainSessionMirrors,
  writeFirstFailureCassette,
} from "../fixtures/two_actor_session_isolation/stack";

const PROFILE_LABEL = "Fixture profile";
const ENDPOINT_LABEL = "Shared Endpoint";
const SESSION_MESSAGE = "actor-a-only-message";
const ACTOR_B_MUTATION_MARKER = "actor-b-must-not-appear";
const SESSION_MESSAGE_IDEMPOTENCY_KEY = "two-actor-session-message";
const SHARING_MODE = "selected";
const CASSETTE_DIRECTORY = fileURLToPath(new URL("../fixtures/two_actor_session_isolation", import.meta.url));
const ISOLATION_CASSETTE = join(CASSETTE_DIRECTORY, "session-isolation-complete.v2.json");
const PROFILE_CASSETTE = join(CASSETTE_DIRECTORY, "provider-profile-sharing-complete.v2.json");
const ISOLATION_RECORDING_ID = "two-actor-session-isolation-first-404-complete-20260808-v2";
const PROFILE_RECORDING_ID = "two-actor-provider-profile-sharing-first-404-complete-20260808-v2";

type PublicResponse = {
  status: number;
  text: string;
  json: unknown;
  headers: Record<string, string>;
};

type SessionAdmission = {
  sessionId: string;
  body: Record<string, unknown>;
  response: PublicResponse;
  idempotencyKey: string;
};

type RecorderMode = "live" | "replay";

function isExpectedActorIsolationNotFound(_actor: AccessActor, method: string, path: string): boolean {
  return method === "GET" && /^\/v1\/sessions\/[^/]+(?:\?.*)?$/.test(path);
}

function browserSemanticHeaders(
  headers: Record<string, string>,
  dynamicIds: string[],
  secrets: string[],
): Record<string, string> {
  const allowed = new Set(["accept", "cache-control", "content-length", "content-type", "idempotency-key", "last-event-id", "location"]);
  const result: Record<string, string> = {};
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (!allowed.has(name)) continue;
    result[name] = redactForCassette(rawValue, secrets, dynamicIds);
  }
  return result;
}

function browserPath(path: string, dynamicIds: string[]): string {
  const url = new URL(path, "http://two-actor.invalid");
  return normalizePath(`${url.pathname}${url.search}`, dynamicIds);
}

function isRelevantBrowserPath(path: string): boolean {
  const pathname = new URL(path, "http://two-actor.invalid").pathname;
  return pathname === "/"
    || pathname === "/providers"
    || pathname === "/endpoints"
    || pathname === "/sessions"
    || pathname.startsWith("/v1/");
}

class ExchangeRecorder {
  private readonly observed: RecordedExchange[] = [];
  private dynamicIds: string[] = [];
  private firstFailure: { exchange: RecordedExchange; classification: CassetteClassification["kind"] } | undefined;
  private readonly browserRequests = new Map<unknown, RecordedExchange>();
  private readonly replayResponses = new Map<RecordedExchange, RecordedExchange>();
  private readonly replayExpected: RecordedExchange[] | undefined;
  private replayIndex = 0;
  private replayError: string | null = null;
  private readonly pendingCaptures: Promise<void>[] = [];
  private readonly attachedPages = new WeakSet<Page>();

  constructor(
    private readonly secrets: string[],
    replayExpected: RecordedExchange[] | undefined,
    private readonly classificationContract: CassetteClassification,
  ) {
    this.replayExpected = replayExpected;
  }

  arm(dynamicIds: string[]): void {
    this.dynamicIds = dynamicIds.filter(Boolean);
  }

  record(
    actor: AccessActor,
    method: string,
    path: string,
    requestBody: unknown,
    status: number,
    responseBody: unknown,
  ): void {
    const item = exchange(
      actor,
      method,
      path,
      requestBody,
      status,
      responseBody,
      this.dynamicIds,
      this.secrets,
    );
    item.sequence = this.observed.length;
    item.response.status = status;
    this.observed.push(item);
  }

  attachBrowserPage(page: Page, actor: AccessActor): void {
    this.attachedPages.add(page);
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (!isRelevantBrowserPath(url.pathname)) return;
      const requestBody = captureBody(request.postData() ?? undefined, this.secrets, this.dynamicIds);
      const item: RecordedExchange = {
        sequence: this.observed.length,
        actor,
        method: request.method(),
        path: browserPath(`${url.pathname}${url.search}`, this.dynamicIds),
        request: {
          semanticHeaders: browserSemanticHeaders(request.headers(), this.dynamicIds, this.secrets),
          bodyHex: requestBody.bodyHex,
          bodySha256: requestBody.bodySha256,
          canonicalJson: requestBody.canonicalJson,
        },
        response: {
          status: 0,
          semanticHeaders: {},
          bodyHex: "",
          bodySha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          canonicalJson: null,
          chunks: [],
          termination: "disconnect",
          responseCode: null,
          completed: false,
        },
      };
      this.observed.push(item);
      this.browserRequests.set(request, item);
      this.consumeReplayRequest(item);
    });
    page.on("response", (response) => {
      const item = this.browserRequests.get(response.request());
      if (!item) return;
      item.response.status = response.status();
      item.response.semanticHeaders = browserSemanticHeaders(response.headers(), this.dynamicIds, this.secrets);
      const contentType = response.headers()["content-type"] ?? "";
      if (/text\/event-stream/i.test(contentType)) return;
      const capture = response.body().then((body) => {
        this.completeItem(item, body.toString("utf8"), response.status(), response.headers(), true);
      }).catch(() => {
        this.completeItem(item, "", response.status(), response.headers(), false, "error");
      });
      this.pendingCaptures.push(capture);
    });
    page.on("requestfailed", (request) => {
      const item = this.browserRequests.get(request);
      if (!item) return;
      this.completeItem(item, "", 0, {}, false, "disconnect");
    });
  }

  private consumeReplayRequest(actual: RecordedExchange): void {
    if (!this.replayExpected) return;
    const expected = this.replayExpected[this.replayIndex];
    if (!expected) {
      this.replayError ??= `browser cassette has an unexpected exchange ${actual.sequence}`;
      return;
    }
    const mismatch = this.requestMismatch(expected, actual);
    if (mismatch) {
      this.replayError ??= `browser cassette exchange ${expected.sequence} changed: ${mismatch}`;
      return;
    }
    this.replayResponses.set(actual, expected);
    this.replayIndex += 1;
  }

  private requestMismatch(expected: RecordedExchange, actual: RecordedExchange): string | null {
    if (expected.actor !== actual.actor) return "actor changed";
    if (expected.method !== actual.method) return "method changed";
    if (expected.path !== actual.path) return `path ${actual.path} != ${expected.path}`;
    if (JSON.stringify(expected.request.semanticHeaders) !== JSON.stringify(actual.request.semanticHeaders)) return "request semantic headers changed";
    if (expected.request.bodyHex !== actual.request.bodyHex) return "request body changed";
    if (expected.request.bodySha256 !== actual.request.bodySha256) return "request body digest changed";
    return null;
  }

  private completeItem(
    item: RecordedExchange,
    rawBody: string,
    status: number,
    headers: Record<string, string>,
    completed: boolean,
    termination: CassetteTermination = completed ? "complete" : "disconnect",
  ): void {
    if (item.response.completed || (item.response.status !== 0 && item.response.bodyHex !== "")) return;
    const responseBody = captureBody(rawBody, this.secrets, this.dynamicIds);
    item.response.status = status;
    item.response.semanticHeaders = browserSemanticHeaders(headers, this.dynamicIds, this.secrets);
    item.response.bodyHex = responseBody.bodyHex;
    item.response.bodySha256 = responseBody.bodySha256;
    item.response.canonicalJson = responseBody.canonicalJson;
    item.response.chunks = rawBody.length === 0
      ? []
      : [{ sequence: 0, bodyHex: responseBody.bodyHex, bodySha256: responseBody.bodySha256, offsetMs: 0 }];
    item.response.termination = termination;
    item.response.responseCode = findSafeResponseCode(responseBody.canonicalJson);
    item.response.completed = completed;
    const expected = this.replayResponses.get(item);
    if (expected) {
      const mismatch = this.responseMismatch(expected, item);
      if (mismatch) this.replayError ??= `browser cassette exchange ${expected.sequence} changed: ${mismatch}`;
    }
  }

  private responseMismatch(expected: RecordedExchange, actual: RecordedExchange): string | null {
    if (expected.response.status !== actual.response.status) return `status ${actual.response.status} != ${expected.response.status}`;
    if (JSON.stringify(expected.response.semanticHeaders) !== JSON.stringify(actual.response.semanticHeaders)) return "response semantic headers changed";
    if (expected.response.bodyHex !== actual.response.bodyHex) return "response body changed";
    if (expected.response.bodySha256 !== actual.response.bodySha256) return "response body digest changed";
    const expectedChunks = expected.response.chunks.map(({ sequence, bodyHex, bodySha256 }) => ({ sequence, bodyHex, bodySha256 }));
    const actualChunks = actual.response.chunks.map(({ sequence, bodyHex, bodySha256 }) => ({ sequence, bodyHex, bodySha256 }));
    if (JSON.stringify(expectedChunks) !== JSON.stringify(actualChunks)) return "response chunks changed";
    if (expected.response.termination !== actual.response.termination) return "response termination changed";
    if (expected.response.completed !== actual.response.completed) return "response completion changed";
    return null;
  }

  classifyFirstFailure(): { exchange: RecordedExchange; classification: CassetteClassification["kind"] } | undefined {
    if (this.firstFailure) return this.firstFailure;
    const candidate = [...this.observed]
      .filter((item) => item.response.status >= 400 && !isExpectedActorIsolationNotFound(item.actor, item.method, item.path))
      .sort((left, right) => left.sequence - right.sequence)[0];
    if (!candidate) return undefined;
    if (!cassetteExactResponseMatches(candidate.response, this.classificationContract.exact_response)) {
      throw new Error(
        `first failure response no longer matches the cassette exact-response contract: ${candidate.actor} ${candidate.method} ${candidate.path} -> ${candidate.response.status} ${candidate.response.responseCode ?? "no-code"}`,
      );
    }
    const barrier = this.classificationContract.positive_catalog_barrier;
    if (barrier.observed) {
      const barrierExchange = this.observed.find((item) =>
        barrier.exact_response !== null && cassetteExactResponseMatches(item.response, barrier.exact_response),
      );
      if (!barrierExchange || barrierExchange.sequence !== barrier.exchange_sequence || barrierExchange.response.status !== barrier.expected_status) {
        throw new Error("positive catalog barrier no longer matches the cassette contract");
      }
    } else if (this.classificationContract.kind !== "evidence_gap_no_positive_catalog_barrier") {
      throw new Error("cassette classification claims evidence without a positive catalog barrier");
    }
    this.firstFailure = {
      exchange: candidate,
      classification: barrier.observed ? this.classificationContract.kind : "evidence_gap_no_positive_catalog_barrier",
    };
    return this.firstFailure;
  }

  completeBrowserResult(
    actor: AccessActor,
    method: string,
    path: string,
    requestBody: unknown,
    status: number,
    responseBody: string,
    responseHeaders: Record<string, string> = {},
    completed = true,
    termination: CassetteTermination = completed ? "complete" : "disconnect",
  ): void {
    const request = captureBody(requestBody === undefined ? undefined : JSON.stringify(requestBody), this.secrets, this.dynamicIds);
    const normalizedPath = browserPath(path, this.dynamicIds);
    const item = this.observed.find((candidate) =>
      candidate.actor === actor
      && candidate.method === method
      && candidate.path === normalizedPath
      && candidate.request.bodyHex === request.bodyHex
      && !candidate.response.completed,
    );
    if (item) this.completeItem(item, responseBody, status, responseHeaders, completed, termination);
  }

  async flush(): Promise<void> {
    await Promise.all(this.pendingCaptures.splice(0));
  }

  async assertReplayConsumed(): Promise<void> {
    await this.flush();
    if (!this.replayExpected) return;
    if (this.replayError) throw new Error(this.replayError);
    if (this.replayIndex !== this.replayExpected.length) {
      throw new Error(`browser cassette consumed ${this.replayIndex}/${this.replayExpected.length} exchanges`);
    }
  }

  isBrowserPage(page: Page): boolean {
    return this.attachedPages.has(page);
  }

  values(): RecordedExchange[] {
    return [...this.observed];
  }

  firstObserved(): { exchange: RecordedExchange; classification: CassetteClassification["kind"] } | undefined {
    return this.firstFailure;
  }
}

function findSafeResponseCode(value: unknown): string | null {
  if (!value || typeof value !== "object" || !("error" in value)) return null;
  const error = value.error;
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") return error.code;
  return null;
}

function mode(): RecorderMode {
  return process.env.ZODE_WEB_TWO_ACTOR_MODE === "replay" ? "replay" : "live";
}

function quarantineCassette(
  base: IncidentCassette,
  first: { exchange: RecordedExchange; classification: CassetteClassification["kind"] },
  exchanges: RecordedExchange[],
  endpointExchanges: IncidentCassette["endpointExchanges"],
): IncidentCassette {
  const recordingId = `${base.recording_id}-quarantine-${Date.now()}`;
  return {
    ...base,
    recording_id: recordingId,
    source_recording_id: recordingId,
    purpose: `${base.purpose} (quarantine-only live capture)`,
    provenance: {
      ...base.provenance,
      source_recording_id: recordingId,
      source_digest: jsonDigest({ exchanges, endpointExchanges }),
      source_path: "in-memory-live-capture",
      source_verified: false,
      promotion: "quarantine_only",
    },
    first_observed: {
      actor: first.exchange.actor,
      method: first.exchange.method,
      path: first.exchange.path,
      status: first.exchange.response.status,
      safeCode: first.exchange.response.responseCode,
      message: firstObservedMessage(first.exchange, first.classification),
      classification: first.classification,
      exchangeSequence: first.exchange.sequence,
    },
    exchanges,
    endpointExchanges,
  };
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function asJson(response: PublicResponse): Record<string, unknown> {
  return asObject(response.json);
}

function containsValue(value: unknown, expected: string): boolean {
  if (value === expected) return true;
  if (Array.isArray(value)) return value.some((item) => containsValue(item, expected));
  if (value && typeof value === "object") return Object.values(value).some((item) => containsValue(item, expected));
  return false;
}

function objectsWith(value: unknown, predicate: (object: Record<string, unknown>) => boolean): Record<string, unknown>[] {
  const matches: Record<string, unknown>[] = [];
  if (Array.isArray(value)) {
    for (const item of value) matches.push(...objectsWith(item, predicate));
  } else if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    if (predicate(object)) matches.push(object);
    for (const item of Object.values(object)) matches.push(...objectsWith(item, predicate));
  }
  return matches;
}

async function publicRequest(
  page: Page,
  actor: AccessActor,
  method: string,
  path: string,
  body: unknown,
  idempotencyKey: string | undefined,
  recorder: ExchangeRecorder,
  record = true,
): Promise<PublicResponse> {
  const result = await page.evaluate(async ({ method, path, body, idempotencyKey }) => {
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== null) headers["content-type"] = "application/json";
    if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
    const response = await fetch(path, {
      method,
      headers,
      body: body === null ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      // The public stream/document boundary is allowed to be non-JSON.
    }
    return { status: response.status, text, json: parsed, headers: Object.fromEntries(response.headers.entries()) };
  }, { method, path, body: body === undefined ? null : body, idempotencyKey });
  if (recorder.isBrowserPage(page)) {
    recorder.completeBrowserResult(actor, method, path, body, result.status, result.text, result.headers, true);
  } else if (record) {
    recorder.record(actor, method, path, body, result.status, result.json);
  }
  return result;
}

async function gotoPublic(page: Page, actor: AccessActor, baseUrl: string, path: string, recorder: ExchangeRecorder): Promise<void> {
  const response = await page.goto(`${baseUrl}${path}`, { waitUntil: "domcontentloaded" });
  if (!recorder.isBrowserPage(page)) recorder.record(actor, "GET", path, undefined, response?.status() ?? 0, null);
}

async function waitForReplicaReady(
  page: Page,
  actor: AccessActor,
  profileId: string,
  endpointId: string,
  recorder: ExchangeRecorder,
): Promise<PublicResponse> {
  let last: PublicResponse | undefined;
  await expect.poll(async () => {
    last = await publicRequest(
      page,
      actor,
      "GET",
      `/v1/auth-profiles/${profileId}/replicas`,
      undefined,
      undefined,
      recorder,
    );
    const replicas = asJson(last).replicas ?? last.json;
    const endpointReplica = objectsWith(replicas, (object) => object.endpoint_id === endpointId)[0];
    return endpointReplica?.status ?? "missing";
  }, { timeout: 15_000, intervals: [100, 250, 500, 1_000] }).toBe("ready");
  return last as PublicResponse;
}

async function readEndpointEventsUntil(
  page: Page,
  actor: AccessActor,
  path: string,
  requiredValues: string[],
  recorder: ExchangeRecorder,
): Promise<{ status: number; data: string }> {
  const result = await page.evaluate(async ({ path, requiredValues }) => {
    const controller = new AbortController();
    let status = 0;
    let headers: Record<string, string> = {};
    let data = "";
    const read = (async () => {
      try {
        const response = await fetch(path, {
          headers: { accept: "text/event-stream" },
          signal: controller.signal,
        });
        status = response.status;
        headers = Object.fromEntries(response.headers.entries());
        if (!response.ok || !response.body) return { status, data, headers };
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        try {
          while (!controller.signal.aborted) {
            const next = await reader.read();
            if (next.done) break;
            data += decoder.decode(next.value, { stream: true });
            if (requiredValues.every((value) => data.includes(value))) break;
          }
        } finally {
          void reader.cancel().catch(() => undefined);
        }
      } catch {
        // The bounded timeout below returns the safely observed prefix.
      }
      return { status, data, headers };
    })();
    let timer = 0;
    const timeout = new Promise<{ status: number; data: string; headers: Record<string, string> }>((resolveTimeout) => {
      timer = window.setTimeout(() => {
        controller.abort();
        resolveTimeout({ status, data, headers });
      }, 20_000);
    });
    const observed = await Promise.race([read, timeout]);
    window.clearTimeout(timer);
    controller.abort();
    return observed;
  }, { path, requiredValues });
  if (recorder.isBrowserPage(page)) {
    recorder.completeBrowserResult(
      actor,
      "GET",
      path,
      undefined,
      result.status,
      result.data,
      result.headers,
      result.data.length > 0,
      "disconnect",
    );
  } else {
    recorder.record(actor, "GET", path, undefined, result.status, null);
  }
  return result;
}

async function expectNoSecrets(response: PublicResponse, secrets: string[]): Promise<void> {
  for (const secret of secrets) expect(response.text).not.toContain(secret);
}

async function expectSafeNotFound(response: PublicResponse, secrets: string[]): Promise<void> {
  expect(response.status).toBe(404);
  await expectNoSecrets(response, secrets);
  expect(response.text).not.toContain(ASSISTANT_MARKER);
}

async function expectNoBrowserCredentialState(page: Page, forbidden: string[]): Promise<void> {
  const state = await page.evaluate(() => JSON.stringify({
    location: location.href,
    localStorage: Object.fromEntries(Object.entries(localStorage)),
    sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
    cookies: document.cookie,
  }));
  for (const marker of forbidden) expect(state).not.toContain(marker);
}

async function expectSharedProviderResource(
  page: Page,
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  endpointId: string,
  profileId: string,
  recorder: ExchangeRecorder,
  recordPublic = true,
): Promise<void> {
  await gotoPublic(page, "actor-b", stack.actorB.baseUrl, "/", recorder);
  const endpoints = await publicRequest(page, "actor-b", "GET", "/v1/endpoints", undefined, undefined, recorder, recordPublic);
  expect(endpoints.status).toBe(200);
  expect(containsValue(endpoints.json, endpointId)).toBe(true);

  const providers = await publicRequest(page, "actor-b", "GET", "/v1/providers", undefined, undefined, recorder, recordPublic);
  expect(providers.status).toBe(200);
  expect(containsValue(providers.json, PROVIDER_NAME)).toBe(true);
  expect(containsValue(providers.json, profileId)).toBe(true);

  const profiles = await publicRequest(
    page,
    "actor-b",
    "GET",
    `/v1/providers/${PROVIDER_NAME}/auth-profiles`,
    undefined,
    undefined,
    recorder,
    recordPublic,
  );
  expect(profiles.status).toBe(200);
  const sharedProfile = objectsWith(profiles.json, (object) => object.auth_profile_id === profileId)[0];
  expect(sharedProfile).toBeDefined();
  expect(sharedProfile?.label).toBe(PROFILE_LABEL);
  expect(sharedProfile?.is_default === true || sharedProfile?.default === true).toBe(true);
  const sharing = sharedProfile?.sharing ?? sharedProfile?.sharing_policy;
  expect(sharing).toEqual(expect.objectContaining({ mode: SHARING_MODE }));
  expect(containsValue(sharing, endpointId)).toBe(true);
  const defaultObjects = objectsWith(providers.json, (object) =>
    (object.auth_profile_id === profileId && (object.is_default === true || object.default === true))
      || object.default_auth_profile_id === profileId
      || object.default_profile_id === profileId,
  );
  expect(defaultObjects.length).toBeGreaterThan(0);

  const replicas = await publicRequest(
    page,
    "actor-b",
    "GET",
    `/v1/auth-profiles/${profileId}/replicas`,
    undefined,
    undefined,
    recorder,
    recordPublic,
  );
  expect(replicas.status).toBe(200);
  const endpointReplica = objectsWith(replicas.json, (object) => object.endpoint_id === endpointId)[0];
  expect(endpointReplica).toBeDefined();
  expect(endpointReplica?.status).toBe("ready");
  expect(containsValue(endpointReplica, profileId)).toBe(true);

  await gotoPublic(page, "actor-b", stack.actorB.baseUrl, "/providers", recorder);
  await expect(page.locator("body")).toContainText(PROFILE_LABEL, { timeout: 15_000 });
  await expect(resourceCard(page, PROVIDER_NAME)).toContainText(
    new RegExp(`${ENDPOINT_LABEL}[^\\n]*(?:ready|installed)`, "i"),
  );
  const providerText = await page.locator("body").innerText();
  expect(providerText).toContain(PROFILE_LABEL);
  expect(providerText).toContain(ENDPOINT_LABEL);
  expect(providerText).toMatch(/ready|installed/i);
  for (const forbidden of [/\bpersonal\b/i, /\bowner\b/i, /\bworkspace\b/i, /\brole\b/i, /\bgrant\b/i]) {
    expect(providerText).not.toMatch(forbidden);
  }
}

function watchDirectEndpointRequests(page: Page, endpointBaseUrl: string): string[] {
  const requests: string[] = [];
  page.on("request", (request) => {
    if (request.url().startsWith(endpointBaseUrl)) requests.push(request.url());
  });
  return requests;
}

function isEndpointSessionPath(path: string): boolean {
  return path === "/v1/events" || path === "/v1/sessions" || /^\/v1\/sessions\/[^/]+(?:\/messages)?$/.test(path);
}

function assertEndpointOwnershipTrace(
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  admission: SessionAdmission,
  actorBSessionId: string,
): void {
  const observations: EndpointObservation[] = stack.endpointTransport.observations()
    .filter((observation) => isEndpointSessionPath(observation.path));
  expect(observations.length, "Server must reach the real Endpoint session API").toBeGreaterThan(0);
  expect(
    observations.every((observation) => observation.subject === null),
    "Server must not forward Zode-Subject to Endpoint",
  ).toBe(true);
  expect(
    observations.every((observation) => observation.controllerAuthMatched === false),
    "Server must not send an Endpoint controller bearer",
  ).toBe(true);

  const createRequests = observations.filter(
    (observation) => observation.method === "POST"
      && observation.path === "/v1/sessions"
      && observation.idempotencyKey === admission.idempotencyKey,
  );
  expect(createRequests.length).toBeGreaterThanOrEqual(3);
  expect(createRequests[0]?.status).toBe(404);
  expect(createRequests.slice(1).every((observation) => observation.status === 201)).toBe(true);
  expect(createRequests.slice(1).every((observation) =>
    observation.requestBodyDigest === createRequests[0]?.requestBodyDigest
  )).toBe(true);
  expect(createRequests.filter((observation) => observation.status === 201)
    .every((observation) => observation.responseBodyDigest === createRequests[1]?.responseBodyDigest)).toBe(true);

  const actorASessionPath = `/v1/sessions/${admission.sessionId}`;
  const actorBSessionPath = `/v1/sessions/${actorBSessionId}`;
  const sessionReads = observations.filter(
    (observation) => observation.method === "GET" && observation.path === actorASessionPath,
  );
  expect(sessionReads.length).toBeGreaterThan(0);
  expect(sessionReads.every((observation) => observation.status === 200)).toBe(true);

  const messageRequests = observations.filter(
    (observation) => observation.path === `${actorASessionPath}/messages`
      && observation.idempotencyKey === SESSION_MESSAGE_IDEMPOTENCY_KEY,
  );
  expect(messageRequests[0]?.status).toBe(404);
  expect(messageRequests.some((observation) => observation.status === 202)).toBe(true);
  expect(
    messageRequests.slice(1).every((observation) => observation.status === 202 || observation.status === 409),
  ).toBe(true);

  const secondSession = observations.filter(
    (observation) => observation.method === "POST"
      && observation.path === "/v1/sessions"
      && observation.idempotencyKey === "two-actor-session-create-b",
  );
  expect(secondSession.some((observation) => observation.status === 201)).toBe(true);
  expect(actorBSessionPath).not.toBe(actorASessionPath);
}

function resourceCard(page: Page, heading: string) {
  return page.locator("article").filter({
    has: page.getByRole("heading", { name: heading, exact: true }),
  });
}

async function openProviders(page: Page): Promise<void> {
  await openManagementPage(page, "Providers");
  await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
}

async function openEndpoints(page: Page): Promise<void> {
  await openManagementPage(page, "Endpoints");
  await expect(page.getByRole("heading", { name: "Endpoints", exact: true })).toBeVisible();
}

async function openManagementPage(page: Page, name: "Endpoints" | "Providers"): Promise<void> {
  const link = page.getByRole("link", { name, exact: true });
  if (await link.isVisible()) {
    await link.click();
    return;
  }
  await page.getByRole("button", { name: "Manage Zode", exact: true }).click();
  await page.getByRole("menuitem", { name, exact: true }).click();
}

async function configureSharedResourcesViaUi(
  page: Page,
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  recorder: ExchangeRecorder,
  onProfileCreated?: (resource: { endpointId: string; profileId: string }) => void,
): Promise<{ endpointId: string; profileId: string; descriptorRevision: number; profileRevision: number }> {
  await page.goto(`${stack.actorA.baseUrl}/providers`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
  await openEndpoints(page);
  await page.getByRole("button", { name: "Add remote Endpoint" }).click();
  const endpointDialog = page.getByRole("dialog", { name: "Add remote Endpoint" });
  await endpointDialog.getByLabel("Endpoint label").fill(ENDPOINT_LABEL);
  await endpointDialog.getByLabel("Endpoint URL").fill(stack.endpointBaseUrl);
  await endpointDialog.getByLabel(/^Controller credential(?: \(write-only\))?$/).fill(stack.endpointControlSecret);
  const endpointResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/endpoints",
  );
  await endpointDialog.getByRole("button", { name: "Add Endpoint" }).click();
  const endpointResponse = await endpointResponsePromise;
  expect(endpointResponse.status()).toBe(201);
  const endpointBody = (await endpointResponse.json()) as Record<string, unknown>;
  const endpointId = String(endpointBody.endpoint_id ?? "");
  expect(endpointId).not.toBe("");
  await expect(endpointDialog).toBeHidden();
  await expect(resourceCard(page, ENDPOINT_LABEL)).toContainText(/online|ready/i);

  await openProviders(page);
  await page.getByRole("button", { name: "Configure provider" }).click();
  const providerForm = page.locator("form").filter({
    has: page.getByRole("heading", { name: "Configure provider", exact: true }),
  });
  await providerForm.getByLabel("Provider ID").fill(PROVIDER_NAME);
  await providerForm.getByLabel("Base URL").fill(stack.providerBaseUrl);
  await providerForm.getByLabel("Models").fill(PROVIDER_MODEL);
  const descriptorResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "PUT" && new URL(response.url()).pathname === `/v1/providers/${PROVIDER_NAME}`,
  );
  await providerForm.getByRole("button", { name: "Save provider" }).click();
  const descriptorResponse = await descriptorResponsePromise;
  expect(descriptorResponse.status()).toBe(200);
  const descriptorBody = (await descriptorResponse.json()) as Record<string, unknown>;
  const descriptorRevision = Number(descriptorBody.revision ?? 0);
  expect(descriptorRevision).toBeGreaterThan(0);
  await expect(providerForm).toBeHidden();

  const providerCard = resourceCard(page, PROVIDER_NAME);
  await providerCard.getByRole("button", { name: "Add API key profile" }).click();
  const profileForm = providerCard
    .locator("form.nested-editor")
    .filter({ hasText: "Add API key profile" });
  await expect(profileForm).toBeVisible();
  await profileForm.getByLabel("Profile label").fill(PROFILE_LABEL);
  const apiKey = profileForm.getByLabel("API key", { exact: true });
  await expect(apiKey).toHaveAttribute("type", "password");
  await apiKey.fill(stack.providerSecret);
  await profileForm.getByRole("checkbox", { name: "Make this the default profile" }).check();
  await profileForm.getByRole("checkbox", { name: `Share with ${ENDPOINT_LABEL}` }).check();
  const profileResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && new URL(response.url()).pathname === `/v1/providers/${PROVIDER_NAME}/auth-profiles`,
  );
  await profileForm.getByRole("button", { name: "Create profile" }).click();
  const profileResponse = await profileResponsePromise;
  expect(profileResponse.status()).toBe(201);
  const profileBody = (await profileResponse.json()) as Record<string, unknown>;
  const profileId = String(profileBody.auth_profile_id ?? "");
  const profileRevision = Number(profileBody.revision ?? 0);
  expect(profileId).not.toBe("");
  expect(profileRevision).toBeGreaterThan(0);
  onProfileCreated?.({ endpointId, profileId });
  await expect(profileForm).toBeHidden();
  await expect(providerCard).toContainText(PROFILE_LABEL);
  await expect(providerCard).toContainText(/explicit default|default profile/i);
  await expect.poll(async () => {
    return (await providerCard.innerText()).toLowerCase();
  }, {
    timeout: 15_000,
    intervals: [100, 250, 500, 1_000],
  }).toMatch(new RegExp(`${ENDPOINT_LABEL.toLowerCase()}[^\\n]*(?:ready|installed)`));
  return { endpointId, profileId, descriptorRevision, profileRevision };
}

async function configureSharedResources(
  page: Page,
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  recorder: ExchangeRecorder,
): Promise<{ endpointId: string; profileId: string; descriptorRevision: number; profileRevision: number }> {
  await gotoPublic(page, "actor-a", stack.actorA.baseUrl, "/", recorder);
  const system = await publicRequest(page, "actor-a", "GET", "/v1/system", undefined, undefined, recorder);
  expect(system.status).toBe(200);
  await expectNoSecrets(system, [stack.providerSecret, stack.endpointControlSecret]);

  const endpoint = await publicRequest(
    page,
    "actor-a",
    "POST",
    "/v1/endpoints",
    {
      label: ENDPOINT_LABEL,
      base_url: stack.endpointBaseUrl,
      control_auth: { kind: "bearer", secret: stack.endpointControlSecret },
    },
    "two-actor-endpoint-add",
    recorder,
  );
  expect(endpoint.status).toBe(201);
  await expectNoSecrets(endpoint, [stack.providerSecret, stack.endpointControlSecret]);
  const endpointId = String(asJson(endpoint).endpoint_id ?? "");
  expect(endpointId).not.toBe("");

  const descriptor = await publicRequest(
    page,
    "actor-a",
    "PUT",
    `/v1/providers/${PROVIDER_NAME}`,
    {
      kind: "openai_compatible",
      base_url: stack.providerBaseUrl,
      models: [PROVIDER_MODEL],
      options: {},
    },
    "two-actor-provider-descriptor",
    recorder,
  );
  expect(descriptor.status).toBe(200);
  const descriptorRevision = Number(asJson(descriptor).revision ?? 0);
  expect(descriptorRevision).toBeGreaterThan(0);

  const profile = await publicRequest(
    page,
    "actor-a",
    "POST",
    `/v1/providers/${PROVIDER_NAME}/auth-profiles`,
    {
      kind: "api_key",
      label: PROFILE_LABEL,
      api_key: stack.providerSecret,
      make_default: true,
      sharing: { mode: SHARING_MODE, endpoint_ids: [endpointId] },
    },
    "two-actor-profile-create",
    recorder,
  );
  expect(profile.status).toBe(201);
  await expectNoSecrets(profile, [stack.providerSecret, stack.endpointControlSecret]);
  const profileId = String(asJson(profile).auth_profile_id ?? "");
  const profileRevision = Number(asJson(profile).revision ?? 0);
  expect(profileId).not.toBe("");
  expect(profileRevision).toBeGreaterThan(0);
  recorder.arm([endpointId, profileId]);

  await waitForReplicaReady(page, "actor-a", profileId, endpointId, recorder);
  recorder.arm([endpointId, profileId]);
  return { endpointId, profileId, descriptorRevision, profileRevision };
}

async function createActorASession(
  page: Page,
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  resource: { endpointId: string; profileId: string; descriptorRevision: number; profileRevision: number },
  recorder: ExchangeRecorder,
  recordPublic = true,
): Promise<SessionAdmission> {
  const body = {
    model: {
      provider: PROVIDER_NAME,
      model: PROVIDER_MODEL,
      provider_execution: {
        schema: "zode.provider-execution.v1",
        revision: resource.descriptorRevision,
        kind: "openai_compatible",
        base_url: stack.providerBaseUrl,
        options: {},
      },
      auth_profile_id: resource.profileId,
      minimum_auth_revision: resource.profileRevision,
    },
  };
  const idempotencyKey = "two-actor-session-create";
  const created = await publicRequest(
    page,
    "actor-a",
    "POST",
    `/v1/endpoints/${resource.endpointId}/sessions`,
    body,
    idempotencyKey,
    recorder,
    recordPublic,
  );
  expect(created.status).toBe(201);
  const sessionId = String(asJson(created).session_id ?? "");
  expect(sessionId).not.toBe("");
  recorder.arm([resource.endpointId, resource.profileId, sessionId]);
  return { sessionId, body, response: created, idempotencyKey };
}

async function assertCreateIdempotencyScope(
  pageA: Page,
  pageB: Page,
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  resource: { endpointId: string },
  admission: SessionAdmission,
  recorder: ExchangeRecorder,
  recordPublic = true,
): Promise<string> {
  const path = `/v1/endpoints/${resource.endpointId}/sessions`;
  const actorAReplay = await publicRequest(
    pageA,
    "actor-a",
    "POST",
    path,
    admission.body,
    admission.idempotencyKey,
    recorder,
    recordPublic,
  );
  expect(actorAReplay.status).toBe(admission.response.status);
  expect(actorAReplay.text).toBe(admission.response.text);
  expect(actorAReplay.json).toEqual(admission.response.json);

  const actorBSameKey = await publicRequest(
    pageB,
    "actor-b",
    "POST",
    path,
    admission.body,
    admission.idempotencyKey,
    recorder,
    recordPublic,
  );
  expect(actorBSameKey.status).toBe(201);
  expect(actorBSameKey.text).toBe(admission.response.text);
  expect(asJson(actorBSameKey).session_id).toBe(admission.sessionId);
  await expectNoSecrets(actorBSameKey, [stack.providerSecret, stack.endpointControlSecret]);

  const actorBNew = await publicRequest(
    pageB,
    "actor-b",
    "POST",
    path,
    admission.body,
    "two-actor-session-create-b",
    recorder,
    recordPublic,
  );
  expect(actorBNew.status).toBe(201);
  const actorBSessionId = String(asJson(actorBNew).session_id ?? "");
  expect(actorBSessionId).not.toBe("");
  expect(actorBSessionId).not.toBe(admission.sessionId);
  await expectNoSecrets(actorBNew, [stack.providerSecret, stack.endpointControlSecret]);
  return actorBSessionId;
}

async function assertSessionIsolation(
  pageA: Page,
  pageB: Page,
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  resource: { endpointId: string; profileId: string; descriptorRevision: number; profileRevision: number },
  sessionId: string,
  recorder: ExchangeRecorder,
  includeProviderRound: boolean,
  actorBSessionId: string,
  recordPublic = true,
): Promise<void> {
  const sessionPath = `/v1/endpoints/${resource.endpointId}/sessions/${sessionId}`;
  const endpointEventsPath = `/v1/endpoints/${resource.endpointId}/events`;
  const sessionRoute = `/endpoints/${resource.endpointId}/sessions/${sessionId}`;
  const listPath = `/v1/endpoints/${resource.endpointId}/sessions`;
  const forbidden = [stack.providerSecret, stack.endpointControlSecret];
  let actorAMessageResponse: PublicResponse | undefined;

  if (includeProviderRound) {
    const stream = readEndpointEventsUntil(
      pageA,
      "actor-a",
      endpointEventsPath,
      [sessionId, ASSISTANT_MARKER],
      recorder,
    );
    const message = await publicRequest(
      pageA,
      "actor-a",
      "POST",
      `${sessionPath}/messages`,
      { content: SESSION_MESSAGE },
      SESSION_MESSAGE_IDEMPOTENCY_KEY,
      recorder,
      recordPublic,
    );
    actorAMessageResponse = message;
    expect(message.status).toBe(202);
    const assistant = await stream;
    expect(assistant.status).toBe(200);
    expect(assistant.data).toContain(ASSISTANT_MARKER);
    await stack.provider.waitForRequests(1);

    const providerRequestCount = stack.provider.requestCount();
    const actorAMessageReplay = await publicRequest(
      pageA,
      "actor-a",
      "POST",
      `${sessionPath}/messages`,
      { content: SESSION_MESSAGE },
      SESSION_MESSAGE_IDEMPOTENCY_KEY,
      recorder,
      recordPublic,
    );
    expect(actorAMessageReplay.status).toBe(message.status);
    expect(actorAMessageReplay.text).toBe(message.text);
    expect(actorAMessageReplay.json).toEqual(message.json);
    expect(stack.provider.requestCount()).toBe(providerRequestCount);
  }

  const actorAList = await publicRequest(pageA, "actor-a", "GET", listPath, undefined, undefined, recorder, recordPublic);
  expect(actorAList.status).toBe(200);
  expect(containsValue(actorAList.json, sessionId)).toBe(true);

  const actorBList = await publicRequest(pageB, "actor-b", "GET", listPath, undefined, undefined, recorder, recordPublic);
  expect(actorBList.status).toBe(200);
  expect(containsValue(actorBList.json, sessionId)).toBe(true);
  if (actorBSessionId) {
    expect(containsValue(actorBList.json, actorBSessionId)).toBe(true);
    const actorBOwnRead = await publicRequest(
      pageB,
      "actor-b",
      "GET",
      `/v1/endpoints/${resource.endpointId}/sessions/${actorBSessionId}`,
      undefined,
      undefined,
      recorder,
      recordPublic,
    );
    expect(actorBOwnRead.status).toBe(200);
  }

  const actorARead = await publicRequest(pageA, "actor-a", "GET", sessionPath, undefined, undefined, recorder, recordPublic);
  expect(actorARead.status).toBe(200);
  if (includeProviderRound) expect(actorARead.text).toContain(ASSISTANT_MARKER);

  const actorBRead = await publicRequest(pageB, "actor-b", "GET", sessionPath, undefined, undefined, recorder, recordPublic);
  expect(actorBRead.status).toBe(200);

  const actorBStream = await readEndpointEventsUntil(
    pageB,
    "actor-b",
    endpointEventsPath,
    [actorBSessionId],
    recorder,
  );
  expect(actorBStream.status).toBe(200);
  expect(actorBStream.data).toContain(actorBSessionId);
  expect(actorBStream.data).toContain(sessionId);
  for (const secret of forbidden) expect(actorBStream.data).not.toContain(secret);

  const actorBSameBodyMutation = await publicRequest(
    pageB,
    "actor-b",
    "POST",
    `${sessionPath}/messages`,
    { content: SESSION_MESSAGE },
    SESSION_MESSAGE_IDEMPOTENCY_KEY,
    recorder,
    recordPublic,
  );
  expect(actorBSameBodyMutation.status).toBe(202);
  if (actorAMessageResponse) expect(actorBSameBodyMutation.text).toBe(actorAMessageResponse.text);

  const actorBMutate = await publicRequest(
    pageB,
    "actor-b",
    "POST",
    `${sessionPath}/messages`,
    { content: ACTOR_B_MUTATION_MARKER },
    SESSION_MESSAGE_IDEMPOTENCY_KEY,
    recorder,
    recordPublic,
  );
  expect([202, 409]).toContain(actorBMutate.status);

  const actorAReadAfterB = await publicRequest(
    pageA,
    "actor-a",
    "GET",
    sessionPath,
    undefined,
    undefined,
    recorder,
    recordPublic,
  );
  expect(actorAReadAfterB.status).toBe(200);
  expect(actorAReadAfterB.text).not.toContain(ACTOR_B_MUTATION_MARKER);
  if (includeProviderRound) expect(actorAReadAfterB.text).toContain(ASSISTANT_MARKER);

  await gotoPublic(pageA, "actor-a", stack.actorA.baseUrl, sessionRoute, recorder);
  expect(new URL(pageA.url()).pathname).toBe(sessionRoute);
  if (includeProviderRound) {
    await expect(pageA.locator("body")).toContainText(ASSISTANT_MARKER, { timeout: 15_000 });
  }

  await gotoPublic(pageB, "actor-b", stack.actorB.baseUrl, sessionRoute, recorder);
  expect(new URL(pageB.url()).pathname).toBe(sessionRoute);

  const idOnly = await publicRequest(pageB, "actor-b", "GET", `/v1/sessions/${sessionId}`, undefined, undefined, recorder, recordPublic);
  expect(idOnly.status).toBe(404);

}

test.describe("two Access actors and Endpoint-owned session subjects", () => {
  test.describe.configure({ mode: "serial" });
  test.setTimeout(120_000);

  test("e2e_browser_two_actor_sessions_are_shared", async ({ browser }) => {
    test.skip(mode() === "replay", "isolation cassette retired; live recapture required");
    const cassettePath = ISOLATION_CASSETTE;
    const replay = mode() === "replay";
    const cassette = await readCassette(
      cassettePath,
      "e2e_browser_two_actor_session_isolation",
      ISOLATION_RECORDING_ID,
    );
    const stack = await createTwoActorStack({
      replayEndpointExchanges: replay ? cassette.endpointExchanges : undefined,
    });
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    const directEndpointRequestsA = watchDirectEndpointRequests(pageA, stack.endpointBaseUrl);
    const directEndpointRequestsB = watchDirectEndpointRequests(pageB, stack.endpointBaseUrl);
    const recorder = new ExchangeRecorder(
      [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET],
      replay ? cassette.exchanges : undefined,
      cassette.classification,
    );
    recorder.attachBrowserPage(pageA, "actor-a");
    recorder.attachBrowserPage(pageB, "actor-b");
    let armed = false;
    let sessionId = "";
    let actorBSessionId = "";
    try {
      const resource = await configureSharedResources(pageA, stack, recorder);
      stack.endpointTransport.arm([resource.endpointId, resource.profileId]);
      await gotoPublic(pageB, "actor-b", stack.actorB.baseUrl, "/", recorder);
      const bEndpoints = await publicRequest(pageB, "actor-b", "GET", "/v1/endpoints", undefined, undefined, recorder);
      expect(bEndpoints.status).toBe(200);
      expect(containsValue(bEndpoints.json, resource.endpointId)).toBe(true);
      const bProviders = await publicRequest(pageB, "actor-b", "GET", "/v1/providers", undefined, undefined, recorder);
      expect(bProviders.status).toBe(200);
      expect(containsValue(bProviders.json, PROVIDER_NAME)).toBe(true);
      const admission = await createActorASession(pageA, stack, resource, recorder);
      sessionId = admission.sessionId;
      armed = true;
      actorBSessionId = await assertCreateIdempotencyScope(pageA, pageB, stack, resource, admission, recorder);
      await assertSessionIsolation(pageA, pageB, stack, resource, sessionId, recorder, true, actorBSessionId);
      assertEndpointOwnershipTrace(stack, admission, actorBSessionId);
      expect(await serverStoresContainSessionMirrors(stack, [sessionId, actorBSessionId])).toBe(false);
      await expectNoBrowserCredentialState(pageA, ["Cf-Access-Jwt-Assertion", PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET]);
      await expectNoBrowserCredentialState(pageB, ["Cf-Access-Jwt-Assertion", PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET]);
      expect(directEndpointRequestsA).toHaveLength(0);
      expect(directEndpointRequestsB).toHaveLength(0);

      await stack.restartServerWithFreshStore();
      const reattached = await publicRequest(
        pageA,
        "actor-a",
        "POST",
        "/v1/endpoints",
        {
          label: ENDPOINT_LABEL,
          base_url: stack.endpointBaseUrl,
          control_auth: { kind: "bearer", secret: stack.endpointControlSecret },
        },
        "two-actor-endpoint-reattach",
        recorder,
      );
      expect(reattached.status).toBe(201);
      const afterRestartRead = await publicRequest(
        pageA,
        "actor-a",
        "GET",
        `/v1/endpoints/${resource.endpointId}/sessions/${sessionId}`,
        undefined,
        undefined,
        recorder,
      );
      expect(afterRestartRead.status).toBe(200);
      const afterRestartBRead = await publicRequest(
        pageB,
        "actor-b",
        "GET",
        `/v1/endpoints/${resource.endpointId}/sessions/${sessionId}`,
        undefined,
        undefined,
        recorder,
      );
      expect(afterRestartBRead.status).toBe(200);
      await expectNoSecrets(afterRestartBRead, [stack.providerSecret, stack.endpointControlSecret]);
      await stack.stopServer();
      expect(await serverStoresContainSessionMirrors(stack, [sessionId, actorBSessionId])).toBe(false);
      if (replay) {
        await recorder.assertReplayConsumed();
        await stack.endpointTransport.flush();
        stack.endpointTransport.assertReplayConsumed();
      }
    } catch (error) {
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      await recorder.flush();
      if (replay) {
        await recorder.assertReplayConsumed();
        await stack.endpointTransport.flush();
        stack.endpointTransport.assertReplayConsumed();
      }
      await stack.endpointTransport.flush();
      if (replay) {
        const first = recorder.classifyFirstFailure();
        if (first) {
          await writeFirstFailureCassette(
            quarantineCassette(cassette, first, recorder.values(), stack.endpointTransport.cassetteExchanges()),
          );
        }
      }
      throw error;
    } finally {
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      await stack.dispose();
    }
  });

  test("e2e_browser_provider_profiles_are_shared_deployment_resources", async ({ browser }) => {
    const cassettePath = PROFILE_CASSETTE;
    const replay = mode() === "replay";
    const cassette = await readCassette(
      cassettePath,
      "e2e_browser_provider_profiles_are_shared_deployment_resources",
      PROFILE_RECORDING_ID,
    );
    const stack = await createTwoActorStack({
      replayEndpointExchanges: replay ? cassette.endpointExchanges : undefined,
    });
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    const directEndpointRequestsA = watchDirectEndpointRequests(pageA, stack.endpointBaseUrl);
    const directEndpointRequestsB = watchDirectEndpointRequests(pageB, stack.endpointBaseUrl);
    const recorder = new ExchangeRecorder(
      [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET],
      replay ? cassette.exchanges : undefined,
      cassette.classification,
    );
    recorder.attachBrowserPage(pageA, "actor-a");
    recorder.attachBrowserPage(pageB, "actor-b");
    let armed = false;
    let sessionId = "";
    let actorBSessionId = "";
    try {
      const resource = await test.step("actor A configures shared deployment resources in the UI", () =>
        configureSharedResourcesViaUi(pageA, stack, recorder, ({ endpointId, profileId }) => {
          armed = true;
          recorder.arm([endpointId, profileId]);
        }),
      );
      armed = true;
      recorder.arm([resource.endpointId, resource.profileId]);
      await test.step("actor B observes the same deployment resources", () =>
        expectSharedProviderResource(pageB, stack, resource.endpointId, resource.profileId, recorder),
      );
      stack.endpointTransport.arm([resource.endpointId, resource.profileId]);
      const admission = await test.step("actor A creates an Endpoint-owned session", () =>
        createActorASession(pageA, stack, resource, recorder),
      );
      sessionId = admission.sessionId;
      armed = true;
      actorBSessionId = await test.step("session creation receipts are shared on one Endpoint", () =>
        assertCreateIdempotencyScope(pageA, pageB, stack, resource, admission, recorder),
      );
      await test.step("both Access actors share the Endpoint session namespace", () =>
        assertSessionIsolation(pageA, pageB, stack, resource, sessionId, recorder, true, actorBSessionId),
      );
      assertEndpointOwnershipTrace(stack, admission, actorBSessionId);
      expect(await serverStoresContainSessionMirrors(stack, [sessionId, actorBSessionId])).toBe(false);
      expect(directEndpointRequestsA).toHaveLength(0);
      expect(directEndpointRequestsB).toHaveLength(0);
      await expectNoBrowserCredentialState(pageA, ["Cf-Access-Jwt-Assertion", PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET]);
      await expectNoBrowserCredentialState(pageB, ["Cf-Access-Jwt-Assertion", PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET]);
      if (replay) {
        await recorder.assertReplayConsumed();
        await stack.endpointTransport.flush();
        stack.endpointTransport.assertReplayConsumed();
      }
    } catch (error) {
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      await recorder.flush();
      if (replay) {
        await recorder.assertReplayConsumed();
        await stack.endpointTransport.flush();
        stack.endpointTransport.assertReplayConsumed();
      }
      await stack.endpointTransport.flush();
      if (replay) {
        const first = recorder.classifyFirstFailure();
        if (first) {
          await writeFirstFailureCassette(
            quarantineCassette(cassette, first, recorder.values(), stack.endpointTransport.cassetteExchanges()),
          );
        }
      }
      throw error;
    } finally {
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      await stack.dispose();
    }
  });
});
