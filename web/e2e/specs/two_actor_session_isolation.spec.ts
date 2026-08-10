import { expect, test, type Browser, type Page } from "@playwright/test";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ASSISTANT_MARKER,
  ENDPOINT_CONTROL_SECRET,
  PROVIDER_MODEL,
  PROVIDER_NAME,
  PROVIDER_SECRET,
  cassetteExactResponseMatches,
  captureBody,
  createNormalizationSlots,
  redactForCassette,
  type AccessActor,
  type CassetteClassification,
  type CassetteTermination,
  type EndpointCassetteExchange,
  type EndpointObservation,
  type IncidentCassette,
  type NormalizationSlots,
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
const ISOLATION_ENDPOINT_REPLAY = join(CASSETTE_DIRECTORY, "session-isolation-endpoint-replay.v8.json");
const PROFILE_ENDPOINT_REPLAY = join(CASSETTE_DIRECTORY, "provider-profile-sharing-endpoint-replay.v8.json");
const ISOLATION_RECORDING_ID = "two-actor-session-isolation-first-404-complete-20260808-v2";
const PROFILE_RECORDING_ID = "two-actor-provider-profile-sharing-first-404-complete-20260808-v2";
const ISOLATION_ENDPOINT_REPLAY_ID = "two-actor-session-isolation-endpoint-replay-20260809-v8";
const PROFILE_ENDPOINT_REPLAY_ID = "two-actor-provider-profile-sharing-endpoint-replay-20260809-v8";
const RETIRED_ENDPOINT_REPLAY_IDS = new Set([
  "two-actor-session-isolation-endpoint-replay-20260809-v8",
  "two-actor-provider-profile-sharing-endpoint-replay-20260809-v8",
]);
const RETIRED_ENDPOINT_REPLAY_FILENAMES = new Set([
  "session-isolation-endpoint-replay.v8.json",
  "provider-profile-sharing-endpoint-replay.v8.json",
]);
const ISOLATION_E2E = "e2e_browser_two_actor_session_isolation";
const PROFILE_E2E = "e2e_browser_provider_profiles_are_shared_deployment_resources";
const ISOLATION_REPLAY_E2E = "e2e_browser_two_actor_session_isolation_replays_complete_endpoint_transcript";
const PROFILE_REPLAY_E2E = "e2e_browser_provider_profiles_shared_deployment_replays_complete_endpoint_transcript";
const LATER_RELATION = "later_test_reproduction_of_gap";
const SSE_LATER_CLASSIFICATION = "TWO_ACTOR_ASSISTANT_STREAM_MARKER_NOT_OBSERVED";
const UI_LATER_CLASSIFICATION = "TWO_ACTOR_UI_ASSETS_NOT_SERVED";
const CAPTURE_SSE_LATER_GAP = process.env.ZODE_CAPTURE_TWO_ACTOR_SSE_LATER_GAP === "1";
const CAPTURE_UI_LATER_GAP = process.env.ZODE_CAPTURE_TWO_ACTOR_UI_LATER_GAP === "1";
const CAPTURE_ENDPOINT_REPLAY = process.env.ZODE_CAPTURE_TWO_ACTOR_ENDPOINT_REPLAY === "1";
const PROMOTE_ENDPOINT_REPLAY = process.env.ZODE_PROMOTE_TWO_ACTOR_ENDPOINT_REPLAY === "1";
const SSE_FIRST_GAP =
  "target/test-recordings/quarantine/local-evidence-gaps/two-actor-sse-terminal-wait-first-gap.v1.json";
const SSE_FIRST_GAP_SHA256 = "dca8187aa95581c10e0e0c848aece50bf3d10b7c89b4b9f39f795ef728f4568e";
const UI_FIRST_GAP =
  "target/test-recordings/quarantine/local-evidence-gaps/two-actor-ui-assets-mode-first-gap.v1.json";
const UI_FIRST_GAP_SHA256 = "239cd0b931fcb43ac8bb0068088d98a0666cbbcc626ce4ff582ae2d93deeca32";
const UI_SAFE_NOT_FOUND_CLASSIFICATION = "TWO_ACTOR_SAFE_NOT_FOUND_NOT_VISIBLE";
const UI_SAFE_NOT_FOUND_FIRST_GAP =
  "target/test-recordings/quarantine/local-evidence-gaps/two-actor-ui-safe-not-found-first-gap.v1.json";
const UI_SAFE_NOT_FOUND_FIRST_GAP_SHA256 = "f8ca192f9d38a78c2c030162a6f216e269315b6f1b198fc69c05d5c3199136fa";
const UI_SHARED_TRUST_CLASSIFICATION = "TWO_ACTOR_SHARED_TRUST_BOUNDARY_NOT_VISIBLE";
const UI_SHARED_TRUST_FIRST_GAP =
  "target/test-recordings/quarantine/local-evidence-gaps/two-actor-ui-shared-trust-boundary-first-gap.v1.json";
const UI_SHARED_TRUST_FIRST_GAP_SHA256 = "e6a5138a2862dada84f9276e9ede8033015954e8f747334da742a9cc4b3bf7ec";
const ASSISTANT_STREAM_TIMEOUT_MS = 20_000;
const REPOSITORY_ROOT = resolve(CASSETTE_DIRECTORY, "../../../..");

type AssistantStreamOutcome =
  | "marker_observed"
  | "stream_ended"
  | "observation_timeout"
  | "stream_error"
  | "response_unavailable";

class BrowserStreamObservationFailure extends Error {
  readonly classification = SSE_LATER_CLASSIFICATION;

  constructor(readonly observation: {
    actor: AccessActor;
    method: "GET";
    path: string;
    status: number;
    outcome: AssistantStreamOutcome;
    observedBytes: number;
  }) {
    super(
      `relation=${LATER_RELATION}; the bounded public SSE observation did not contain the expected assistant marker`,
    );
    this.name = "BrowserStreamObservationFailure";
  }
}

class EndpointReplayCaptureIdentityFailure extends Error {
  readonly classification = "TWO_ACTOR_ENDPOINT_REPLAY_IDENTITY_RETIRED";

  constructor(recordingId: string) {
    super(
      `two-actor Endpoint replay capture refused retired recording identity ${recordingId}; `
        + "configure a new recording_id and destination before any replacement capture",
    );
    this.name = "EndpointReplayCaptureIdentityFailure";
  }
}

function assertEndpointReplayCaptureIdentity(recordingId: string, destination: string): void {
  if (
    RETIRED_ENDPOINT_REPLAY_IDS.has(recordingId)
    || RETIRED_ENDPOINT_REPLAY_FILENAMES.has(basename(destination))
  ) {
    throw new EndpointReplayCaptureIdentityFailure(recordingId);
  }
}

class BrowserUiObservationFailure extends Error {
  constructor(
    readonly owningE2e: typeof ISOLATION_E2E | typeof PROFILE_E2E,
    readonly classification: string,
    readonly originalGap: string,
    readonly originalGapSha256: string,
    message: string,
    readonly observation: {
      actor: AccessActor;
      method: "GET";
      path: string;
      status: number;
      outcome:
        | "visible_marker_missing"
        | "safe_not_found_not_visible"
        | "shared_trust_boundary_not_visible";
      observedBytes: number;
    },
  ) {
    super(`relation=${LATER_RELATION}; ${message}`);
    this.name = "BrowserUiObservationFailure";
  }
}

type RetainableBrowserObservationFailure =
  | BrowserStreamObservationFailure
  | BrowserUiObservationFailure;

type EndpointReplayCassette = {
  schema: "zode.web-two-actor-endpoint-replay.v2";
  version: 2;
  recording_id: string;
  owner: typeof ISOLATION_E2E | typeof PROFILE_E2E;
  boundary: "server_endpoint_http";
  relation: typeof LATER_RELATION;
  normalization: "capture_wide_ordered_identity_slots.v1";
  purpose: string;
  source_incident: {
    recording_id: string;
    whole_digest: string;
  };
  endpoint_exchanges: EndpointCassetteExchange[];
  source_digest: string;
  whole_digest: string;
};

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

function isExpectedActorIsolationNotFound(actor: AccessActor, method: string, path: string): boolean {
  if (actor !== "actor-b") return false;
  if (method === "POST" && /^\/v1\/endpoints\/[^/]+\/sessions\/[^/]+\/messages(?:\?.*)?$/.test(path)) return true;
  if (method !== "GET") return false;
  return (
    /^\/v1\/endpoints\/[^/]+\/sessions\/[^/]+(?:\/events)?(?:\?.*)?$/.test(path)
    || /^\/v1\/sessions\/[^/]+(?:\?.*)?$/.test(path)
    || /^\/endpoints\/[^/]+\/sessions\/[^/]+(?:\?.*)?$/.test(path)
  );
}

function browserSemanticHeaders(
  headers: Record<string, string>,
  dynamicIds: string[],
  secrets: string[],
  slots: NormalizationSlots,
): Record<string, string> {
  const allowed = new Set(["accept", "cache-control", "content-type", "idempotency-key", "last-event-id", "location"]);
  const result: Record<string, string> = {};
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (!allowed.has(name)) continue;
    result[name] = redactForCassette(rawValue, secrets, dynamicIds, slots);
  }
  return result;
}

function browserPath(path: string, dynamicIds: string[], slots: NormalizationSlots): string {
  const url = new URL(path, "http://two-actor.invalid");
  return normalizePath(`${url.pathname}${url.search}`, dynamicIds, slots);
}

function isRelevantBrowserPath(path: string): boolean {
  const pathname = new URL(path, "http://two-actor.invalid").pathname;
  return pathname === "/"
    || pathname === "/providers"
    || pathname === "/endpoints"
    || pathname === "/sessions"
    || (CAPTURE_UI_LATER_GAP && /^\/endpoints\/[^/]+\/sessions\/[^/]+$/.test(pathname))
    || pathname.startsWith("/v1/");
}

class ExchangeRecorder {
  private readonly observed: RecordedExchange[] = [];
  private dynamicIds: string[] = [];
  private readonly normalizationSlots = createNormalizationSlots();
  private firstFailure: { exchange: RecordedExchange; classification: CassetteClassification["kind"] } | undefined;
  private readonly browserRequests = new Map<unknown, RecordedExchange>();
  private readonly pendingCaptures: Promise<void>[] = [];
  private readonly attachedPages = new WeakSet<Page>();

  constructor(
    private readonly secrets: string[],
    private readonly classificationContract: CassetteClassification,
    private readonly positiveCatalogBarrierContract: RecordedExchange | undefined,
  ) {}

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
      this.normalizationSlots,
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
      const requestBody = captureBody(
        request.postData() ?? undefined,
        this.secrets,
        this.dynamicIds,
        this.normalizationSlots,
      );
      const item: RecordedExchange = {
        sequence: this.observed.length,
        actor,
        method: request.method(),
        path: browserPath(`${url.pathname}${url.search}`, this.dynamicIds, this.normalizationSlots),
        request: {
          semanticHeaders: browserSemanticHeaders(
            request.headers(),
            this.dynamicIds,
            this.secrets,
            this.normalizationSlots,
          ),
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
    });
    page.on("response", (response) => {
      const item = this.browserRequests.get(response.request());
      if (!item) return;
      item.response.status = response.status();
      item.response.semanticHeaders = browserSemanticHeaders(
        response.headers(),
        this.dynamicIds,
        this.secrets,
        this.normalizationSlots,
      );
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

  private completeItem(
    item: RecordedExchange,
    rawBody: string,
    status: number,
    headers: Record<string, string>,
    completed: boolean,
    termination: CassetteTermination = completed ? "complete" : "disconnect",
  ): void {
    if (item.response.completed || (item.response.status !== 0 && item.response.bodyHex !== "")) return;
    const responseBody = captureBody(
      rawBody,
      this.secrets,
      this.dynamicIds,
      this.normalizationSlots,
    );
    item.response.status = status;
    item.response.semanticHeaders = browserSemanticHeaders(
      headers,
      this.dynamicIds,
      this.secrets,
      this.normalizationSlots,
    );
    item.response.bodyHex = responseBody.bodyHex;
    item.response.bodySha256 = responseBody.bodySha256;
    item.response.canonicalJson = responseBody.canonicalJson;
    item.response.chunks = rawBody.length === 0
      ? []
      : [{ sequence: 0, bodyHex: responseBody.bodyHex, bodySha256: responseBody.bodySha256, offsetMs: 0 }];
    item.response.termination = termination;
    item.response.responseCode = findSafeResponseCode(responseBody.canonicalJson);
    item.response.completed = completed;
  }

  private positiveCatalogBarrierMismatch(actual: RecordedExchange): string | null {
    const barrier = this.classificationContract.positive_catalog_barrier;
    const expected = this.positiveCatalogBarrierContract;
    if (!barrier.observed || !expected || barrier.exchange_sequence === null) {
      return "positive catalog barrier contract is unavailable";
    }
    if (actual.sequence !== barrier.exchange_sequence) return "positive catalog barrier sequence changed";
    if (actual.actor !== expected.actor) return "positive catalog barrier actor changed";
    if (actual.method !== expected.method) return "positive catalog barrier method changed";
    if (actual.path !== expected.path) return "positive catalog barrier path changed";
    if (actual.response.status !== barrier.expected_status) {
      return `positive catalog barrier status ${actual.response.status} != ${barrier.expected_status}`;
    }
    if (actual.response.completed !== true || actual.response.termination !== "complete") {
      return "positive catalog barrier did not terminate completely";
    }
    const expectedSchema = expected.response.canonicalJson?.schema;
    if (
      typeof expectedSchema !== "string"
      || !actual.response.canonicalJson
      || typeof actual.response.canonicalJson !== "object"
      || actual.response.canonicalJson.schema !== expectedSchema
    ) {
      return "positive catalog barrier schema changed";
    }
    return null;
  }

  classifyFirstFailure(): { exchange: RecordedExchange; classification: CassetteClassification["kind"] } | undefined {
    if (this.firstFailure) return this.firstFailure;
    const candidate = [...this.observed]
      .filter((item) => item.response.status >= 400 && !isExpectedActorIsolationNotFound(item.actor, item.method, item.path))
      .sort((left, right) => left.sequence - right.sequence)[0];
    if (!candidate) return undefined;
    if (!cassetteExactResponseMatches(candidate.response, this.classificationContract.exact_response)) {
      throw new Error("first failure response no longer matches the cassette exact-response contract");
    }
    const barrier = this.classificationContract.positive_catalog_barrier;
    if (barrier.observed) {
      const barrierExchange = barrier.exchange_sequence === null
        ? undefined
        : this.observed[barrier.exchange_sequence];
      const mismatch = barrierExchange
        ? this.positiveCatalogBarrierMismatch(barrierExchange)
        : "positive catalog barrier was not observed";
      if (mismatch) {
        throw new Error(`positive catalog barrier no longer matches the public contract: ${mismatch}`);
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
    const request = captureBody(
      requestBody === undefined ? undefined : JSON.stringify(requestBody),
      this.secrets,
      this.dynamicIds,
      this.normalizationSlots,
    );
    const normalizedPath = browserPath(path, this.dynamicIds, this.normalizationSlots);
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

  isBrowserPage(page: Page): boolean {
    return this.attachedPages.has(page);
  }

  values(): RecordedExchange[] {
    return [...this.observed];
  }

  latestExchange(actor: AccessActor, method: string, path: string): RecordedExchange | undefined {
    const normalizedPath = browserPath(path, this.dynamicIds, this.normalizationSlots);
    return [...this.observed].reverse().find((item) =>
      item.actor === actor && item.method === method && item.path === normalizedPath,
    );
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

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writePrivateDurableJson(path: string, value: unknown): Promise<void> {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(path, 0o600);
  await syncDirectory(dirname(path));
}

const MAX_ENDPOINT_REPLAY_EXCHANGES = 128;
const MAX_ENDPOINT_REPLAY_BODY_BYTES = 8 * 1024 * 1024;
const MAX_ENDPOINT_REPLAY_TOTAL_BYTES = 24 * 1024 * 1024;
const MAX_ENDPOINT_REPLAY_FILE_BYTES = 64 * 1024 * 1024;
const ENDPOINT_REPLAY_HEADERS = new Set([
  "accept",
  "cache-control",
  "content-type",
  "idempotency-key",
  "last-event-id",
  "location",
]);

function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeCanonicalHex(value: unknown, label: string): Buffer {
  if (
    typeof value !== "string"
    || value.length > MAX_ENDPOINT_REPLAY_BODY_BYTES * 2
    || !/^(?:[0-9a-f]{2})*$/.test(value)
  ) {
    throw new Error(`two-actor Endpoint replay ${label} is not canonical bounded hex`);
  }
  const decoded = Buffer.from(value, "hex");
  if (decoded.toString("hex") !== value) {
    throw new Error(`two-actor Endpoint replay ${label} changed while decoding`);
  }
  return decoded;
}

function validateSemanticHeaderMap(value: unknown, label: string): asserts value is Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`two-actor Endpoint replay ${label} headers are invalid`);
  }
  for (const [name, headerValue] of Object.entries(value)) {
    if (
      name !== name.toLowerCase()
      || !ENDPOINT_REPLAY_HEADERS.has(name)
      || typeof headerValue !== "string"
      || Buffer.byteLength(headerValue) > 8 * 1024
    ) {
      throw new Error(`two-actor Endpoint replay ${label} header is invalid`);
    }
  }
}

function replayForbiddenMarkers(): string[] {
  const markerValues = [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET];
  const encodedMarkers = markerValues.flatMap((marker) => [
    marker,
    Buffer.from(marker).toString("base64"),
    Buffer.from(marker).toString("base64url"),
    Buffer.from(marker).toString("hex"),
    encodeURIComponent(marker),
  ]);
  return [...encodedMarkers, "cf-access-jwt-assertion", "authorization", "cookie"];
}

function assertReplayTextSecretSafe(value: string, label: string): void {
  const lowered = value.toLowerCase();
  for (const forbidden of replayForbiddenMarkers()) {
    if (lowered.includes(forbidden.toLowerCase())) {
      throw new Error(`two-actor Endpoint replay ${label} contains forbidden credential material`);
    }
  }
}

function assertReplaySecretSafe(metadata: unknown, decodedBodies: Buffer[]): void {
  assertReplayTextSecretSafe(JSON.stringify(metadata), "cassette");
  for (const body of decodedBodies) {
    assertReplayTextSecretSafe(body.toString("utf8"), "decoded bytes");
  }
}

function hasExactKeys(value: unknown, expectedKeys: readonly string[]): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

const ENDPOINT_REPLAY_TOP_LEVEL_KEYS = [
  "schema",
  "version",
  "recording_id",
  "owner",
  "boundary",
  "relation",
  "normalization",
  "purpose",
  "source_incident",
  "endpoint_exchanges",
  "source_digest",
  "whole_digest",
] as const;
const ENDPOINT_REPLAY_EXCHANGE_KEYS = [
  "sequence",
  "method",
  "path",
  "subjectSlot",
  "controllerAuth",
  "idempotencyKey",
  "requestHeaders",
  "requestBodyHex",
  "requestBodyDigest",
  "status",
  "responseHeaders",
  "responseBodyHex",
  "responseBodyDigest",
  "responseChunks",
  "termination",
  "responseCode",
  "completed",
] as const;

function assertCanonicalReplayBytes(bytes: Buffer, replay: EndpointReplayCassette): void {
  const canonical = Buffer.from(`${JSON.stringify(replay, null, 2)}\n`, "utf8");
  if (!bytes.equals(canonical)) {
    throw new Error("two-actor Endpoint replay cassette is not canonical JSON or contains duplicate keys");
  }
}

async function readExactlyAt(
  handle: Awaited<ReturnType<typeof open>>,
  size: number,
): Promise<Buffer> {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await handle.read(bytes, offset, size - offset, offset);
    if (result.bytesRead === 0) {
      throw new Error("two-actor Endpoint replay source ended during bounded read");
    }
    offset += result.bytesRead;
  }
  return bytes;
}

async function readStableBoundedBytes(
  handle: Awaited<ReturnType<typeof open>>,
  expectedSize: number,
): Promise<Buffer> {
  if (!Number.isSafeInteger(expectedSize) || expectedSize <= 0 || expectedSize > MAX_ENDPOINT_REPLAY_FILE_BYTES) {
    throw new Error("two-actor Endpoint replay source exceeds the file bound");
  }
  const first = await readExactlyAt(handle, expectedSize);
  const second = await readExactlyAt(handle, expectedSize);
  const after = await handle.stat();
  if (after.size !== expectedSize || !first.equals(second)) {
    throw new Error("two-actor Endpoint replay source changed during bounded read");
  }
  assertReplayTextSecretSafe(first.toString("utf8"), "raw bytes");
  return first;
}

function validateEndpointReplayCassette(
  replay: EndpointReplayCassette,
  owner: typeof ISOLATION_E2E | typeof PROFILE_E2E,
  recordingId: string,
  incident: IncidentCassette,
): void {
  if (
    !hasExactKeys(replay, ENDPOINT_REPLAY_TOP_LEVEL_KEYS)
    || replay.schema !== "zode.web-two-actor-endpoint-replay.v2"
    || replay.version !== 2
    || replay.recording_id !== recordingId
    || replay.owner !== owner
    || replay.boundary !== "server_endpoint_http"
    || replay.relation !== LATER_RELATION
    || replay.normalization !== "capture_wide_ordered_identity_slots.v1"
    || typeof replay.purpose !== "string"
    || replay.purpose.length === 0
    || replay.purpose.length > 4_096
    || !hasExactKeys(replay.source_incident, ["recording_id", "whole_digest"])
    || replay.source_incident?.recording_id !== incident.recording_id
    || replay.source_incident?.whole_digest !== incident.whole_digest
    || !Array.isArray(replay.endpoint_exchanges)
    || replay.endpoint_exchanges.length === 0
    || replay.endpoint_exchanges.length > MAX_ENDPOINT_REPLAY_EXCHANGES
    || replay.source_digest !== jsonDigest(replay.endpoint_exchanges)
    || !/^sha256:[0-9a-f]{64}$/.test(replay.whole_digest)
  ) {
    throw new Error("two-actor Endpoint replay cassette metadata is invalid");
  }
  const { whole_digest: wholeDigest, ...unsigned } = replay;
  if (wholeDigest !== jsonDigest(unsigned)) {
    throw new Error("two-actor Endpoint replay cassette integrity changed");
  }

  const decodedBodies: Buffer[] = [];
  let totalBytes = 0;
  for (const [index, exchange] of replay.endpoint_exchanges.entries()) {
    if (
      !hasExactKeys(exchange, ENDPOINT_REPLAY_EXCHANGE_KEYS)
      || exchange.sequence !== index
      || typeof exchange.method !== "string"
      || !/^[A-Z]{3,16}$/.test(exchange.method)
      || typeof exchange.path !== "string"
      || !exchange.path.startsWith("/")
      || Buffer.byteLength(exchange.path) > 16 * 1024
      || typeof exchange.subjectSlot !== "string"
      || !/^(?:none|subject-[1-9][0-9]*)$/.test(exchange.subjectSlot)
      || !["shared", "unexpected"].includes(exchange.controllerAuth)
      || (exchange.idempotencyKey !== null
        && (typeof exchange.idempotencyKey !== "string" || Buffer.byteLength(exchange.idempotencyKey) > 8 * 1024))
      || !Number.isInteger(exchange.status)
      || exchange.status < 100
      || exchange.status > 599
      || !["complete", "disconnect", "error"].includes(exchange.termination)
      || exchange.completed !== (exchange.termination === "complete")
      || (exchange.responseCode !== null
        && (typeof exchange.responseCode !== "string" || Buffer.byteLength(exchange.responseCode) > 8 * 1024))
      || !Array.isArray(exchange.responseChunks)
      || exchange.responseChunks.length > 4_096
    ) {
      throw new Error(`two-actor Endpoint replay exchange ${index} metadata is invalid`);
    }
    validateSemanticHeaderMap(exchange.requestHeaders, `exchange ${index} request`);
    validateSemanticHeaderMap(exchange.responseHeaders, `exchange ${index} response`);

    const requestBody = decodeCanonicalHex(exchange.requestBodyHex, `exchange ${index} request body`);
    if (!/^[0-9a-f]{64}$/.test(exchange.requestBodyDigest) || sha256Hex(requestBody) !== exchange.requestBodyDigest) {
      throw new Error(`two-actor Endpoint replay exchange ${index} request digest changed`);
    }
    decodedBodies.push(requestBody);
    totalBytes += requestBody.byteLength;

    if ((exchange.responseBodyHex === null) !== (exchange.responseBodyDigest === null)) {
      throw new Error(`two-actor Endpoint replay exchange ${index} response body metadata is incomplete`);
    }
    const responseBody = exchange.responseBodyHex === null
      ? Buffer.alloc(0)
      : decodeCanonicalHex(exchange.responseBodyHex, `exchange ${index} response body`);
    if (
      exchange.responseBodyDigest !== null
      && (!/^[0-9a-f]{64}$/.test(exchange.responseBodyDigest) || sha256Hex(responseBody) !== exchange.responseBodyDigest)
    ) {
      throw new Error(`two-actor Endpoint replay exchange ${index} response digest changed`);
    }

    const chunkBodies = exchange.responseChunks.map((chunk, chunkIndex) => {
      if (
        !hasExactKeys(chunk, ["sequence", "bodyHex", "bodySha256", "offsetMs"])
        || chunk.sequence !== chunkIndex
        || typeof chunk.offsetMs !== "number"
        || !Number.isFinite(chunk.offsetMs)
        || chunk.offsetMs < 0
      ) {
        throw new Error(`two-actor Endpoint replay exchange ${index} chunk ${chunkIndex} metadata is invalid`);
      }
      const body = decodeCanonicalHex(chunk.bodyHex, `exchange ${index} chunk ${chunkIndex}`);
      if (chunk.bodySha256 !== `sha256:${sha256Hex(body)}`) {
        throw new Error(`two-actor Endpoint replay exchange ${index} chunk ${chunkIndex} digest changed`);
      }
      decodedBodies.push(body);
      totalBytes += body.byteLength;
      return body;
    });
    const concatenatedChunks = Buffer.concat(chunkBodies);
    if (!concatenatedChunks.equals(responseBody)) {
      throw new Error(`two-actor Endpoint replay exchange ${index} chunks do not equal the complete response body`);
    }
    if (exchange.responseBodyHex === null && exchange.responseChunks.length !== 0) {
      throw new Error(`two-actor Endpoint replay exchange ${index} has chunks without a response body`);
    }
    decodedBodies.push(responseBody);
    totalBytes += responseBody.byteLength;
    if (totalBytes > MAX_ENDPOINT_REPLAY_TOTAL_BYTES) {
      throw new Error("two-actor Endpoint replay cassette exceeds the decoded byte bound");
    }
  }
  assertReplaySecretSafe(replay, decodedBodies);
}

function sameFileIdentity(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function readReplayBytesWithoutLinks(path: string, allowedMode: number): Promise<Buffer> {
  const before = await lstat(path);
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || (before.mode & 0o777) !== allowedMode
    || before.size <= 0
    || before.size > MAX_ENDPOINT_REPLAY_FILE_BYTES
  ) {
    throw new Error("two-actor Endpoint replay source is not a regular file with the required mode");
  }
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFileIdentity(before, opened) || opened.size !== before.size) {
      throw new Error("two-actor Endpoint replay source changed during open");
    }
    return await readStableBoundedBytes(handle, opened.size);
  } finally {
    await handle.close();
  }
}

function parseEndpointReplayCassette(
  bytes: Buffer,
  owner: typeof ISOLATION_E2E | typeof PROFILE_E2E,
  recordingId: string,
  incident: IncidentCassette,
): EndpointReplayCassette {
  if (bytes.byteLength <= 0 || bytes.byteLength > MAX_ENDPOINT_REPLAY_FILE_BYTES) {
    throw new Error("two-actor Endpoint replay cassette exceeds the file bound");
  }
  assertReplayTextSecretSafe(bytes.toString("utf8"), "raw bytes");
  const replay = JSON.parse(bytes.toString("utf8")) as EndpointReplayCassette;
  validateEndpointReplayCassette(replay, owner, recordingId, incident);
  assertCanonicalReplayBytes(bytes, replay);
  return replay;
}

async function readEndpointReplayCassette(
  path: string,
  owner: typeof ISOLATION_E2E | typeof PROFILE_E2E,
  recordingId: string,
  incident: IncidentCassette,
): Promise<EndpointReplayCassette> {
  const before = await lstat(path);
  const checkoutMode = before.mode & 0o777;
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || ![0o444, 0o644].includes(checkoutMode)
    || before.size <= 0
    || before.size > MAX_ENDPOINT_REPLAY_FILE_BYTES
  ) {
    throw new Error("two-actor Endpoint replay cassette is not a checkout-safe regular file");
  }
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let normalized = false;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFileIdentity(before, opened) || opened.size !== before.size) {
      throw new Error("two-actor Endpoint replay cassette changed during open");
    }
    const replay = parseEndpointReplayCassette(
      await readStableBoundedBytes(handle, opened.size),
      owner,
      recordingId,
      incident,
    );
    if (checkoutMode === 0o644) {
      await handle.chmod(0o444);
      await handle.sync();
      normalized = true;
    }
    return replay;
  } finally {
    await handle.close();
    if (normalized) await syncDirectory(dirname(path));
    const after = await lstat(path);
    if (!sameFileIdentity(before, after) || !after.isFile() || (after.mode & 0o777) !== 0o444) {
      throw new Error("two-actor Endpoint replay cassette is not immutable after validation");
    }
  }
}

async function pathMatchesFileIdentity(
  path: string,
  identity: Awaited<ReturnType<typeof lstat>>,
): Promise<boolean> {
  try {
    const current = await lstat(path);
    return current.isFile() && !current.isSymbolicLink() && sameFileIdentity(current, identity);
  } catch {
    return false;
  }
}

async function promoteEndpointReplayCandidate(
  candidatePath: string,
  destinationPath: string,
  owner: typeof ISOLATION_E2E | typeof PROFILE_E2E,
  recordingId: string,
  incident: IncidentCassette,
): Promise<void> {
  const bytes = await readReplayBytesWithoutLinks(candidatePath, 0o600);
  parseEndpointReplayCassette(bytes, owner, recordingId, incident);
  const destinationDirectory = dirname(destinationPath);
  const destinationDirectoryMetadata = await lstat(destinationDirectory);
  if (
    !destinationDirectoryMetadata.isDirectory()
    || destinationDirectoryMetadata.isSymbolicLink()
    || await realpath(destinationDirectory) !== resolve(destinationDirectory)
  ) {
    throw new Error("two-actor Endpoint replay destination directory is not a confined regular directory");
  }
  const temporaryPath = join(
    destinationDirectory,
    `.${basename(destinationPath)}.tmp-${process.pid}-${randomUUID()}`,
  );
  let temporaryCreated = false;
  let destinationLinked = false;
  let createdIdentity: Awaited<ReturnType<typeof lstat>> | undefined;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporaryPath, "wx+", 0o600);
    temporaryCreated = true;
    createdIdentity = await handle.stat();
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.chmod(0o444);
    await handle.sync();
    const written = await readStableBoundedBytes(handle, bytes.byteLength);
    if (!written.equals(bytes)) {
      throw new Error("two-actor Endpoint replay promotion changed the validated bytes");
    }
    parseEndpointReplayCassette(written, owner, recordingId, incident);
    await link(temporaryPath, destinationPath);
    destinationLinked = true;
    const linked = await lstat(destinationPath);
    if (
      !createdIdentity
      || !sameFileIdentity(createdIdentity, linked)
      || linked.nlink !== 2
      || (linked.mode & 0o777) !== 0o444
    ) {
      throw new Error("two-actor Endpoint replay promotion did not create the validated inode");
    }
    if (!await pathMatchesFileIdentity(temporaryPath, createdIdentity)) {
      throw new Error("two-actor Endpoint replay temporary inode changed before publication");
    }
    await unlink(temporaryPath);
    temporaryCreated = false;
    await syncDirectory(destinationDirectory);
    const published = await lstat(destinationPath);
    if (
      !sameFileIdentity(createdIdentity, published)
      || published.nlink !== 1
      || (published.mode & 0o777) !== 0o444
    ) {
      throw new Error("two-actor Endpoint replay published inode changed before completion");
    }
    await handle.close();
    handle = undefined;
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (destinationLinked && createdIdentity && await pathMatchesFileIdentity(destinationPath, createdIdentity)) {
      await unlink(destinationPath).catch(() => undefined);
    }
    if (temporaryCreated && createdIdentity && await pathMatchesFileIdentity(temporaryPath, createdIdentity)) {
      await unlink(temporaryPath).catch(() => undefined);
    }
    await syncDirectory(destinationDirectory).catch(() => undefined);
    throw error;
  }
}

async function retainEndpointReplayCandidate(
  owner: typeof ISOLATION_E2E | typeof PROFILE_E2E,
  recordingId: string,
  incident: IncidentCassette,
  endpointExchanges: EndpointCassetteExchange[],
): Promise<string> {
  if (!incident.whole_digest) throw new Error("the source incident cassette has no integrity digest");
  const unsigned = {
    schema: "zode.web-two-actor-endpoint-replay.v2" as const,
    version: 2 as const,
    recording_id: recordingId,
    owner,
    boundary: "server_endpoint_http" as const,
    relation: LATER_RELATION,
    normalization: "capture_wide_ordered_identity_slots.v1" as const,
    purpose:
      "Replay the complete secret-safe Server-to-Endpoint transcript through the same real browser and real processes while retaining the original incident cassette as first-occurrence provenance.",
    source_incident: {
      recording_id: incident.recording_id,
      whole_digest: incident.whole_digest,
    },
    endpoint_exchanges: endpointExchanges,
    source_digest: jsonDigest(endpointExchanges),
  };
  const replay: EndpointReplayCassette = {
    ...unsigned,
    whole_digest: jsonDigest(unsigned),
  };
  validateEndpointReplayCassette(replay, owner, recordingId, incident);
  const quarantineRoot = resolve(
    process.env.ZODE_TEST_RECORDING_ROOT
      ?? join(REPOSITORY_ROOT, "target/test-recordings/quarantine"),
  );
  await mkdir(quarantineRoot, { recursive: true, mode: 0o700 });
  const runRoot = await mkdtemp(join(quarantineRoot, "two-actor-endpoint-replay-"));
  await chmod(runRoot, 0o700);
  await syncDirectory(quarantineRoot);
  const path = join(runRoot, `${recordingId}.json`);
  await writePrivateDurableJson(path, replay);
  return path;
}

async function retainLaterBrowserObservation(
  failure: RetainableBrowserObservationFailure,
  exchange: RecordedExchange,
): Promise<string> {
  const streamFailure = failure instanceof BrowserStreamObservationFailure;
  const originalGap = streamFailure ? SSE_FIRST_GAP : failure.originalGap;
  const expectedGapDigest = streamFailure ? SSE_FIRST_GAP_SHA256 : failure.originalGapSha256;
  const gapPath = resolve(REPOSITORY_ROOT, originalGap);
  const gapBytes = await readFile(gapPath);
  const gapDigest = createHash("sha256").update(gapBytes).digest("hex");
  if (gapDigest !== expectedGapDigest) {
    throw new Error("the original two-actor browser evidence gap digest changed");
  }
  const safetyText = JSON.stringify(exchange).toLowerCase();
  for (const forbidden of [
    PROVIDER_SECRET,
    ENDPOINT_CONTROL_SECRET,
    "cf-access-jwt-assertion",
    "authorization",
    "cookie",
  ]) {
    if (safetyText.includes(forbidden.toLowerCase())) {
      throw new Error("the later two-actor browser observation contains forbidden credential material");
    }
  }
  const quarantineRoot = resolve(
    process.env.ZODE_TEST_RECORDING_ROOT
      ?? join(REPOSITORY_ROOT, "target/test-recordings/quarantine"),
  );
  await mkdir(quarantineRoot, { recursive: true, mode: 0o700 });
  const runRoot = await mkdtemp(join(quarantineRoot, streamFailure ? "two-actor-sse-later-" : "two-actor-ui-later-"));
  await chmod(runRoot, 0o700);
  await syncDirectory(quarantineRoot);
  const unsigned = {
    schema: "zode.evidence-gap-later-reproduction.v1",
    version: 1,
    owning_e2e: streamFailure ? ISOLATION_E2E : failure.owningE2e,
    recording_id: basename(runRoot),
    relation: LATER_RELATION,
    original_evidence_gap: originalGap,
    original_evidence_gap_sha256: expectedGapDigest,
    classification: failure.classification,
    first_observed: {
      actor: failure.observation.actor,
      method: failure.observation.method,
      path: exchange.path,
      status: failure.observation.status,
      observation_outcome: failure.observation.outcome,
      observed_bytes: failure.observation.observedBytes,
      expected_marker_observed: false,
    },
    secret_safe_exchange_retained: true,
    raw_exchange_retained: false,
    public_sse_same_entry_replay_required: streamFailure,
    browser_behavior_replay_required: !streamFailure,
    do_not_relabel_as_first: true,
    source_digest: jsonDigest(exchange),
    exchange,
  };
  const metadata = {
    ...unsigned,
    integrity_sha256: jsonDigest(unsigned),
  };
  const path = join(runRoot, "observation.v1.json");
  await writePrivateDurableJson(path, metadata);
  return path;
}

async function retainRequestedBrowserObservation(
  error: unknown,
  recorder: ExchangeRecorder,
): Promise<void> {
  const failure =
    error instanceof BrowserStreamObservationFailure && CAPTURE_SSE_LATER_GAP
    || error instanceof BrowserUiObservationFailure && CAPTURE_UI_LATER_GAP
      ? error
      : undefined;
  if (!failure) return;
  const observed = recorder.latestExchange(
    failure.observation.actor,
    failure.observation.method,
    failure.observation.path,
  );
  if (!observed) {
    throw new AggregateError(
      [error, new Error("the browser failure had no secret-safe public exchange")],
      "two-actor later reproduction could not retain its public browser observation",
    );
  }
  try {
    const path = await retainLaterBrowserObservation(failure, observed);
    process.stderr.write(`ZODE_E2E_TWO_ACTOR_LATER_OBSERVATION ${path}\n`);
  } catch (captureError) {
    throw new AggregateError(
      [error, captureError],
      "two-actor later reproduction failed together with its durable browser evidence capture",
    );
  }
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

async function gotoPublic(page: Page, actor: AccessActor, baseUrl: string, path: string, recorder: ExchangeRecorder): Promise<number> {
  const response = await page.goto(`${baseUrl}${path}`, { waitUntil: "domcontentloaded" });
  const status = response?.status() ?? 0;
  if (!recorder.isBrowserPage(page)) recorder.record(actor, "GET", path, undefined, status, null);
  return status;
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

async function waitForAssistant(
  page: Page,
  actor: AccessActor,
  path: string,
  recorder: ExchangeRecorder,
): Promise<{ status: number; data: string }> {
  const result = await page.evaluate(async ({ path, marker, timeoutMs }) => {
    const response = await fetch(path, { headers: { accept: "text/event-stream" } });
    const headers = Object.fromEntries(response.headers.entries());
    if (!response.ok || !response.body) {
      return {
        status: response.status,
        data: "",
        headers,
        outcome: "response_unavailable" as const,
      };
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let data = "";
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const remaining = Math.max(1, deadline - Date.now());
      const next = await new Promise<
        | { kind: "read"; value: ReadableStreamReadResult<Uint8Array> }
        | { kind: "timeout" }
        | { kind: "error" }
      >((resolveRead) => {
        let settled = false;
        const settle = (
          value:
            | { kind: "read"; value: ReadableStreamReadResult<Uint8Array> }
            | { kind: "timeout" }
            | { kind: "error" },
        ) => {
          if (settled) return;
          settled = true;
          window.clearTimeout(timer);
          resolveRead(value);
        };
        const timer = window.setTimeout(() => settle({ kind: "timeout" }), remaining);
        void reader.read()
          .then((value) => settle({ kind: "read", value }))
          .catch(() => settle({ kind: "error" }));
      });
      if (next.kind === "timeout") {
        void reader.cancel().catch(() => undefined);
        return { status: response.status, data, headers, outcome: "observation_timeout" as const };
      }
      if (next.kind === "error") {
        void reader.cancel().catch(() => undefined);
        return { status: response.status, data, headers, outcome: "stream_error" as const };
      }
      if (next.value.done) {
        data += decoder.decode();
        return { status: response.status, data, headers, outcome: "stream_ended" as const };
      }
      data += decoder.decode(next.value.value, { stream: true });
      if (data.includes(marker)) {
        void reader.cancel().catch(() => undefined);
        return { status: response.status, data, headers, outcome: "marker_observed" as const };
      }
    }
    void reader.cancel().catch(() => undefined);
    return { status: response.status, data, headers, outcome: "observation_timeout" as const };
  }, { path, marker: ASSISTANT_MARKER, timeoutMs: ASSISTANT_STREAM_TIMEOUT_MS });
  if (recorder.isBrowserPage(page)) {
    const completed = result.outcome === "stream_ended";
    recorder.completeBrowserResult(
      actor,
      "GET",
      path,
      undefined,
      result.status,
      result.data,
      result.headers,
      completed,
      completed ? "complete" : result.outcome === "stream_error" ? "error" : "disconnect",
    );
  } else {
    recorder.record(actor, "GET", path, undefined, result.status, null);
  }
  if (result.outcome !== "marker_observed") {
    throw new BrowserStreamObservationFailure({
      actor,
      method: "GET",
      path,
      status: result.status,
      outcome: result.outcome,
      observedBytes: Buffer.byteLength(result.data),
    });
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
  await expect(page.getByText(PROFILE_LABEL, { exact: true })).toBeVisible();
  const providerText = await page.locator("body").innerText();
  expect(providerText).toContain(PROFILE_LABEL);
  try {
    expect(providerText).toMatch(/deployment[ -]shared|shared deployment/i);
  } catch {
    throw new BrowserUiObservationFailure(
      PROFILE_E2E,
      UI_SHARED_TRUST_CLASSIFICATION,
      UI_SHARED_TRUST_FIRST_GAP,
      UI_SHARED_TRUST_FIRST_GAP_SHA256,
      "the shared profile was available to the second admitted actor but the UI did not explain its deployment-shared trust boundary",
      {
        actor: "actor-b",
        method: "GET",
        path: `/v1/providers/${PROVIDER_NAME}/auth-profiles`,
        status: profiles.status,
        outcome: "shared_trust_boundary_not_visible",
        observedBytes: Buffer.byteLength(providerText),
      },
    );
  }
  expect(providerText).toMatch(/ready|installed|distributed/i);
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
  return path === "/v1/sessions" || /^\/v1\/sessions\/[^/]+(?:\/messages|\/events)?$/.test(path);
}

function isIdempotencyReceiptMiss(observation: EndpointObservation): boolean {
  return observation.status === 404 && observation.responseCode === "idempotency_receipt_not_found";
}

function assertEndpointOwnershipTrace(
  stack: Awaited<ReturnType<typeof createTwoActorStack>>,
  admission: SessionAdmission,
  actorBSessionId: string,
): void {
  const observations: EndpointObservation[] = stack.endpointTransport.observations()
    .filter((observation) => isEndpointSessionPath(observation.path));
  expect(observations.length, "Server must reach the real Endpoint session API").toBeGreaterThan(0);
  expect(observations.every((observation) => observation.subject !== null)).toBe(true);
  expect(observations.every((observation) => observation.controllerAuthMatched)).toBe(true);

  const createRequests = observations.filter(
    (observation) => observation.method === "POST"
      && observation.path === "/v1/sessions"
      && observation.idempotencyKey === admission.idempotencyKey,
  );
  const receiptMisses = createRequests.filter(
    isIdempotencyReceiptMiss,
  );
  expect(receiptMisses).toHaveLength(2);
  const successfulCreates = createRequests.filter(
    (observation) => observation.status === 201 && observation.responseCode === null,
  );
  expect(successfulCreates).toHaveLength(3);
  const successfulCreatesBySubject = new Map<string, EndpointObservation[]>();
  for (const observation of successfulCreates) {
    const subject = observation.subject as string;
    successfulCreatesBySubject.set(subject, [...successfulCreatesBySubject.get(subject) ?? [], observation]);
  }
  expect(successfulCreatesBySubject.size).toBe(2);
  const actorACreates = [...successfulCreatesBySubject.values()].find((items) => items.length === 2) ?? [];
  expect(actorACreates).toHaveLength(2);
  const actorASubject = actorACreates[0]?.subject;
  expect(actorASubject).not.toBeNull();
  expect(actorACreates[1]?.subject).toBe(actorASubject);
  expect(actorACreates[1]?.requestBodyDigest).toBe(actorACreates[0]?.requestBodyDigest);
  expect(actorACreates[1]?.responseBodyDigest).toBe(actorACreates[0]?.responseBodyDigest);
  const actorBCreate = [...successfulCreatesBySubject.values()].find((items) => items.length === 1)?.[0];
  expect(actorBCreate).toBeDefined();
  expect(actorBCreate?.requestBodyDigest).toBe(actorACreates[0]?.requestBodyDigest);
  expect(actorBCreate?.status).toBe(201);
  expect(actorBCreate?.subject).not.toBe(actorASubject);
  expect(new Set(receiptMisses.map((observation) => observation.subject))).toEqual(
    new Set([actorASubject, actorBCreate?.subject]),
  );
  const subjects = new Set(observations.map((observation) => observation.subject));
  expect(subjects.size).toBe(2);
  expect(observations.every((observation) => observation.subject === actorASubject || observation.subject === actorBCreate?.subject)).toBe(true);

  const actorASessionPath = `/v1/sessions/${admission.sessionId}`;
  const actorBSessionPath = `/v1/sessions/${actorBSessionId}`;
  const actorAOwned = observations.filter(
    (observation) => observation.subject === actorASubject && observation.path.includes(actorASessionPath),
  );
  expect(actorAOwned.length).toBeGreaterThan(0);
  const actorAReceiptMisses = actorAOwned.filter(isIdempotencyReceiptMiss);
  const actorAResolved = actorAOwned.filter((observation) => !isIdempotencyReceiptMiss(observation));
  expect(actorAResolved.every((observation) => observation.status !== 404)).toBe(true);
  for (const receiptMiss of actorAReceiptMisses) {
    expect(actorAResolved.some((observation) =>
      observation.method === receiptMiss.method
      && observation.path === receiptMiss.path
      && observation.idempotencyKey === receiptMiss.idempotencyKey
      && observation.requestBodyDigest === receiptMiss.requestBodyDigest,
    )).toBe(true);
  }

  const actorAMessageRequests = observations.filter(
    (observation) => observation.subject === actorASubject
      && observation.path === `${actorASessionPath}/messages`
      && observation.idempotencyKey === SESSION_MESSAGE_IDEMPOTENCY_KEY,
  );
  expect(actorAMessageRequests.filter(isIdempotencyReceiptMiss)).toHaveLength(1);
  const actorAResolvedMessages = actorAMessageRequests.filter(
    (observation) => !isIdempotencyReceiptMiss(observation),
  );
  expect(actorAResolvedMessages).toHaveLength(2);
  expect(actorAResolvedMessages[1]?.requestBodyDigest).toBe(actorAResolvedMessages[0]?.requestBodyDigest);
  expect(actorAResolvedMessages[1]?.status).toBe(actorAResolvedMessages[0]?.status);
  expect(actorAResolvedMessages[1]?.responseBodyDigest).toBe(actorAResolvedMessages[0]?.responseBodyDigest);

  const actorBSubject = actorBCreate?.subject;
  expect(actorBSubject).not.toBeNull();
  const actorBAgainstA = observations.filter(
    (observation) => observation.subject === actorBSubject && observation.path.includes(actorASessionPath),
  );
  expect(actorBAgainstA.length).toBeGreaterThanOrEqual(3);
  expect(actorBAgainstA.every((observation) => observation.status === 404)).toBe(true);
  const actorBMessageRequests = observations.filter(
    (observation) => observation.subject === actorBSubject
      && observation.path === `${actorASessionPath}/messages`
      && observation.idempotencyKey === SESSION_MESSAGE_IDEMPOTENCY_KEY,
  );
  expect(actorBMessageRequests.length).toBeGreaterThanOrEqual(2);
  expect(actorBMessageRequests[0]?.requestBodyDigest).toBe(actorAResolvedMessages[0]?.requestBodyDigest);
  expect(actorBMessageRequests.every((observation) => observation.status === 404)).toBe(true);
  expect(new Set(actorBMessageRequests.map((observation) => observation.responseCode))).toEqual(
    new Set(["idempotency_receipt_not_found", "session_not_found"]),
  );

  const actorBOwned = observations.filter(
    (observation) => observation.subject === actorBSubject && observation.path.includes(actorBSessionPath),
  );
  expect(actorBOwned.length).toBeGreaterThan(0);
  expect(actorBOwned.every((observation) => observation.status !== 404)).toBe(true);
  expect(actorASubject).not.toBe(actorBSubject);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function profileCard(page: Page, label: string) {
  return page.locator(".profile-row").filter({ has: page.getByText(label, { exact: true }) });
}

function distributionRow(card: ReturnType<typeof profileCard>, endpointLabel: string) {
  return card.getByRole("group", { name: new RegExp(escapeRegex(endpointLabel)) });
}

async function openProviders(page: Page): Promise<void> {
  await page.getByRole("link", { name: "Providers" }).click();
  await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
}

async function openEndpoints(page: Page): Promise<void> {
  await page.getByRole("link", { name: "Endpoints" }).click();
  await expect(page.getByRole("heading", { name: "Endpoints", exact: true })).toBeVisible();
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
  const controllerCredential = endpointDialog.getByLabel("Controller credential");
  await expect(controllerCredential).toHaveAttribute("type", "password");
  await controllerCredential.fill(stack.endpointControlSecret);
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
  const endpointCard = page.locator("article.resource-card").filter({
    has: page.getByRole("heading", { name: ENDPOINT_LABEL, exact: true }),
  });
  await expect(endpointCard).toHaveCount(1);
  await expect(endpointCard).toContainText(/online|ready/i);

  await openProviders(page);
  await page.getByRole("button", { name: "Configure provider" }).click();
  const providerDialog = page.locator("form.editor-panel").filter({
    has: page.getByRole("heading", { name: "Configure provider", exact: true }),
  });
  await providerDialog.getByLabel("Provider ID").fill(PROVIDER_NAME);
  await providerDialog.getByLabel("Provider kind").selectOption("openai_compatible");
  await providerDialog.getByLabel("Base URL").fill(stack.providerBaseUrl);
  await providerDialog.getByLabel("Models").fill(PROVIDER_MODEL);
  const descriptorResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "PUT" && new URL(response.url()).pathname === `/v1/providers/${PROVIDER_NAME}`,
  );
  await providerDialog.getByRole("button", { name: "Save provider" }).click();
  const descriptorResponse = await descriptorResponsePromise;
  expect(descriptorResponse.status()).toBe(200);
  const descriptorBody = (await descriptorResponse.json()) as Record<string, unknown>;
  const descriptorRevision = Number(descriptorBody.revision ?? 0);
  expect(descriptorRevision).toBeGreaterThan(0);
  await expect(providerDialog).toBeHidden();

  await page.getByRole("button", { name: "Add API key profile" }).click();
  const profileDialog = page.locator("form.nested-editor").filter({
    has: page.getByRole("heading", { name: "Add API key profile", exact: true }),
  });
  await profileDialog.getByLabel("Profile label").fill(PROFILE_LABEL);
  const apiKey = profileDialog.getByLabel("API key");
  await expect(apiKey).toHaveAttribute("type", "password");
  await apiKey.fill(stack.providerSecret);
  await profileDialog.getByRole("checkbox", { name: "Make this the default profile" }).check();
  await profileDialog.getByRole("checkbox", { name: `Share with ${ENDPOINT_LABEL}` }).check();
  const profileResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && new URL(response.url()).pathname === `/v1/providers/${PROVIDER_NAME}/auth-profiles`,
  );
  await profileDialog.getByRole("button", { name: "Create profile" }).click();
  const profileResponse = await profileResponsePromise;
  expect(profileResponse.status()).toBe(201);
  const profileBody = (await profileResponse.json()) as Record<string, unknown>;
  const profileId = String(profileBody.auth_profile_id ?? "");
  const profileRevision = Number(profileBody.revision ?? 0);
  expect(profileId).not.toBe("");
  expect(profileRevision).toBeGreaterThan(0);
  onProfileCreated?.({ endpointId, profileId });
  await expect(profileDialog).toBeHidden();
  const card = profileCard(page, PROFILE_LABEL);
  await expect(card).toContainText(/explicit default|default profile/i);
  const distribution = distributionRow(card, ENDPOINT_LABEL);
  await expect.poll(async () => {
    if ((await distribution.count()) === 0) return "";
    return (await distribution.innerText()).toLowerCase();
  }, {
    timeout: 15_000,
    intervals: [100, 250, 500, 1_000],
  }).toMatch(/\bready\b|\binstalled\b/);
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
  expect(actorBSameKey.text).not.toBe(admission.response.text);
  const actorBSessionId = String(asJson(actorBSameKey).session_id ?? "");
  expect(actorBSessionId).not.toBe("");
  expect(actorBSessionId).not.toBe(admission.sessionId);
  expect(asJson(actorBSameKey)).not.toEqual(asJson(admission.response));
  await expectNoSecrets(actorBSameKey, [stack.providerSecret, stack.endpointControlSecret]);
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
  actorBSessionId?: string,
  recordPublic = true,
): Promise<void> {
  const sessionPath = `/v1/endpoints/${resource.endpointId}/sessions/${sessionId}`;
  const sessionRoute = `/endpoints/${resource.endpointId}/sessions/${sessionId}`;
  const listPath = `/v1/endpoints/${resource.endpointId}/sessions`;
  const forbidden = [stack.providerSecret, stack.endpointControlSecret];
  let actorAMessageResponse: PublicResponse | undefined;

  if (includeProviderRound) {
    const stream = waitForAssistant(pageA, "actor-a", `${sessionPath}/events`, recorder);
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
  expect(containsValue(actorBList.json, sessionId)).toBe(false);
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
  await expectSafeNotFound(actorBRead, forbidden);

  const actorBStream = await publicRequest(
    pageB,
    "actor-b",
    "GET",
    `${sessionPath}/events`,
    undefined,
    undefined,
    recorder,
    recordPublic,
  );
  await expectSafeNotFound(actorBStream, forbidden);

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
  await expectSafeNotFound(actorBSameBodyMutation, forbidden);
  if (actorAMessageResponse) expect(actorBSameBodyMutation.text).not.toBe(actorAMessageResponse.text);

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
  await expectSafeNotFound(actorBMutate, forbidden);

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

  const actorANavigationStatus = await gotoPublic(pageA, "actor-a", stack.actorA.baseUrl, sessionRoute, recorder);
  expect(new URL(pageA.url()).pathname).toBe(sessionRoute);
  if (includeProviderRound) {
    try {
      await expect(pageA.getByText(ASSISTANT_MARKER, { exact: false })).toBeVisible();
    } catch {
      throw new BrowserUiObservationFailure(
        ISOLATION_E2E,
        UI_LATER_CLASSIFICATION,
        UI_FIRST_GAP,
        UI_FIRST_GAP_SHA256,
        "the public session was durable but the real browser did not render its assistant marker",
        {
          actor: "actor-a",
          method: "GET",
          path: sessionRoute,
          status: actorANavigationStatus,
          outcome: "visible_marker_missing",
          observedBytes: Buffer.byteLength(await pageA.locator("body").innerText()),
        },
      );
    }
  }

  await gotoPublic(pageB, "actor-b", stack.actorB.baseUrl, sessionRoute, recorder);
  expect(new URL(pageB.url()).pathname).toBe(sessionRoute);
  try {
    const unavailable = pageB.getByRole("status").filter({
      hasText: /^The requested resource was not found or is unavailable\.$/,
    });
    await expect(unavailable).toHaveCount(1);
    await expect(unavailable).toBeVisible();
  } catch {
    throw new BrowserUiObservationFailure(
      ISOLATION_E2E,
      UI_SAFE_NOT_FOUND_CLASSIFICATION,
      UI_SAFE_NOT_FOUND_FIRST_GAP,
      UI_SAFE_NOT_FOUND_FIRST_GAP_SHA256,
      "the isolated session returned a safe 404 but the real browser did not render a safe unavailable state",
      {
        actor: "actor-b",
        method: "GET",
        path: sessionPath,
        status: actorBRead.status,
        outcome: "safe_not_found_not_visible",
        observedBytes: Buffer.byteLength(await pageB.locator("body").innerText()),
      },
    );
  }
  await expect(pageB.locator("body")).not.toContainText(ASSISTANT_MARKER);

  const idOnly = await publicRequest(pageB, "actor-b", "GET", `/v1/sessions/${sessionId}`, undefined, undefined, recorder, recordPublic);
  expect(idOnly.status).toBe(404);

}

test.describe("two Access actors and Endpoint-owned session subjects", () => {
  test.describe.configure({ mode: "serial" });
  test.setTimeout(120_000);

  async function runSessionIsolation(browser: Browser, replay: boolean): Promise<void> {
    if (!replay && CAPTURE_ENDPOINT_REPLAY) {
      assertEndpointReplayCaptureIdentity(ISOLATION_ENDPOINT_REPLAY_ID, ISOLATION_ENDPOINT_REPLAY);
    }
    const cassettePath = ISOLATION_CASSETTE;
    const cassette = await readCassette(
      cassettePath,
      ISOLATION_E2E,
      ISOLATION_RECORDING_ID,
    );
    const endpointReplay = replay
      ? await readEndpointReplayCassette(
          ISOLATION_ENDPOINT_REPLAY,
          ISOLATION_E2E,
          ISOLATION_ENDPOINT_REPLAY_ID,
          cassette,
        )
      : undefined;
    const stack = await createTwoActorStack({ replayEndpointExchanges: endpointReplay?.endpoint_exchanges });
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    const directEndpointRequestsA = watchDirectEndpointRequests(pageA, stack.endpointBaseUrl);
    const directEndpointRequestsB = watchDirectEndpointRequests(pageB, stack.endpointBaseUrl);
    const recorder = new ExchangeRecorder(
      [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET],
      cassette.classification,
      cassette.classification.positive_catalog_barrier.exchange_sequence === null
        ? undefined
        : cassette.exchanges[cassette.classification.positive_catalog_barrier.exchange_sequence],
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
      await expectSafeNotFound(afterRestartBRead, [stack.providerSecret, stack.endpointControlSecret]);
      await stack.stopServer();
      expect(await serverStoresContainSessionMirrors(stack, [sessionId, actorBSessionId])).toBe(false);
      await contextA.close();
      await contextB.close();
      await recorder.flush();
      await stack.endpointTransport.flush();
      if (!replay && CAPTURE_ENDPOINT_REPLAY) {
        const path = await retainEndpointReplayCandidate(
          ISOLATION_E2E,
          ISOLATION_ENDPOINT_REPLAY_ID,
          cassette,
          stack.endpointTransport.cassetteExchanges(),
        );
        if (PROMOTE_ENDPOINT_REPLAY) {
          await promoteEndpointReplayCandidate(
            path,
            ISOLATION_ENDPOINT_REPLAY,
            ISOLATION_E2E,
            ISOLATION_ENDPOINT_REPLAY_ID,
            cassette,
          );
        }
        process.stderr.write(`ZODE_E2E_TWO_ACTOR_ENDPOINT_REPLAY ${path}\n`);
      }
      if (replay) {
        stack.endpointTransport.assertReplayConsumed();
      }
    } catch (error) {
      await recorder.flush();
      if (!replay) await retainRequestedBrowserObservation(error, recorder);
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      try {
        await stack.endpointTransport.flush();
        if (replay) stack.endpointTransport.assertReplayConsumed();
      } catch (flushError) {
        throw new AggregateError(
          [error, flushError],
          "two-actor public failure was retained before Endpoint transport flush failed",
        );
      }
      const first = recorder.classifyFirstFailure();
      if (!replay && first) {
        await writeFirstFailureCassette(
          quarantineCassette(cassette, first, recorder.values(), stack.endpointTransport.cassetteExchanges()),
        );
      }
      throw error;
    } finally {
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      await stack.dispose();
    }
  }

  async function runSharedProviderProfiles(browser: Browser, replay: boolean): Promise<void> {
    if (!replay && CAPTURE_ENDPOINT_REPLAY) {
      assertEndpointReplayCaptureIdentity(PROFILE_ENDPOINT_REPLAY_ID, PROFILE_ENDPOINT_REPLAY);
    }
    const cassettePath = PROFILE_CASSETTE;
    const cassette = await readCassette(
      cassettePath,
      PROFILE_E2E,
      PROFILE_RECORDING_ID,
    );
    const endpointReplay = replay
      ? await readEndpointReplayCassette(
          PROFILE_ENDPOINT_REPLAY,
          PROFILE_E2E,
          PROFILE_ENDPOINT_REPLAY_ID,
          cassette,
        )
      : undefined;
    const stack = await createTwoActorStack({ replayEndpointExchanges: endpointReplay?.endpoint_exchanges });
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    const directEndpointRequestsA = watchDirectEndpointRequests(pageA, stack.endpointBaseUrl);
    const directEndpointRequestsB = watchDirectEndpointRequests(pageB, stack.endpointBaseUrl);
    const recorder = new ExchangeRecorder(
      [PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET],
      cassette.classification,
      cassette.classification.positive_catalog_barrier.exchange_sequence === null
        ? undefined
        : cassette.exchanges[cassette.classification.positive_catalog_barrier.exchange_sequence],
    );
    recorder.attachBrowserPage(pageA, "actor-a");
    recorder.attachBrowserPage(pageB, "actor-b");
    let armed = false;
    let sessionId = "";
    let actorBSessionId = "";
    try {
      const resource = await configureSharedResourcesViaUi(pageA, stack, recorder, ({ endpointId, profileId }) => {
        armed = true;
        recorder.arm([endpointId, profileId]);
      });
      armed = true;
      recorder.arm([resource.endpointId, resource.profileId]);
      await expectSharedProviderResource(pageB, stack, resource.endpointId, resource.profileId, recorder);
      stack.endpointTransport.arm([resource.endpointId, resource.profileId]);
      const admission = await createActorASession(pageA, stack, resource, recorder);
      sessionId = admission.sessionId;
      armed = true;
      actorBSessionId = await assertCreateIdempotencyScope(pageA, pageB, stack, resource, admission, recorder);
      await assertSessionIsolation(pageA, pageB, stack, resource, sessionId, recorder, true, actorBSessionId);
      assertEndpointOwnershipTrace(stack, admission, actorBSessionId);
      expect(await serverStoresContainSessionMirrors(stack, [sessionId, actorBSessionId])).toBe(false);
      expect(directEndpointRequestsA).toHaveLength(0);
      expect(directEndpointRequestsB).toHaveLength(0);
      await expectNoBrowserCredentialState(pageA, ["Cf-Access-Jwt-Assertion", PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET]);
      await expectNoBrowserCredentialState(pageB, ["Cf-Access-Jwt-Assertion", PROVIDER_SECRET, ENDPOINT_CONTROL_SECRET]);
      await stack.stopServer();
      await contextA.close();
      await contextB.close();
      await recorder.flush();
      await stack.endpointTransport.flush();
      if (!replay && CAPTURE_ENDPOINT_REPLAY) {
        const path = await retainEndpointReplayCandidate(
          PROFILE_E2E,
          PROFILE_ENDPOINT_REPLAY_ID,
          cassette,
          stack.endpointTransport.cassetteExchanges(),
        );
        if (PROMOTE_ENDPOINT_REPLAY) {
          await promoteEndpointReplayCandidate(
            path,
            PROFILE_ENDPOINT_REPLAY,
            PROFILE_E2E,
            PROFILE_ENDPOINT_REPLAY_ID,
            cassette,
          );
        }
        process.stderr.write(`ZODE_E2E_TWO_ACTOR_ENDPOINT_REPLAY ${path}\n`);
      }
      if (replay) {
        stack.endpointTransport.assertReplayConsumed();
      }
    } catch (error) {
      await recorder.flush();
      if (!replay) await retainRequestedBrowserObservation(error, recorder);
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      try {
        await stack.endpointTransport.flush();
        if (replay) stack.endpointTransport.assertReplayConsumed();
      } catch (flushError) {
        throw new AggregateError(
          [error, flushError],
          "two-actor shared-profile failure was retained before Endpoint transport flush failed",
        );
      }
      const first = recorder.classifyFirstFailure();
      if (!replay && first) {
        await writeFirstFailureCassette(
          quarantineCassette(cassette, first, recorder.values(), stack.endpointTransport.cassetteExchanges()),
        );
      }
      throw error;
    } finally {
      await contextA.close().catch(() => undefined);
      await contextB.close().catch(() => undefined);
      await stack.dispose();
    }
  }

  test(ISOLATION_E2E, async ({ browser }) => {
    await runSessionIsolation(browser, false);
  });

  test(ISOLATION_REPLAY_E2E, async ({ browser }) => {
    await runSessionIsolation(browser, true);
  });

  test(PROFILE_E2E, async ({ browser }) => {
    await runSharedProviderProfiles(browser, false);
  });

  test(PROFILE_REPLAY_E2E, async ({ browser }) => {
    await runSharedProviderProfiles(browser, true);
  });
});
