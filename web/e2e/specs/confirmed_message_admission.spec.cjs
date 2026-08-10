const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  RecordingJournal,
  SecretLedger,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require("../support/harness.cjs");

const E2E_NAME =
  "e2e_browser_confirmed_message_admission_is_not_downgraded_by_projection_failure";
const CLASSIFICATION =
  "CONFIRMED_MESSAGE_ADMISSION_DOWNGRADED_BY_PROJECTION_FAILURE__later_test_reproduction_of_gap";
const FIRST_OBSERVED =
  "relation=later_test_reproduction_of_gap; a message received HTTP 202 and completed once, but two temporary projection failures were presented as an admission failure";
const RECOVERY_CAPTURE_SET_ID = "0002-a2a1957f-a6dd-4f94-b17a-72a347742753";
const RECOVERY_FIRST_FAILURE_ID = "000037-b29abd27-5b5a-4c48-b381-da5043195b9b";
const RECOVERY_SOURCE_DIGEST = "e04029f9cb10618b7dba1162b2b8674ab7c4c5a35e18aea176620d95d3e8dae5";
const CAPTURE_ENV = "ZODE_RECOVER_CONFIRMED_ADMISSION_CAPTURE_ROOT";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const PROVIDER = "confirmed-admission-fixture";
const MODEL = "confirmed-admission-model";
const MESSAGE = "confirmed admission survives projection failure";

function matchingCassettes() {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs
    .readdirSync(INCIDENT_DIRECTORY)
    .filter((name) => name.endsWith(".v1.json"))
    .map((name) => path.join(INCIDENT_DIRECTORY, name))
    .filter((candidate) => {
      try {
        const value = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return value.e2e_name === E2E_NAME && value.classification === CLASSIFICATION;
      } catch {
        return false;
      }
    });
}

function assertCassetteIdentity() {
  const matches = matchingCassettes();
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(fs.readFileSync(matches[0], "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.boundary).toBe("browser-capture-set");
  expect(cassette.first_observed).toBe(FIRST_OBSERVED);
  expect(cassette.source_digest).toBe(RECOVERY_SOURCE_DIGEST);
  expect(cassette.first_failure_recording_id).toBe(RECOVERY_FIRST_FAILURE_ID);
  expect(cassette.exchanges).toHaveLength(14);
  expect(
    cassette.exchanges.some(
      (exchange) =>
        exchange.boundary === "management-access-edge" &&
        exchange.method === "POST" &&
        exchange.path.endsWith("/messages") &&
        exchange.response.status === 202,
    ),
  ).toBe(true);
  for (const boundary of ["management-access-edge", "server-endpoint-control"]) {
    expect(
      cassette.exchanges.filter(
        (exchange) =>
          exchange.boundary === boundary &&
          exchange.method === "GET" &&
          exchange.response.status === 503,
      ),
    ).toHaveLength(2);
  }
  expect(
    cassette.exchanges.some(
      (exchange) =>
        exchange.boundary === "provider-recording-proxy" && exchange.response.status === 200,
    ),
  ).toBe(true);
  expect(fs.statSync(matches[0]).mode & 0o777).toBe(0o444);
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function recoveredSecretLedger(rootDir, manifest) {
  const ledger = new SecretLedger();
  let access = 0;
  let control = 0;
  let provider = 0;
  for (const recordingId of manifest.members) {
    const rawName = fs
      .readdirSync(rootDir)
      .find((name) => name.startsWith(recordingId) && name.endsWith(".raw.json"));
    if (!rawName) throw new Error(`recovery capture omitted raw member ${recordingId}`);
    const raw = JSON.parse(fs.readFileSync(path.join(rootDir, rawName), "utf8"));
    const assertion = raw.request_headers?.["cf-access-jwt-assertion"];
    if (typeof assertion === "string" && assertion) {
      ledger.add(`recovered_access_assertion_${++access}`, assertion, { derive: false });
    }
    const authorization = raw.request_headers?.authorization;
    if (typeof authorization === "string" && authorization) {
      const value = authorization.replace(/^Bearer\s+/iu, "");
      const prefix = raw.boundary === "provider-recording-proxy" ? "provider" : "control";
      const sequence = prefix === "provider" ? ++provider : ++control;
      ledger.add(`recovered_${prefix}_authorization_${sequence}`, value, { derive: false });
    }
  }
  return ledger;
}

async function recoverAndPromote(rootDir) {
  const manifestPath = path.join(rootDir, `${RECOVERY_CAPTURE_SET_ID}.manifest.json`);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const ledger = recoveredSecretLedger(rootDir, manifest);
  const journal = RecordingJournal.openFlushedCaptureRoot({ rootDir, ledger });
  const recovered = journal.reloadCaptureSet(RECOVERY_CAPTURE_SET_ID);
  expect(recovered.e2eName).toBe(E2E_NAME);
  expect(recovered.sourceDigest).toBe(RECOVERY_SOURCE_DIGEST);
  expect(recovered.firstFailureRecordingId).toBe(RECOVERY_FIRST_FAILURE_ID);
  expect(recovered.records).toHaveLength(14);
  for (const record of recovered.records) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
  return journal.promoteFlushedCaptureSet(RECOVERY_CAPTURE_SET_ID, {
    e2eName: E2E_NAME,
    classification: CLASSIFICATION,
    firstObserved: FIRST_OBSERVED,
    firstFailureRecordingId: RECOVERY_FIRST_FAILURE_ID,
    destinationDirectory: INCIDENT_DIRECTORY,
    replay: async (envelope) => {
      const replayServer = await journal.startReplayServer(envelope);
      try {
        const results = await journal.replay(envelope, { baseUrl: replayServer.baseUrl });
        return results;
      } finally {
        await replayServer.finish();
      }
    },
  });
}

async function managementJson(page, method, requestPath, body) {
  return page.evaluate(
    async ({ method: requestMethod, requestPath: targetPath, body: requestBody }) => {
      const response = await fetch(targetPath, {
        method: requestMethod,
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "idempotency-key": `${requestMethod.toLowerCase()}-${crypto.randomUUID()}`,
        },
        body: requestBody === undefined ? undefined : JSON.stringify(requestBody),
      });
      return { status: response.status, body: await response.json() };
    },
    { method, requestPath, body },
  );
}

async function projectionFaultProxy(harness) {
  let captureSetId;
  let armAfterMessage = false;
  let armed = false;
  let sessionFailures = 0;
  let listFailures = 0;
  let subject;
  const fault = await startHttpServer((_request, response) => {
    response.writeHead(503, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        error: { code: "endpoint_unavailable", message: "projection temporarily unavailable", retryable: true },
      }),
    );
  });
  const proxy = await startHttpServer(async (request, response) => {
    subject = request.headers["zode-subject"] || subject;
    const requestUrl = new URL(request.url ?? "/", "http://endpoint.invalid");
    const failSession =
      armed &&
      request.method === "GET" &&
      /^\/v1\/sessions\/[^/]+$/u.test(requestUrl.pathname) &&
      sessionFailures === 0;
    const failList =
      armed && request.method === "GET" && requestUrl.pathname === "/v1/sessions" && listFailures === 0;
    if (failSession) sessionFailures += 1;
    if (failList) listFailures += 1;
    const record = await proxyHttp({
      targetBaseUrl: failSession || failList ? fault.baseUrl : harness.endpoint.baseUrl,
      request,
      response,
      extraHeaders: {
        authorization: `Bearer ${harness.controllerSecret}`,
        ...(subject ? { "zode-subject": subject } : {}),
      },
      boundary: "server-endpoint-control",
      journal: harness.journal,
      ledger: harness.ledger,
      captureSetId: captureSetId ?? harness.journal.currentCaptureSetId,
      canonicalOrigin: failSession || failList ? fault.baseUrl : harness.endpoint.baseUrl,
    });
    if (
      armAfterMessage &&
      request.method === "POST" &&
      requestUrl.pathname.endsWith("/messages") &&
      record?.response?.status === 202
    ) {
      armed = true;
    }
  });
  return {
    proxy,
    get failures() {
      return { session: sessionFailures, list: listFailures };
    },
    setCaptureSetId(value) {
      captureSetId = value;
    },
    armAfterConfirmedMessage() {
      armAfterMessage = true;
    },
    async close() {
      await proxy.close();
      await fault.close();
    },
  };
}

async function preseedSession(page, harness, endpointBaseUrl) {
  const endpoint = await managementJson(page, "POST", "/v1/endpoints", {
    label: "Confirmed admission Endpoint",
    base_url: endpointBaseUrl,
    control_auth: { kind: "bearer", secret: harness.controllerSecret },
  });
  expect(endpoint.status).toBe(201);
  const endpointId = endpoint.body.endpoint_id;
  const provider = await managementJson(page, "PUT", `/v1/providers/${PROVIDER}`, {
    kind: "openai_compatible",
    base_url: `${harness.providerProxy.baseUrl}/v1`,
    models: [MODEL],
    options: {},
  });
  expect(provider.status).toBe(200);
  const profile = await managementJson(page, "POST", `/v1/providers/${PROVIDER}/auth-profiles`, {
    kind: "api_key",
    label: "Confirmed admission profile",
    api_key: harness.providerSecret,
    make_default: true,
    sharing: { mode: "selected", endpoint_ids: [endpointId] },
  });
  expect(profile.status).toBe(201);
  const session = await managementJson(page, "POST", `/v1/endpoints/${endpointId}/sessions`, {
    model: {
      provider: PROVIDER,
      model: MODEL,
      provider_execution: {
        schema: "zode.provider-execution.v1",
        revision: provider.body.revision,
        kind: provider.body.kind,
        base_url: provider.body.base_url,
        options: provider.body.options,
      },
      auth_profile_id: profile.body.auth_profile_id,
      minimum_auth_revision: profile.body.revision,
    },
    tools: [],
  });
  expect(session.status).toBe(201);
  return { endpointId, sessionId: session.body.session_id };
}

test(E2E_NAME, async ({ page }) => {
  test.setTimeout(180_000);
  const recoveryRoot = process.env[CAPTURE_ENV];
  if (!recoveryRoot) assertCassetteIdentity();
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-confirmed-admission",
  });
  const endpointProxy = await projectionFaultProxy(harness);
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    const session = await preseedSession(page, harness, endpointProxy.proxy.baseUrl);
    const sessionPath = `/v1/endpoints/${session.endpointId}/sessions/${session.sessionId}`;
    const sessionUiPath = `/endpoints/${session.endpointId}/sessions/${session.sessionId}`;
    const messagePath = `${sessionPath}/messages`;
    const browserMessages = [];
    page.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname === messagePath) {
        browserMessages.push(request.headers()["idempotency-key"] ?? "");
      }
    });
    await page.goto(`${harness.managementUrl}${sessionUiPath}`, { waitUntil: "domcontentloaded" });
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await expect(composer).toBeVisible();
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled();
    await page.evaluate(() => {
      const alerts = [];
      const sample = () => {
        for (const node of document.querySelectorAll('[role="alert"]')) {
          const text = node.textContent?.trim();
          if (text && !alerts.includes(text)) alerts.push(text);
        }
      };
      const observer = new MutationObserver(sample);
      observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
      window.__zodeConfirmedAdmissionObservation = { alerts, observer };
      sample();
    });
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 128 });
    endpointProxy.setCaptureSetId(captureSetId);
    endpointProxy.armAfterConfirmedMessage();

    await composer.fill(MESSAGE);
    await composer.press("Enter");
    await harness.fakeProvider.waitForRequest(1);
    await expect(page.getByText("E2E_OK", { exact: true })).toBeVisible({ timeout: 30_000 });
    await expect.poll(() => endpointProxy.failures).toEqual({ session: 1, list: 1 });
    await expect
      .poll(
        async () => {
          const result = await managementJson(page, "GET", sessionPath);
          const transcript = Array.isArray(result.body?.transcript) ? result.body.transcript : [];
          return {
            status: result.status,
            user: transcript.filter((message) => message.role === "user" && message.content === MESSAGE)
              .length,
            assistant: transcript.filter(
              (message) => message.role === "assistant" && message.content === "E2E_OK",
            ).length,
          };
        },
        { timeout: 30_000 },
      )
      .toEqual({ status: 200, user: 1, assistant: 1 });
    expect(browserMessages).toHaveLength(1);
    expect(browserMessages[0]).toMatch(/^[0-9a-f-]{36}$/iu);
    const alerts = await page.evaluate(() => {
      const observation = window.__zodeConfirmedAdmissionObservation;
      observation?.observer.disconnect();
      return observation?.alerts ?? [];
    });
    const admissionAlerts = alerts.filter((message) => /Server is unavailable|Endpoint is unavailable/iu.test(message));
    if (admissionAlerts.length > 0) {
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        postStatus: 202,
        projectionFailures: endpointProxy.failures,
        browserPostCount: browserMessages.length,
        durableUserCount: 1,
        durableAssistantCount: 1,
        alerts: admissionAlerts,
      });
    }
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await page.close().catch(() => undefined);
      await harness.journal.waitForIdle(15_000);
      endpointProxy.setCaptureSetId(undefined);
      if (captureSetId) {
        const records = recordsFor(harness, captureSetId);
        const firstFailure = records.find(
          (record) =>
            record.boundary === "management-access-edge" &&
            record.method === "GET" &&
            record.response.status === 503,
        );
        if (!firstFailure)
          throw new Error("confirmed-admission capture omitted the public projection failure");
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        if (recoveryRoot && primaryError?.classification === CLASSIFICATION) {
          const promoted = await recoverAndPromote(path.resolve(recoveryRoot));
          primaryError = new ProductBehaviorFailure(
            CLASSIFICATION,
            `${FIRST_OBSERVED}; cassette=${promoted.cassettePath}`,
            { captureSetId: RECOVERY_CAPTURE_SET_ID, recordingId: RECOVERY_FIRST_FAILURE_ID },
          );
        }
      } else if (!primaryError) {
        throw new Error("confirmed-admission capture was not armed");
      }
    } catch (captureError) {
      primaryError = captureError;
    }
    try {
      await endpointProxy.close();
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
  }
  if (primaryError) throw primaryError;
});
