const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  RealProcess,
  proxyHttp,
  createWebE2EHarness,
  startHttpServer,
} = require("../support/harness.cjs");
const { openManagement } = require("../support/radix.cjs");

const E2E_NAME = "e2e_browser_provider_descriptor_stale_selection_recovers_before_session";
const CLASSIFICATION = "STALE_PROVIDER_DESCRIPTOR_SELECTION_NOT_RECOVERABLE";
const FIRST_OBSERVED =
  "a second management flow advanced the provider descriptor while an open session form kept the old revision; Start session returned invalid_request but the page only showed Check the requested values and try again.";
const PROVIDER = "stale-descriptor-provider";
const MODEL = "stale-descriptor-model";
const UPDATED_MODEL = "stale-descriptor-model-v2";
const ENDPOINT_LABEL = "Stale descriptor Endpoint";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const MANAGEMENT_INCIDENT_CASSETTE = path.join(
  INCIDENT_DIRECTORY,
  "0003-90177662-5a96-4b54-ae1c-405785d6a220-b31f0255-6669-4b7d-ad6c-dd51ebb999a3.v1.json",
);
const ENDPOINT_CONTROL_INCIDENT_CASSETTE = path.join(
  INCIDENT_DIRECTORY,
  "0003-d9045cc6-11c5-4504-86f6-00ac4fb93cc3-f5167ce3-0a5e-4b22-b224-4749c069c9de.v1.json",
);

function assertCassetteIdentity() {
  const managementCassette = JSON.parse(fs.readFileSync(MANAGEMENT_INCIDENT_CASSETTE, "utf8"));
  const endpointCassette = JSON.parse(fs.readFileSync(ENDPOINT_CONTROL_INCIDENT_CASSETTE, "utf8"));
  for (const cassette of [managementCassette, endpointCassette]) {
    expect(cassette.schema).toBe("zode.http-incident-recording.v1");
    expect(cassette.version).toBe(1);
    expect(cassette.e2e_name).toBe(E2E_NAME);
    expect(cassette.classification).toBe(CLASSIFICATION);
    expect(cassette.first_observed).toBe(FIRST_OBSERVED);
    expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  }
  expect(managementCassette.exchanges).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        boundary: "management-access-edge",
        method: "POST",
        response: expect.objectContaining({ status: 400 }),
      }),
    ]),
  );
  expect(endpointCassette.exchanges).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        boundary: "server-endpoint-control",
        method: "POST",
        response: expect.objectContaining({ status: 404 }),
      }),
      expect.objectContaining({
        boundary: "server-endpoint-control",
        method: "POST",
        response: expect.objectContaining({ status: 422 }),
      }),
    ]),
  );
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

async function addRemoteEndpoint(page, harness, endpointUrl) {
  await openManagement(page, "Endpoints");
  await page.getByRole("button", { name: "Add remote Endpoint", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add remote Endpoint" });
  await dialog.getByLabel("Endpoint label").fill(ENDPOINT_LABEL);
  await dialog.getByLabel("Endpoint URL").fill(endpointUrl);
  await dialog.getByLabel("Controller credential").fill(harness.controllerSecret);
  const responsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/v1/endpoints",
  );
  await dialog.getByRole("button", { name: "Add Endpoint", exact: true }).click();
  expect((await responsePromise).status()).toBe(201);
  await expect(dialog).toBeHidden();
}

async function configureProvider(page, harness, model = MODEL) {
  await openManagement(page, "Providers");
  await page.getByRole("button", { name: "Configure provider", exact: true }).click();
  const form = page.locator("form.editor-panel").filter({ hasText: "Configure provider" });
  await form.getByLabel("Provider ID").fill(PROVIDER);
  await expect(form.getByText("OpenAI compatible", { exact: true })).toBeVisible();
  await form.getByLabel("Base URL").fill(`${harness.providerProxy.baseUrl}/v1`);
  await form.getByLabel("Models").fill(model);
  const responsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === "PUT" &&
      new URL(response.url()).pathname === `/v1/providers/${PROVIDER}`,
  );
  await form.getByRole("button", { name: "Save provider", exact: true }).click();
  expect((await responsePromise).status()).toBe(200);
  await expect(form).toBeHidden();
}

async function createProfile(page, harness) {
  await openManagement(page, "Providers");
  const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
  await card.getByRole("button", { name: "Add API key profile", exact: true }).click();
  const form = card.locator("form.nested-editor");
  await form.getByLabel("Profile label").fill("Stale descriptor profile");
  const secret = `${harness.providerSecret}-stale-descriptor`;
  await form.getByLabel("API key").fill(secret);
  await form.getByRole("checkbox", { name: "Make this the default profile", exact: true }).check();
  await form.getByRole("checkbox", { name: `Share with ${ENDPOINT_LABEL}`, exact: true }).check();
  const responsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === `/v1/providers/${PROVIDER}/auth-profiles`,
  );
  await form.getByRole("button", { name: "Create profile", exact: true }).click();
  expect((await responsePromise).status()).toBe(201);
  await expect(form).toBeHidden();
}

async function openSessionForm(page) {
  await page.getByRole("navigation", { name: "Primary", exact: true })
    .getByRole("link", { name: "New session", exact: true }).click();
  const form = page.locator("form#home-session-composer");
  await expect(form.getByRole("combobox", { name: "Environment", exact: true })).not.toHaveText("");
  await expect(
    form.getByRole("button", { name: "Choose model and reasoning", exact: true }),
  ).toContainText(MODEL);
  return form;
}

async function advanceDescriptor(adminPage, harness, rotatedProviderProxy) {
  const result = await adminPage.evaluate(
    async ({ provider, baseUrl, model }) => {
      const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}`, {
        method: "PUT",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "idempotency-key": crypto.randomUUID(),
        },
        body: JSON.stringify({
          kind: "openai_compatible",
          base_url: baseUrl,
          models: [model],
          options: {},
        }),
      });
      return { status: response.status, body: await response.json() };
    },
    { provider: PROVIDER, baseUrl: `${rotatedProviderProxy.baseUrl}/v1`, model: UPDATED_MODEL },
  );
  expect(result.status).toBe(200);
  expect(Number(result.body.revision)).toBe(2);
  expect(result.body.base_url).toContain(rotatedProviderProxy.baseUrl);
}

async function startRotatedProviderProxy(harness) {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("rotated provider proxy did not bind");
  const proxy = {
    baseUrl: `http://127.0.0.1:${address.port}`,
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
  harness.rotatedProviderProxy = proxy;
  return proxy;
}

async function startEndpointControlProxy(
  harness,
  captureSetId = () => undefined,
  endpointSubject = () => undefined,
) {
  let targetBaseUrl = harness.endpoint.baseUrl;
  let replayOnlyRemaining = 0;
  let activeRequests = 0;
  let idleResolvers = [];
  const proxy = await startHttpServer((request, response) => {
    const replayOnly = replayOnlyRemaining > 0
      && request.method === "POST"
      && request.url === "/v1/sessions";
    if (replayOnly) replayOnlyRemaining -= 1;
    const streaming = String(request.headers.accept || "").includes("text/event-stream")
      || request.url.includes("/events");
    if (!streaming) activeRequests += 1;
    const forward = () => proxyHttp({
      targetBaseUrl,
      request,
      response,
      extraHeaders: {
        authorization: `Bearer ${harness.controllerSecret}`,
        ...(endpointSubject() ? { "zode-subject": endpointSubject() } : {}),
        ...(replayOnly
          ? { "zode-idempotency-mode": "replay-only" }
          : {}),
      },
      boundary: "server-endpoint-control",
      journal: harness.journal,
      ledger: harness.ledger,
      captureSetId: captureSetId() || harness.journal.currentCaptureSetId,
      canonicalOrigin: harness.endpoint.baseUrl,
    });
    return (streaming ? harness.journal.withRecordingDisabled(forward) : forward()).finally(() => {
      if (streaming) return;
      activeRequests -= 1;
      if (activeRequests === 0) {
        const resolvers = idleResolvers;
        idleResolvers = [];
        for (const resolve of resolvers) resolve();
      }
    });
  });
  proxy.setTarget = (value) => { targetBaseUrl = value; };
  proxy.setReplayOnly = (count) => { replayOnlyRemaining = count; };
  proxy.waitForIdle = async () => {
    while (activeRequests > 0) {
      await new Promise((resolve) => idleResolvers.push(resolve));
    }
  };
  return proxy;
}

async function startReplayEndpoint(harness, providerProxy) {
  const sourceConfigPath = path.join(harness.runRoot, "endpoint", "endpoint-config.json");
  const replayRoot = path.join(harness.runRoot, "endpoint-stale-replay");
  fs.cpSync(harness.staleReplaySeedRoot, replayRoot, { recursive: true });
  // The snapshot came from a live Endpoint and still has its ownership
  // sidecar. A replay process must claim the durable database as a fresh
  // process, not inherit the stopped process's lock.
  for (const staleSidecar of [
    "endpoint.sqlite3.endpoint.lock",
    "endpoint.sqlite3.server-owner",
    path.join("credentials", ".endpoint.lock"),
  ]) {
    fs.rmSync(path.join(replayRoot, staleSidecar), { force: true });
  }
  const credentials = path.join(replayRoot, "credentials");
  const blobs = path.join(replayRoot, "blobs");
  fs.mkdirSync(credentials, { recursive: true, mode: 0o700 });
  fs.mkdirSync(blobs, { recursive: true, mode: 0o700 });
  const config = JSON.parse(fs.readFileSync(sourceConfigPath, "utf8"));
  const secretFile = path.join(replayRoot, "controller.secret");
  config.listen = "127.0.0.1:0";
  config.runtime_store.path = path.join(replayRoot, "endpoint.sqlite3");
  config.credential_replica_store.directory = credentials;
  config.blob_store.directory = blobs;
  config.controller_auth[0].secret_file = secretFile;
  config.provider_execution.allowed_base_url_origins = [new URL(providerProxy.baseUrl).origin];
  const configPath = path.join(replayRoot, "endpoint-config.json");
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);
  const env = { ...process.env, NODE_ENV: "test" };
  for (const key of [
    "OPENCODE_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "MISTRAL_API_KEY",
    "TOGETHER_API_KEY",
    "XAI_API_KEY",
    "GROQ_API_KEY",
    "COHERE_API_KEY",
  ]) delete env[key];
  return RealProcess.start({
    name: "endpoint",
    binary: process.env.ZODE_ENDPOINT_BIN || path.join(__dirname, "../../../target/debug/zode"),
    args: ["--config", configPath],
    cwd: path.resolve(__dirname, "../../.."),
    env,
    readyPrefix: "ZODE_READY ",
    ledger: harness.ledger,
    logDir: path.join(replayRoot, "logs"),
    startupCaptureRoot: path.join(harness.journal.rootDir, "endpoint-stale-replay-startup"),
    startupConfigBytes: Buffer.from(JSON.stringify(config)),
    e2eName: E2E_NAME,
  });
}

async function restartEndpointWithProviderOrigin(harness, providerProxy, e2eName) {
  const configPath = path.join(harness.runRoot, "endpoint", "endpoint-config.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const endpointPort = new URL(harness.endpoint.baseUrl).port;
  config.listen = `127.0.0.1:${endpointPort}`;
  config.provider_execution.allowed_base_url_origins = [new URL(providerProxy.baseUrl).origin];
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);
  await harness.endpoint.stop();
  const env = { ...process.env, NODE_ENV: "test" };
  for (const key of [
    "OPENCODE_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "MISTRAL_API_KEY",
    "TOGETHER_API_KEY",
    "XAI_API_KEY",
    "GROQ_API_KEY",
    "COHERE_API_KEY",
  ]) delete env[key];
  const rotated = await RealProcess.start({
    name: "endpoint",
    binary: process.env.ZODE_ENDPOINT_BIN || path.join(__dirname, "../../../target/debug/zode"),
    args: ["--config", configPath],
    cwd: path.resolve(__dirname, "../../.."),
    env,
    readyPrefix: "ZODE_READY ",
    ledger: harness.ledger,
    logDir: path.join(harness.runRoot, "logs", "endpoint-rotation"),
    startupCaptureRoot: path.join(harness.journal.rootDir, "endpoint-rotation-startup"),
    startupConfigBytes: Buffer.from(JSON.stringify(config)),
    e2eName,
  });
  harness.endpoint = rotated;
  await harness.endpointIdentity();
}

async function snapshotEndpointForReplay(harness) {
  await harness.endpoint.stop();
  const seedRoot = path.join(harness.runRoot, "endpoint-stale-replay-seed");
  fs.cpSync(path.join(harness.runRoot, "endpoint"), seedRoot, { recursive: true });
  harness.staleReplaySeedRoot = seedRoot;
}

test(E2E_NAME, async ({ browser, page }) => {
  test.setTimeout(180_000);
  const captureRequested = process.env.ZODE_CAPTURE_STALE_DESCRIPTOR === "1";
  if (!captureRequested) assertCassetteIdentity();
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-server",
  });
  const recordingDisabled = !captureRequested;
  if (recordingDisabled) {
    await harness.journal.waitForIdle();
    harness.journal.replayDepth += 1;
  }
  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  let captureSetId;
  let failureCaptureSetId;
  let endpointFailureCaptureSetId;
  let endpointSubject;
  let endpointControlProxy;
  let primaryError;
  try {
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 96 });
    endpointControlProxy = await startEndpointControlProxy(
      harness,
      () => endpointFailureCaptureSetId,
      () => endpointSubject,
    );
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "What do you want to work on?", exact: true }),
    ).toBeVisible();
    await addRemoteEndpoint(page, harness, endpointControlProxy.baseUrl);
    await configureProvider(page, harness);
    await createProfile(page, harness);
    const form = await openSessionForm(page);
    expect(new URL(page.url()).pathname).toBe("/");
    const execution = form.getByRole("button", { name: "Choose model and reasoning", exact: true });
    await expect(execution).toContainText(MODEL);

    await adminPage.goto(`${harness.managementUrl}/providers`, { waitUntil: "domcontentloaded" });
    await expect(adminPage.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
    await harness.journal.waitForIdle();
    harness.journal.flushCaptureSet(captureSetId);
    endpointFailureCaptureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 16 });
    failureCaptureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 48 });
    const rotatedProviderProxy = await startRotatedProviderProxy(harness);
    await snapshotEndpointForReplay(harness);
    await restartEndpointWithProviderOrigin(harness, rotatedProviderProxy, E2E_NAME);
    expect(new URL(page.url()).pathname).toBe("/");
    await advanceDescriptor(adminPage, harness, rotatedProviderProxy);
    expect(new URL(page.url()).pathname).toBe("/");
    const submit = form.getByRole("button", { name: "Start session", exact: true });
    await expect(submit).toBeEnabled({ timeout: 20_000 });
    const responsePromise = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        new URL(response.url()).pathname.includes("/sessions"),
    );
    await submit.click();
    const response = await responsePromise;
    expect(response.status()).toBe(400);
    const body = await response.json();
    expect(body.error.code).toBe("invalid_request");
    if (captureRequested) {
      await expect(page.getByRole("status")).toHaveText("Check the requested values and try again.");
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        status: response.status(),
        path: new URL(response.url()).pathname,
        observedNotice: "Check the requested values and try again.",
      });
    }

    await expect(page.getByRole("status")).toHaveText(
      "The provider configuration changed while this form was open. The latest selection is loaded; review it and try again.",
    );
    await expect(
      form.getByRole("button", { name: "Choose model and reasoning", exact: true }),
    ).toContainText(UPDATED_MODEL);
    const retryResponsePromise = page.waitForResponse(
      (candidate) =>
        candidate.request().method() === "POST" &&
        new URL(candidate.url()).pathname.includes("/sessions"),
    );
    await submit.click();
    expect((await retryResponsePromise).status()).toBe(201);
    await expect(page).toHaveURL(/\/endpoints\/[^/]+\/sessions\/[^/]+$/u);
    await expect(page.locator('[data-zode-session-identity="true"]')).toContainText(UPDATED_MODEL);
  } catch (error) {
    primaryError = error;
  } finally {
    await endpointControlProxy?.waitForIdle?.();
    await page.close().catch(() => undefined);
    if (recordingDisabled) harness.journal.replayDepth -= 1;
    try {
      if (captureRequested) {
        await harness.journal.waitForIdle();
      const records = recordsFor(harness, failureCaptureSetId);
      const firstFailure = records.find(
        (record) =>
          record.boundary === "management-access-edge" &&
          record.method === "POST" &&
          record.path.includes("/sessions") &&
          record.response?.status === 400,
      );
      if (!firstFailure) throw new Error("stale descriptor capture contained no 400 session-create exchange");
      const capture = harness.journal.flushCaptureSet(failureCaptureSetId, {
        firstFailureRecordingId: firstFailure.recordingId,
      });
      expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
      for (const record of records) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
      const endpointRecords = recordsFor(harness, endpointFailureCaptureSetId);
      endpointSubject = endpointRecords.find((record) => record.request_headers?.["zode-subject"])
        ?.request_headers?.["zode-subject"];
      if (!endpointSubject) throw new Error("stale descriptor control capture contained no endpoint subject");
      const endpointFailure = endpointRecords.find(
        (record) =>
          record.boundary === "server-endpoint-control" &&
          record.method === "POST" &&
          record.path === "/v1/sessions" &&
          record.response?.status === 422,
      );
      if (!endpointFailure) throw new Error("stale descriptor control capture contained no 422 session exchange");
      const endpointCapture = harness.journal.flushCaptureSet(endpointFailureCaptureSetId, {
        firstFailureRecordingId: endpointFailure.recordingId,
      });
      expect(endpointCapture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
      for (const record of endpointRecords) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
      if (captureRequested && primaryError?.classification === CLASSIFICATION) {
        let replayEndpoint;
        let promoted;
        try {
          replayEndpoint = await startReplayEndpoint(harness, harness.rotatedProviderProxy);
          endpointControlProxy.setTarget(replayEndpoint.baseUrl);
          endpointControlProxy.setReplayOnly(1);
          promoted = await harness.journal.promoteCaptureSet(endpointFailureCaptureSetId, {
            e2eName: E2E_NAME,
            classification: CLASSIFICATION,
            firstObserved: FIRST_OBSERVED,
            firstFailureRecordingId: endpointFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) =>
              harness.journal.replay(envelope, {
                baseUrl: endpointControlProxy.baseUrl,
                boundaryBaseUrls: {
                  "server-endpoint-control": endpointControlProxy.baseUrl,
                },
              }),
          });
        } finally {
          await replayEndpoint?.stop().catch(() => undefined);
          endpointControlProxy.setReplayOnly(0);
          endpointControlProxy.setTarget(harness.endpoint.baseUrl);
        }
        primaryError = new ProductBehaviorFailure(
          CLASSIFICATION,
          `${FIRST_OBSERVED}; cassette=${promoted.cassettePath}`,
          { captureSetId: endpointFailureCaptureSetId, recordingId: endpointFailure.recordingId },
        );
      }
      }
    } catch (captureError) {
      if (!primaryError) primaryError = captureError;
    }
    await adminContext.close().catch(() => undefined);
    await endpointControlProxy?.close().catch(() => undefined);
    await harness.rotatedProviderProxy?.close().catch(() => undefined);
    await harness.close().catch((error) => {
      primaryError ||= error;
    });
  }
  if (primaryError) throw primaryError;
});
