const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  RealProcess,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require("../support/harness.cjs");
const {
  closeExecutionChoices,
  expectSelectedExecutionProfile,
  openExecutionChoices,
  selectExecutionProfile,
} = require("../support/radix.cjs");

const E2E_NAME =
  "e2e_browser_session_execution_selection_preserves_current_defaults_history_and_identity";
const PRIMARY_PROVIDER = "goal3-primary-provider";
const PRIMARY_MODEL = "goal3-primary-model";
const DECOY_PROVIDER = "aaa-goal3-decoy-provider";
const DECOY_MODEL = "aaa-goal3-decoy-model";

async function managementJson(page, method, requestPath, body) {
  return page.evaluate(async ({ method, requestPath, body }) => {
    const headers = {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    };
    if (method !== "GET") headers["idempotency-key"] = `${method.toLowerCase()}-${crypto.randomUUID()}`;
    const response = await fetch(requestPath, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: response.status, json, text };
  }, { method, requestPath, body });
}

async function mutableEndpointProxy(harness) {
  let target = harness.endpoint;
  let subject;
  const proxy = await startHttpServer((request, response) => {
    subject = request.headers["zode-subject"] || subject;
    return proxyHttp({
      targetBaseUrl: target.baseUrl,
      request,
      response,
      extraHeaders: {
        authorization: `Bearer ${harness.controllerSecret}`,
        ...(subject ? { "zode-subject": subject } : {}),
      },
      boundary: "server-endpoint-control",
      journal: harness.journal,
      ledger: harness.ledger,
      captureSetId: harness.journal.currentCaptureSetId,
      canonicalOrigin: target.baseUrl,
    }).catch((error) => {
      harness.journal._fail(error);
      if (!response.headersSent) response.writeHead(502, { "content-type": "application/json" });
      if (!response.writableEnded) {
        response.end(JSON.stringify({ error: { code: "endpoint_unavailable", retryable: true } }));
      }
    });
  });
  return {
    proxy,
    get baseUrl() {
      return proxy.baseUrl;
    },
    setTarget(next) {
      target = next;
    },
    async close() {
      await proxy.close();
    },
  };
}

async function replaceManagementEdgeWithProfileFailure(harness, provider) {
  const previousEdge = harness.edge;
  const failingPath = `/v1/providers/${provider}/auth-profiles`;
  const edge = await startHttpServer(async (request, response) => {
    if (request.method === "GET" && request.url === failingPath) {
      const body = Buffer.from(
        JSON.stringify({
          error: {
            code: "provider_unavailable",
            message: "Provider profile inventory is unavailable",
            retryable: true,
          },
        }),
      );
      harness.journal.record({
        boundary: "management-access-edge",
        method: request.method,
        requestPath: request.url,
        requestHeaders: request.headers,
        requestBody: Buffer.alloc(0),
        responseStatus: 503,
        responseHeaders: { "content-type": "application/json" },
        responseChunks: [{ data: body, offsetUs: 0 }],
        captureSetId: harness.journal.currentCaptureSetId,
      });
      response.writeHead(503, { "content-type": "application/json" });
      response.end(body);
      return;
    }
    return proxyHttp({
      targetBaseUrl: harness.server.baseUrl,
      request,
      response,
      extraHeaders: { "cf-access-jwt-assertion": harness.access.issue() },
      boundary: "management-access-edge",
      journal: harness.journal,
      ledger: harness.ledger,
      captureSetId: harness.journal.currentCaptureSetId,
      canonicalOrigin: harness.managementOrigin,
    });
  });
  harness.edge = edge;
  await previousEdge.close();
  return edge;
}

async function restartEndpoint(harness) {
  await harness.endpoint.stop();
  const configPath = path.join(harness.runRoot, "endpoint", "endpoint-config.json");
  const binary = process.env.ZODE_ENDPOINT_BIN || path.resolve(__dirname, "../../../target/debug/zode");
  return RealProcess.start({
    name: "endpoint",
    binary,
    args: ["--config", configPath],
    cwd: path.resolve(__dirname, "../../.."),
    env: { ...process.env, NODE_ENV: "test" },
    readyPrefix: "ZODE_READY ",
    ledger: harness.ledger,
    logDir: path.join(harness.runRoot, "logs", "endpoint-goal3-restart"),
    startupCaptureRoot: path.join(harness.journal.rootDir, "startup", "endpoint-goal3-restart"),
    startupConfigBytes: fs.readFileSync(configPath),
    e2eName: E2E_NAME,
  });
}

async function waitForTranscript(page, sessionPath, content) {
  await expect
    .poll(
      async () => {
        const result = await managementJson(page, "GET", sessionPath);
        return result.status === 200 &&
          result.json?.transcript?.some((message) => message.content === content) === true;
      },
      { timeout: 20_000 },
    )
    .toBe(true);
}

async function seedSession(page, harness, endpointBaseUrl) {
  const endpoint = await managementJson(page, "POST", "/v1/endpoints", {
    label: "Goal 3 recovery Endpoint",
    base_url: endpointBaseUrl,
    control_auth: { kind: "bearer", secret: harness.controllerSecret },
  });
  expect(endpoint.status).toBe(201);

  const descriptor = {
    kind: "openai_compatible",
    base_url: `${harness.providerProxy.baseUrl}/v1`,
    models: [PRIMARY_MODEL],
    options: {},
  };
  const decoyDescriptor = {
    kind: "openai_compatible",
    base_url: `${harness.providerProxy.baseUrl}/v1`,
    models: [DECOY_MODEL],
    options: {},
  };
  const primaryProvider = await managementJson(
    page,
    "PUT",
    `/v1/providers/${PRIMARY_PROVIDER}`,
    descriptor,
  );
  const decoyProvider = await managementJson(
    page,
    "PUT",
    `/v1/providers/${DECOY_PROVIDER}`,
    decoyDescriptor,
  );
  expect(primaryProvider.status).toBe(200);
  expect(decoyProvider.status).toBe(200);

  const endpointId = endpoint.json.endpoint_id;
  const oldSecret = harness.providerSecret;
  const recoverySecret = `${harness.providerSecret}-goal3-recovery`;
  const decoySecret = `${harness.providerSecret}-goal3-decoy`;
  harness.ledger.add("goal3_recovery_secret", recoverySecret);
  harness.ledger.add("goal3_decoy_secret", decoySecret);
  const oldProfile = await managementJson(
    page,
    "POST",
    `/v1/providers/${PRIMARY_PROVIDER}/auth-profiles`,
    {
      kind: "api_key",
      label: "Goal 3 retired profile",
      api_key: oldSecret,
      make_default: true,
      sharing: { mode: "selected", endpoint_ids: [endpointId] },
    },
  );
  const recoveryProfile = await managementJson(
    page,
    "POST",
    `/v1/providers/${PRIMARY_PROVIDER}/auth-profiles`,
    {
      kind: "api_key",
      label: "Goal 3 recovery profile",
      api_key: recoverySecret,
      make_default: false,
      sharing: { mode: "selected", endpoint_ids: [endpointId] },
    },
  );
  const decoyProfile = await managementJson(
    page,
    "POST",
    `/v1/providers/${DECOY_PROVIDER}/auth-profiles`,
    {
      kind: "api_key",
      label: "Goal 3 decoy profile",
      api_key: decoySecret,
      make_default: true,
      sharing: { mode: "selected", endpoint_ids: [endpointId] },
    },
  );
  expect(oldProfile.status).toBe(201);
  expect(recoveryProfile.status).toBe(201);
  expect(decoyProfile.status).toBe(201);

  const session = await managementJson(page, "POST", `/v1/endpoints/${endpointId}/sessions`, {
    model: {
      provider: PRIMARY_PROVIDER,
      model: PRIMARY_MODEL,
      provider_execution: {
        schema: "zode.provider-execution.v1",
        revision: primaryProvider.json.revision,
        kind: primaryProvider.json.kind,
        base_url: primaryProvider.json.base_url,
        options: primaryProvider.json.options,
      },
      auth_profile_id: oldProfile.json.auth_profile_id,
      minimum_auth_revision: oldProfile.json.revision,
    },
    tools: [],
  });
  expect(session.status).toBe(201);
  return {
    endpointId,
    sessionId: session.json.session_id,
    oldProfileId: oldProfile.json.auth_profile_id,
    recoveryProfileId: recoveryProfile.json.auth_profile_id,
    decoyProfileId: decoyProfile.json.auth_profile_id,
  };
}

test(E2E_NAME, async ({ page }) => {
  test.setTimeout(180_000);
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-goal3-recovery",
  });
  const endpointProxy = await mutableEndpointProxy(harness);
  const captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 256 });
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "What do you want to work on?", exact: true })).toBeVisible();
    const session = await seedSession(page, harness, endpointProxy.baseUrl);
    const sessionPath = `/v1/endpoints/${session.endpointId}/sessions/${session.sessionId}`;
    const sessionUrl = () =>
      `${harness.managementUrl}/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`;
    const history = "history before execution recovery";
    const message = await managementJson(page, "POST", `${sessionPath}/messages`, { content: history });
    expect(message.status).toBe(202);
    await waitForTranscript(page, sessionPath, history);

    await page.goto(sessionUrl(), { waitUntil: "domcontentloaded" });
    await expect(page.getByLabel("You").getByText(history, { exact: true })).toBeVisible();
    const trigger = page.getByRole("button", { name: "Choose model", exact: true });
    await expect(trigger).toHaveAttribute("data-zode-execution-state", "ready");
    await expectSelectedExecutionProfile(
      page,
      trigger,
      PRIMARY_MODEL,
      "Goal 3 retired profile",
    );
    await openExecutionChoices(page, trigger, DECOY_MODEL);
    await closeExecutionChoices(page);
    await expectSelectedExecutionProfile(
      page,
      trigger,
      PRIMARY_MODEL,
      "Goal 3 retired profile",
    );
    const firstApply = page.waitForResponse(
      (response) =>
        response.request().method() === "PUT" &&
        new URL(response.url()).pathname === `${sessionPath}/model`,
    );
    await selectExecutionProfile(page, trigger, DECOY_MODEL, "Goal 3 decoy profile");
    expect((await firstApply).status()).toBe(202);
    await expect(
      page.getByText("Execution updated. This session and its history were preserved.", { exact: true }),
    ).toBeVisible();

    const beforeNoop = await managementJson(page, "GET", sessionPath);
    expect(beforeNoop.status).toBe(200);
    expect(beforeNoop.json.session_id).toBe(session.sessionId);
    expect(beforeNoop.json.transcript.some((message) => message.content === history)).toBe(true);
    let noOpModelUpdates = 0;
    page.on("request", (request) => {
      if (
        request.method() === "PUT" &&
        new URL(request.url()).pathname === `${sessionPath}/model`
      ) {
        noOpModelUpdates += 1;
      }
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByLabel("You").getByText(history, { exact: true })).toBeVisible();
    const currentExecution = page.getByRole("button", { name: "Choose model", exact: true });
    await expectSelectedExecutionProfile(
      page,
      currentExecution,
      DECOY_MODEL,
      "Goal 3 decoy profile",
    );
    await selectExecutionProfile(page, currentExecution, DECOY_MODEL, "Goal 3 decoy profile");
    await expect(
      page.getByText("Session execution is already current. Existing history was preserved.", { exact: true }),
    ).toBeVisible();
    expect(noOpModelUpdates).toBe(0);
    const afterNoop = await managementJson(page, "GET", sessionPath);
    expect(afterNoop.json.session_id).toBe(beforeNoop.json.session_id);
    expect(afterNoop.json.model).toEqual(beforeNoop.json.model);
    expect(afterNoop.json.transcript).toEqual(beforeNoop.json.transcript);

    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    const composer = page.getByRole("textbox", { name: "Message", exact: true });
    await composer.fill("continue after execution recovery");
    await composer.press("Enter");
    await expect(page.getByText("E2E_OK", { exact: true })).toBeVisible({ timeout: 30_000 });
    await waitForTranscript(page, sessionPath, "continue after execution recovery");
    const beforeRestart = await managementJson(page, "GET", sessionPath);

    await harness.restartServer();
    const restartedEndpoint = await restartEndpoint(harness);
    endpointProxy.setTarget(restartedEndpoint);
    harness.endpoint = restartedEndpoint;
    await harness.endpointIdentity();
    await page.goto(sessionUrl(), { waitUntil: "domcontentloaded" });
    await expect(page.getByLabel("You").getByText(history, { exact: true })).toBeVisible();
    await expect(
      page.getByLabel("You").getByText("continue after execution recovery", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText("E2E_OK", { exact: true })).toHaveCount(2, { timeout: 30_000 });
    await expectSelectedExecutionProfile(
      page,
      page.getByRole("button", { name: "Choose model", exact: true }),
      DECOY_MODEL,
      "Goal 3 decoy profile",
    );
    const afterRestart = await managementJson(page, "GET", sessionPath);
    expect(afterRestart.status, afterRestart.text).toBe(200);
    expect(afterRestart.json.session_id).toBe(beforeRestart.json.session_id);
    expect(afterRestart.json.model).toEqual(beforeRestart.json.model);
    expect(afterRestart.json.transcript).toEqual(beforeRestart.json.transcript);

    await replaceManagementEdgeWithProfileFailure(harness, DECOY_PROVIDER);
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByText("Auth profiles are unavailable. Try again from Manage.", { exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Start session", exact: true })).toBeDisabled();

    await page.goto(sessionUrl(), { waitUntil: "domcontentloaded" });
    await expect(page.getByLabel("You").getByText(history, { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeDisabled();
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await page.close();
      await harness.journal.waitForIdle(15_000);
      harness.journal.flushCaptureSet(captureSetId);
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
    try {
      await endpointProxy.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
    try {
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
  }
  if (primaryError) throw primaryError;
});
