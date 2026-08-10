const fs = require("node:fs");
const path = require("node:path");
const { isDeepStrictEqual } = require("node:util");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  RealProcess,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require("../support/harness.cjs");
const {
  expectSelectedExecutionProfile,
  selectExecutionProfile,
} = require("../support/radix.cjs");

const E2E_NAME = "e2e_browser_bad_session_retains_history_and_offers_same_session_execution_recovery";
const CLASSIFICATION = "BAD_SESSION_SAME_SESSION_RECOVERY_MISSING";
const LATER_CLASSIFICATION = `${CLASSIFICATION}__later_test_reproduction_of_gap`;
const FIRST_OBSERVED =
  "an existing Endpoint-owned session retained its history after its selected auth profile was removed, but the real session page exposed no user-operable same-session provider/model/profile recovery entry";
const LATER_FIRST_OBSERVED = `relation=later_test_reproduction_of_gap; ${FIRST_OBSERVED}`;
const PROVIDER = "bad-session-recovery-fixture";
const MODEL = "bad-session-recovery-model";
const DECOY_PROVIDER = "aaa-bad-session-recovery-decoy";
const DECOY_MODEL = "aaa-bad-session-recovery-decoy-model";
const ENDPOINT_LABEL = "Bad session recovery Endpoint";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const CAPTURE_ENV = "ZODE_CAPTURE_BAD_SESSION_RECOVERY";
const SELECTION_CLASSIFICATION = "BAD_SESSION_RECOVERY_SELECTION_DIVERGED_FROM_CURRENT_EXECUTION";
const SELECTION_LATER_CLASSIFICATION = `${SELECTION_CLASSIFICATION}__later_test_reproduction_of_gap`;
const SELECTION_FIRST_OBSERVED =
  "a recovered Endpoint-owned session exposed its current provider, model, and profile, but the real browser recovery form selected a different execution after refresh";
const SELECTION_LATER_FIRST_OBSERVED =
  `relation=later_test_reproduction_of_gap; ${SELECTION_FIRST_OBSERVED}`;
const NOOP_DESCRIPTOR_CLASSIFICATION =
  "BAD_SESSION_RECOVERY_NOOP_REPLACED_CURRENT_EXECUTION_DESCRIPTOR";
const NOOP_DESCRIPTOR_FIRST_OBSERVED =
  "after the Server provider descriptor advanced without changing the visible provider, model, or profile, the real browser no-op Apply replaced the Endpoint-owned current execution descriptor";
const NOOP_DESCRIPTOR_LATER_CLASSIFICATION =
  `${NOOP_DESCRIPTOR_CLASSIFICATION}__later_test_reproduction_of_gap`;
const NOOP_DESCRIPTOR_LATER_FIRST_OBSERVED =
  `relation=later_test_reproduction_of_gap; ${NOOP_DESCRIPTOR_FIRST_OBSERVED}`;

function cassettesFor(classification) {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs
    .readdirSync(INCIDENT_DIRECTORY)
    .filter((name) => name.endsWith(".v1.json"))
    .map((name) => path.join(INCIDENT_DIRECTORY, name))
    .filter((candidate) => {
      try {
        const value = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return value.e2e_name === E2E_NAME && value.classification === classification;
      } catch {
        return false;
      }
    });
}

function assertCassetteIdentity() {
  const matches = cassettesFor(LATER_CLASSIFICATION);
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(fs.readFileSync(matches[0], "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.boundary).toBe("browser-capture-set");
  expect(cassette.e2e_name).toBe(E2E_NAME);
  expect(cassette.classification).toBe(LATER_CLASSIFICATION);
  expect(cassette.first_observed).toBe(LATER_FIRST_OBSERVED);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "GET" &&
    exchange.path.includes("/sessions/") &&
    exchange.response.status === 200,
  )).toBe(true);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "DELETE" &&
    exchange.path.includes("/auth-profiles/") &&
    exchange.response.status === 200,
  )).toBe(true);

  const selectionMatches = cassettesFor(SELECTION_LATER_CLASSIFICATION);
  expect(selectionMatches).toHaveLength(1);
  const selection = JSON.parse(fs.readFileSync(selectionMatches[0], "utf8"));
  expect(selection.schema).toBe("zode.http-incident-recording.v1");
  expect(selection.version).toBe(1);
  expect(selection.boundary).toBe("browser-capture-set");
  expect(selection.e2e_name).toBe(E2E_NAME);
  expect(selection.classification).toBe(SELECTION_LATER_CLASSIFICATION);
  expect(selection.first_observed).toBe(SELECTION_LATER_FIRST_OBSERVED);
  expect(selection.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(selection.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(selection.exchanges.map((exchange) => exchange.boundary)).toEqual([
    "management-access-edge",
    "server-endpoint-control",
  ]);

  const noopDescriptorMatches = cassettesFor(NOOP_DESCRIPTOR_LATER_CLASSIFICATION);
  expect(noopDescriptorMatches).toHaveLength(1);
  const noopDescriptor = JSON.parse(fs.readFileSync(noopDescriptorMatches[0], "utf8"));
  expect(noopDescriptor.schema).toBe("zode.http-incident-recording.v1");
  expect(noopDescriptor.version).toBe(1);
  expect(noopDescriptor.boundary).toBe("browser-capture-set");
  expect(noopDescriptor.e2e_name).toBe(E2E_NAME);
  expect(noopDescriptor.classification).toBe(NOOP_DESCRIPTOR_LATER_CLASSIFICATION);
  expect(noopDescriptor.first_observed).toBe(NOOP_DESCRIPTOR_LATER_FIRST_OBSERVED);
  expect(noopDescriptor.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(noopDescriptor.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(noopDescriptor.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "PUT" &&
    exchange.path.endsWith("/model") &&
    exchange.response.status === 202,
  )).toBe(true);
  expect(noopDescriptor.exchanges.every((exchange) =>
    exchange.boundary === "management-access-edge",
  )).toBe(true);
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

async function managementJson(page, method, requestPath, body) {
  return page.evaluate(async ({ method, requestPath, body }) => {
    const response = await fetch(requestPath, {
      method,
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "idempotency-key": `${method.toLowerCase()}-${crypto.randomUUID()}`,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }, { method, requestPath, body });
}

async function waitForProfileReady(page, provider, profileId, endpointId) {
  await expect.poll(async () => {
    const profiles = await managementJson(
      page,
      "GET",
      `/v1/providers/${encodeURIComponent(provider)}/auth-profiles`,
    );
    if (profiles.status !== 200) return false;
    const profile = profiles.body.items?.find(
      (candidate) =>
        candidate.auth_profile_id === profileId || candidate.profile_id === profileId,
    );
    const replica = profile?.distribution?.find(
      (candidate) => candidate.endpoint_id === endpointId,
    );
    return (
      profile?.status === "ready" &&
      replica?.status === "ready" &&
      replica.installed_revision !== null &&
      replica.installed_revision >= profile.revision
    );
  }, { timeout: 20_000 }).toBe(true);
}

async function mutableEndpointProxy(harness) {
  let target = harness.endpoint;
  let subject;
  let captureSetId;
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
      captureSetId: captureSetId ?? harness.journal.currentCaptureSetId,
      canonicalOrigin: target.baseUrl,
    }).catch((error) => {
      harness.journal._fail(error);
      if (!response.headersSent) response.writeHead(502, { "content-type": "application/json" });
      if (!response.writableEnded) response.end(JSON.stringify({
        error: { code: "endpoint_unavailable", retryable: true },
      }));
    });
  });
  return {
    proxy,
    setTarget(next) { target = next; },
    setCaptureSetId(next) { captureSetId = next; },
    async close() { await proxy.close(); },
  };
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
    logDir: path.join(harness.runRoot, "logs", "endpoint-selection-restart"),
    startupCaptureRoot: path.join(harness.journal.rootDir, "startup", "endpoint-selection-restart"),
    startupConfigBytes: fs.readFileSync(configPath),
    e2eName: E2E_NAME,
  });
}

async function assertRecoverySelection(page, trigger, expected) {
  try {
    await expectSelectedExecutionProfile(
      page,
      trigger,
      expected.model,
      expected.profileLabel,
    );
  } catch (error) {
    throw new ProductBehaviorFailure(
      SELECTION_CLASSIFICATION,
      SELECTION_FIRST_OBSERVED,
      {
        expected,
        cause: error instanceof Error ? error.message : String(error),
      },
    );
  }
}

async function preseedSession(page, harness, endpointBaseUrl) {
  const endpoint = await managementJson(page, "POST", "/v1/endpoints", {
    label: ENDPOINT_LABEL,
    base_url: endpointBaseUrl,
    control_auth: { kind: "bearer", secret: harness.controllerSecret },
  });
  expect(endpoint.status).toBe(201);
  const endpointId = endpoint.body.endpoint_id;

  const decoyProvider = await managementJson(page, "PUT", `/v1/providers/${DECOY_PROVIDER}`, {
    kind: "openai_compatible",
    base_url: `${harness.providerProxy.baseUrl}/v1`,
    models: [DECOY_MODEL],
    options: {},
  });
  expect(decoyProvider.status).toBe(200);
  const decoySecret = `${harness.providerSecret}-decoy`;
  const decoyProfile = await managementJson(
    page,
    "POST",
    `/v1/providers/${DECOY_PROVIDER}/auth-profiles`,
    {
      kind: "api_key",
      label: "Decoy session profile",
      api_key: decoySecret,
      make_default: true,
      sharing: { mode: "selected", endpoint_ids: [endpointId] },
    },
  );
  expect(decoyProfile.status).toBe(201);
  harness.ledger.add("decoy_profile", decoySecret);

  const provider = await managementJson(page, "PUT", `/v1/providers/${PROVIDER}`, {
    kind: "openai_compatible",
    base_url: `${harness.providerProxy.baseUrl}/v1`,
    models: [MODEL],
    options: {},
  });
  expect(provider.status).toBe(200);

  const first = await managementJson(page, "POST", `/v1/providers/${PROVIDER}/auth-profiles`, {
    kind: "api_key",
    label: "Retired session profile",
    api_key: harness.providerSecret,
    make_default: true,
    sharing: { mode: "selected", endpoint_ids: [endpointId] },
  });
  expect(first.status).toBe(201);
  const second = await managementJson(page, "POST", `/v1/providers/${PROVIDER}/auth-profiles`, {
    kind: "api_key",
    label: "Recovery session profile",
    api_key: `${harness.providerSecret}-recovery`,
    make_default: false,
    sharing: { mode: "selected", endpoint_ids: [endpointId] },
  });
  expect(second.status).toBe(201);
  harness.ledger.add("recovery_profile", `${harness.providerSecret}-recovery`);

  await Promise.all([
    waitForProfileReady(
      page,
      DECOY_PROVIDER,
      decoyProfile.body.auth_profile_id,
      endpointId,
    ),
    waitForProfileReady(page, PROVIDER, first.body.auth_profile_id, endpointId),
    waitForProfileReady(page, PROVIDER, second.body.auth_profile_id, endpointId),
  ]);

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
      auth_profile_id: first.body.auth_profile_id,
      minimum_auth_revision: first.body.revision,
    },
    tools: [],
  });
  expect(session.status).toBe(201);
  return {
    endpointId,
    sessionId: session.body.session_id,
    retiredProfileId: first.body.auth_profile_id,
    recoveryProfileId: second.body.auth_profile_id,
  };
}

test(E2E_NAME, async ({ page }) => {
  test.setTimeout(180_000);
  const captureRequested = process.env[CAPTURE_ENV] === "1";
  if (!captureRequested) assertCassetteIdentity();
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-bad-session-recovery",
  });
  const endpointProxy = await mutableEndpointProxy(harness);
  let captureSetId;
  let controlCaptureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { name: "What do you want to work on?", exact: true })).toBeVisible();
    const session = await preseedSession(page, harness, endpointProxy.proxy.baseUrl);
    await page.goto(
      `${harness.managementUrl}/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`,
      { waitUntil: "domcontentloaded" },
    );
    await expect(page.getByRole("button", { name: "Choose model", exact: true })).toBeVisible();
    const messagePath = `/v1/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}/messages`;
    const message = await managementJson(page, "POST", messagePath, {
      content: "history before execution recovery",
    });
    expect(message.status).toBe(202);
    await expect.poll(async () => page.evaluate(async (requestPath) => {
      const response = await fetch(requestPath, { headers: { accept: "application/json" } });
      if (!response.ok) return false;
      const body = await response.json();
      return body.transcript?.some((item) => item.content === "history before execution recovery") === true;
    }, `/v1/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`), {
      timeout: 20_000,
    }).toBe(true);
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 128 });
    const deleted = await page.evaluate(async ({ provider, profileId }) => {
      const response = await fetch(
        `/v1/providers/${encodeURIComponent(provider)}/auth-profiles/${encodeURIComponent(profileId)}`,
        {
          method: "DELETE",
          headers: { "Idempotency-Key": `bad-session-delete-${crypto.randomUUID()}` },
        },
      );
      return { status: response.status, body: await response.json() };
    }, { provider: PROVIDER, profileId: session.retiredProfileId });
    expect(deleted.status).toBe(200);

    try {
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.getByLabel("You").getByText("history before execution recovery", { exact: true })).toBeVisible();
      const trigger = page.getByRole("button", { name: "Choose execution", exact: true });
      await expect(trigger).toHaveAttribute("data-zode-execution-state", "needs-recovery");
      const modelResponse = page.waitForResponse((response) =>
        response.request().method() === "PUT" &&
        new URL(response.url()).pathname ===
          `/v1/endpoints/${session.endpointId}/sessions/${session.sessionId}/model`,
      );
      await selectExecutionProfile(page, trigger, MODEL, "Recovery session profile");
      expect((await modelResponse).status()).toBe(202);
      await expect(page.getByText("Execution updated. This session and its history were preserved.", { exact: true })).toBeVisible();
      const advancedDescriptor = await managementJson(page, "PUT", `/v1/providers/${PROVIDER}`, {
        kind: "openai_compatible",
        base_url: `${harness.providerProxy.baseUrl}/v1`,
        models: [MODEL],
        options: {},
      });
      expect(advancedDescriptor.status).toBe(200);
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.getByLabel("You").getByText("history before execution recovery", { exact: true })).toBeVisible();
      const currentTrigger = page.getByRole("button", { name: "Choose execution", exact: true });
      const sessionPath =
        `/v1/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`;
      const sessionUrl =
        `${harness.managementUrl}/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`;
      await assertRecoverySelection(page, currentTrigger, {
        provider: PROVIDER,
        model: MODEL,
        profileLabel: "Recovery session profile",
      });
      await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { name: "What do you want to work on?", exact: true })).toBeVisible();
      await page.goto("about:blank");
      await harness.journal.waitForIdle(15_000);
      harness.journal.flushCaptureSet(captureSetId);
      captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 8 });
      await page.goto(`${harness.managementUrl}${sessionPath}`, { waitUntil: "domcontentloaded" });
      const beforeNoop = await managementJson(page, "GET", sessionPath);
      expect(beforeNoop.status, "beforeNoop session read").toBe(200);
      expect(beforeNoop.body.session_id).toBe(session.sessionId);
      expect(advancedDescriptor.body.revision)
        .toBeGreaterThan(beforeNoop.body.model.provider_execution_revision);
      harness.journal.flushCaptureSet(captureSetId);
      controlCaptureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 16 });
      captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 128 });
      endpointProxy.setCaptureSetId(controlCaptureSetId);
      await page.goto(sessionUrl, { waitUntil: "domcontentloaded" });
      await expect(page.getByLabel("You").getByText("history before execution recovery", { exact: true })).toBeVisible();
      const recoveredTrigger = page.getByRole("button", { name: "Choose execution", exact: true });
      await selectExecutionProfile(page, recoveredTrigger, MODEL, "Recovery session profile");
      await expect(
        page.getByText("Session execution is already current. Existing history was preserved.", { exact: true }),
      ).toBeVisible();
      const afterNoop = await managementJson(page, "GET", sessionPath);
      expect(afterNoop.status, "afterNoop session read").toBe(200);
      expect(afterNoop.body.session_id).toBe(session.sessionId);
      await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { name: "What do you want to work on?", exact: true })).toBeVisible();
      await page.goto("about:blank");
      await harness.journal.waitForIdle(15_000);
      endpointProxy.setCaptureSetId(undefined);
      harness.journal.flushCaptureSet(controlCaptureSetId);
      controlCaptureSetId = undefined;
      if (!isDeepStrictEqual(afterNoop.body.model, beforeNoop.body.model)) {
        throw new ProductBehaviorFailure(
          NOOP_DESCRIPTOR_CLASSIFICATION,
          NOOP_DESCRIPTOR_FIRST_OBSERVED,
          {
            beforeRevision: beforeNoop.body.model.provider_execution_revision,
            afterRevision: afterNoop.body.model.provider_execution_revision,
            provider: beforeNoop.body.model.provider,
            model: beforeNoop.body.model.model,
            profileId: beforeNoop.body.model.auth_profile_id,
          },
        );
      }
      expect(afterNoop.body.transcript).toEqual(beforeNoop.body.transcript);
      await page.goto(sessionUrl, { waitUntil: "domcontentloaded" });
      await expect(page.getByLabel("You").getByText("history before execution recovery", { exact: true })).toBeVisible();
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.getByLabel("You").getByText("history before execution recovery", { exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Send", exact: true })).toBeEnabled({
        timeout: 30_000,
      });
      const messageInput = page.getByRole("textbox", { name: "Message", exact: true });
      await messageInput.fill("continue after execution recovery");
      await messageInput.press("Enter");
      await expect(page.getByText("E2E_OK", { exact: true })).toBeVisible({ timeout: 30_000 });
      await expect.poll(async () => page.evaluate(async (requestPath) => {
        const response = await fetch(requestPath, { headers: { accept: "application/json" } });
        if (!response.ok) return false;
        const body = await response.json();
        return body.transcript?.some((item) => item.role === "assistant" && item.content === "E2E_OK") === true;
      }, `/v1/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`), {
        timeout: 20_000,
      }).toBe(true);
      const beforeRestart = await managementJson(page, "GET", sessionPath);
      expect(beforeRestart.status, "beforeRestart session read").toBe(200);
      expect(beforeRestart.body.session_id).toBe(session.sessionId);
      await harness.restartServer();
      const restartedEndpoint = await restartEndpoint(harness);
      endpointProxy.setTarget(restartedEndpoint);
      harness.endpoint = restartedEndpoint;
      await harness.endpointIdentity();
      await page.goto(
        `${harness.managementUrl}/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`,
        { waitUntil: "domcontentloaded" },
      );
      await expect(page.getByText("continue after execution recovery", { exact: true })).toBeVisible();
      await expect(page.getByText("E2E_OK", { exact: true })).toHaveCount(2, { timeout: 20_000 });
      const restartedTrigger = page.getByRole("button", { name: "Choose execution", exact: true });
      await expect(restartedTrigger).toHaveAttribute("data-zode-execution-state", "needs-recovery");
      await assertRecoverySelection(page, restartedTrigger, {
        provider: PROVIDER,
        model: MODEL,
        profileLabel: "Recovery session profile",
      });
      const afterRestart = await managementJson(page, "GET", sessionPath);
      expect(afterRestart.status, "afterRestart session read").toBe(200);
      expect(afterRestart.body.session_id).toBe(session.sessionId);
      expect(afterRestart.body.model).toEqual(beforeRestart.body.model);
      expect(afterRestart.body.transcript).toEqual(beforeRestart.body.transcript);
      await harness.journal.waitForQuiescent(15_000);
    } catch (error) {
      if (error instanceof ProductBehaviorFailure) throw error;
      const cause = error instanceof Error ? error.message : String(error);
      const safeCause = harness.ledger.redact(cause);
      throw new ProductBehaviorFailure(CLASSIFICATION, `${FIRST_OBSERVED}; cause=${safeCause}`, {
        cause,
        sessionId: session.sessionId,
        endpointId: session.endpointId,
      });
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await page.close();
      await endpointProxy.close();
      await harness.server.stop();
      await harness.edge.close();
      await harness.journal.waitForIdle(15_000);
      endpointProxy.setCaptureSetId(undefined);
      if (controlCaptureSetId) harness.journal.flushCaptureSet(controlCaptureSetId);
      if (!captureSetId) {
        if (!primaryError) throw new Error("bad-session recovery capture was not armed");
        throw primaryError;
      }
      const records = recordsFor(harness, captureSetId);
      const firstFailure = primaryError?.classification === NOOP_DESCRIPTOR_CLASSIFICATION
        ? records.find((record) =>
            record.boundary === "management-access-edge" &&
            record.method === "PUT" &&
            record.path.endsWith("/model") &&
            record.response.status === 202,
          )
        : records.find((record) =>
            record.boundary === "management-access-edge" &&
            record.method === "GET" &&
            record.path.includes("/sessions/") &&
            record.response.status === 200,
          ) || records[0];
      if (!firstFailure) throw new Error("bad-session recovery capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        const promotion = primaryError.classification === CLASSIFICATION
          ? { classification: LATER_CLASSIFICATION, firstObserved: LATER_FIRST_OBSERVED }
          : primaryError.classification === SELECTION_CLASSIFICATION
            ? {
                classification: SELECTION_LATER_CLASSIFICATION,
                firstObserved: SELECTION_LATER_FIRST_OBSERVED,
              }
            : primaryError.classification === NOOP_DESCRIPTOR_CLASSIFICATION
              ? {
                  classification: NOOP_DESCRIPTOR_LATER_CLASSIFICATION,
                  firstObserved: NOOP_DESCRIPTOR_LATER_FIRST_OBSERVED,
                }
            : undefined;
        if (captureRequested && promotion) {
          const promoted = await harness.journal.promoteFlushedCaptureSet(captureSetId, {
            e2eName: E2E_NAME,
            classification: promotion.classification,
            firstObserved: promotion.firstObserved,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: harness.managementUrl,
              boundaryBaseUrls: {
                "management-access-edge": harness.managementUrl,
                "server-endpoint-control": endpointProxy.proxy.baseUrl,
              },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            primaryError.classification,
            `${promotion.firstObserved}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: firstFailure.recordingId },
          );
        }
      } else {
        harness.journal.flushCaptureSet(captureSetId);
      }
    } catch (captureError) {
      primaryError = captureError;
    }
    for (const resource of [harness.endpoint, harness.server, harness.edge, harness.callbackEdge]) {
      try {
        if (resource?.stop) await resource.stop();
        else if (resource?.close) await resource.close();
      } catch (resourceError) {
        primaryError ||= resourceError;
      }
    }
    try {
      await endpointProxy.close();
    } catch (proxyError) {
      primaryError ||= proxyError;
    }
    try {
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
  }
  if (primaryError) throw primaryError;
});
