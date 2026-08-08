const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
} = require("../support/harness.cjs");

const E2E_NAME = "e2e_browser_bad_session_retains_history_and_offers_same_session_execution_recovery";
const CLASSIFICATION = "BAD_SESSION_SAME_SESSION_RECOVERY_MISSING";
const LATER_CLASSIFICATION = `${CLASSIFICATION}__later_test_reproduction_of_gap`;
const FIRST_OBSERVED =
  "an existing Endpoint-owned session retained its history after its selected auth profile was removed, but the real session page exposed no user-operable same-session provider/model/profile recovery entry";
const LATER_FIRST_OBSERVED = `relation=later_test_reproduction_of_gap; ${FIRST_OBSERVED}`;
const PROVIDER = "bad-session-recovery-fixture";
const MODEL = "bad-session-recovery-model";
const ENDPOINT_LABEL = "Bad session recovery Endpoint";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const CAPTURE_ENV = "ZODE_CAPTURE_BAD_SESSION_RECOVERY";

function matchingCassettes() {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs
    .readdirSync(INCIDENT_DIRECTORY)
    .filter((name) => name.endsWith(".v1.json"))
    .map((name) => path.join(INCIDENT_DIRECTORY, name))
    .filter((candidate) => {
      try {
        const value = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return value.e2e_name === E2E_NAME && value.classification === LATER_CLASSIFICATION;
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

async function preseedSession(page, harness) {
  const endpoint = await managementJson(page, "POST", "/v1/endpoints", {
    label: ENDPOINT_LABEL,
    base_url: harness.endpoint.baseUrl,
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
  await page.addInitScript(() => {
    const NativeEventSource = window.__zodeNativeEventSource || window.EventSource;
    window.__zodeNativeEventSource = NativeEventSource;
    const sources = [];
    window.__zodeBadSessionEventSources = sources;
    if (window.localStorage.getItem("zode-bad-session-disable-event-source") === "1") {
      window.EventSource = class extends EventTarget {
        constructor() {
          super();
          this.readyState = 2;
          this.url = "";
          this.withCredentials = false;
        }
        close() {}
      };
    } else {
      window.EventSource = class extends NativeEventSource {
        constructor(...args) {
          super(...args);
          sources.push(this);
        }
      };
    }
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
    const session = await preseedSession(page, harness);
    await page.goto(
      `${harness.managementUrl}/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`,
      { waitUntil: "domcontentloaded" },
    );
    await expect(page.getByRole("heading", { name: MODEL, exact: true })).toBeVisible();
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
    await page.evaluate(() => {
      window.localStorage.setItem("zode-bad-session-disable-event-source", "1");
      for (const source of window.__zodeBadSessionEventSources || []) source.close();
    });
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 64 });

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
      await expect(page.getByRole("heading", { name: MODEL, exact: true })).toBeVisible();
      await expect(page.getByText("history before execution recovery", { exact: true })).toBeVisible();
      const recovery = page.locator("form.session-execution-recovery");
      await expect(recovery.getByRole("heading", { name: "Recover session execution", exact: true })).toBeVisible();
      await recovery.getByLabel("Auth profile").selectOption({ label: "Recovery session profile" });
      const modelResponse = page.waitForResponse((response) =>
        response.request().method() === "PUT" &&
        new URL(response.url()).pathname ===
          `/v1/endpoints/${session.endpointId}/sessions/${session.sessionId}/model`,
      );
      await recovery.getByRole("button", { name: "Apply execution", exact: true }).click();
      expect((await modelResponse).status()).toBe(202);
      await expect(page.getByText("Session execution updated. Existing history was preserved.", { exact: true })).toBeVisible();
      await page.evaluate(() => window.localStorage.removeItem("zode-bad-session-disable-event-source"));
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { name: MODEL, exact: true })).toBeVisible();
      await expect(
        page.locator("form.session-execution-recovery").getByLabel("Auth profile").locator("option:checked"),
      ).toHaveText("Recovery session profile");
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
      await harness.restartServer();
      await page.goto(
        `${harness.managementUrl}/endpoints/${encodeURIComponent(session.endpointId)}/sessions/${encodeURIComponent(session.sessionId)}`,
        { waitUntil: "domcontentloaded" },
      );
      await expect(page.getByText("continue after execution recovery", { exact: true })).toBeVisible();
      await expect(page.getByText("E2E_OK", { exact: true })).toHaveCount(2, { timeout: 20_000 });
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        cause,
        sessionId: session.sessionId,
        endpointId: session.endpointId,
      });
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await page.evaluate(() => {
        for (const source of window.__zodeBadSessionEventSources || []) source.close();
      });
      await harness.journal.waitForIdle(15_000);
      const records = recordsFor(harness, captureSetId);
      const firstFailure = records.find((record) =>
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
        if (captureRequested && primaryError.classification === CLASSIFICATION) {
          const promoted = await harness.journal.promoteFlushedCaptureSet(captureSetId, {
            e2eName: E2E_NAME,
            classification: LATER_CLASSIFICATION,
            firstObserved: LATER_FIRST_OBSERVED,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: harness.managementUrl,
              boundaryBaseUrls: { "management-access-edge": harness.managementUrl },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            CLASSIFICATION,
            `${LATER_FIRST_OBSERVED}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: firstFailure.recordingId },
          );
        }
      } else {
        harness.journal.flushCaptureSet(captureSetId);
      }
    } catch (captureError) {
      primaryError = captureError;
    }
    try {
      await page.close();
    } catch (pageError) {
      primaryError ||= pageError;
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
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
  }
  if (primaryError) throw primaryError;
});
