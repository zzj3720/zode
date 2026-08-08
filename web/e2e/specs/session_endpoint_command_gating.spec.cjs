const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
} = require("../support/harness.cjs");

const E2E_NAME = "e2e_browser_endpoint_unavailable_disables_new_session_command";
const CLASSIFICATION = "ENDPOINT_UNAVAILABLE_SESSION_COMMAND_ENABLED";
const FIRST_OBSERVED =
  "the real Endpoint stopped responding, but the Sessions page kept the New session command enabled instead of disabling commands for an unavailable Endpoint";
const PROVIDER = "session-command-gating-fixture";
const MODEL = "session-command-gating-model";
const ENDPOINT_LABEL = "Command gating Endpoint";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const CAPTURE_ENV = "ZODE_CAPTURE_ENDPOINT_COMMAND_GATING";

function matchingCassettes() {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs.readdirSync(INCIDENT_DIRECTORY)
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
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge"
      && exchange.method === "GET"
      && exchange.path.includes("/sessions")
      && exchange.response.status === 503)).toBe(true);
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
  const profile = await managementJson(page, "POST", `/v1/providers/${PROVIDER}/auth-profiles`, {
    kind: "api_key",
    label: "Command gating profile",
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
  if (process.env[CAPTURE_ENV] !== "1") assertCassetteIdentity();
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-endpoint-command-gating",
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
    const session = await preseedSession(page, harness);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByRole("link", { name: new RegExp(session.sessionId) })).toBeVisible();
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 32 });
    await harness.endpoint.stop();
    try {
      await page.reload({ waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "New session", exact: true })).toBeDisabled();
    } catch (error) {
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        cause: error instanceof Error ? error.message : String(error),
      });
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await harness.journal.waitForIdle();
      const records = recordsFor(harness, captureSetId);
      const firstFailure = records.find((record) =>
        record.boundary === "management-access-edge"
          && record.path.includes("/sessions")
          && record.response.status === 503) || records[0];
      if (!firstFailure) throw new Error("command-gating capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) {
          expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        }
        if (process.env[CAPTURE_ENV] === "1" && primaryError.classification === CLASSIFICATION) {
          const promoted = await harness.journal.promoteFlushedCaptureSet(captureSetId, {
            e2eName: E2E_NAME,
            classification: CLASSIFICATION,
            firstObserved: FIRST_OBSERVED,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: harness.managementUrl,
              boundaryBaseUrls: { "management-access-edge": harness.managementUrl },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            CLASSIFICATION,
            `${FIRST_OBSERVED}; cassette=${promoted.cassettePath}`,
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
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
  }
  if (primaryError) throw primaryError;
});
