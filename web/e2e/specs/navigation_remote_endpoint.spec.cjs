const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
} = require("../support/harness.cjs");

const INCIDENT_DIRECTORY = path.resolve(__dirname, "..", "fixtures", "incidents");
const CAPTURE_CASE_ENV = "ZODE_CAPTURE_NAVIGATION_ENDPOINT_CASE";
const REMOTE_LABEL = "Browser remote Endpoint";

const CASES = [
  {
    key: "navigation",
    e2eName: "e2e_browser_primary_navigation_uses_real_canonical_links",
    classification: "PRIMARY_NAVIGATION_LINKS_MISSING",
    firstObserved: "the rendered management shell exposed primary destinations as buttons without canonical href links",
  },
  {
    key: "remote-endpoint",
    e2eName: "e2e_browser_adds_remote_endpoint_through_server_catalog",
    classification: "REMOTE_ENDPOINT_BROWSER_ACTION_MISSING",
    firstObserved: "the rendered Endpoints destination had no Add remote Endpoint action or write-only catalog form",
  },
  {
    key: "endpoint-probe",
    e2eName: "e2e_browser_remote_endpoint_probe_reports_online_and_unreachable",
    classification: "REMOTE_ENDPOINT_PROBE_ACTION_MISSING__later_test_reproduction_of_gap",
    firstObserved: "relation=later_test_reproduction_of_gap; the preseeded remote Endpoint card had no bounded Server-initiated probe action or reachable-state result",
  },
];

function matchingCassettes(testCase) {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs
    .readdirSync(INCIDENT_DIRECTORY)
    .filter((name) => name.endsWith(".v1.json"))
    .map((name) => path.join(INCIDENT_DIRECTORY, name))
    .filter((candidate) => {
      try {
        const value = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return value.e2e_name === testCase.e2eName
          && value.classification === testCase.classification;
      } catch {
        return false;
      }
    });
}

function assertCassetteIdentity(testCase) {
  const matches = matchingCassettes(testCase);
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(fs.readFileSync(matches[0], "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.boundary).toBe("browser-capture-set");
  expect(cassette.first_observed).toBe(testCase.firstObserved);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges.length).toBeGreaterThan(0);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge"
      && exchange.method === "GET"
      && exchange.path === "/"
      && exchange.response.status === 200)).toBe(true);
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function firstPageRecord(records) {
  return records.find((record) =>
    record.boundary === "management-access-edge"
      && record.method === "GET"
      && record.path === "/") || records[0];
}

async function openShell(page, harness) {
  const response = await page.goto(`${harness.managementUrl}/`, {
    waitUntil: "domcontentloaded",
  });
  expect(response?.status()).toBe(200);
  await expect(
    page.getByRole("heading", { name: "What do you want to work on?", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("textbox", { name: "New session message", exact: true })).toBeVisible();
}

async function exerciseNavigation(page) {
  await expect(page.getByText("This machine", { exact: true }).first()).toBeVisible();
  const primary = page.getByRole("navigation", { name: "Primary", exact: true });
  const newSession = primary.getByRole("link", { name: "New session", exact: true });
  await expect(newSession).toHaveAttribute("href", "/");

  await page.getByRole("button", { name: "Manage Zode", exact: true }).click();
  const management = page.getByRole("menu", { name: "Manage Zode", exact: true });
  await expect(management.getByRole("menuitem")).toHaveCount(3);
  for (const [name, href] of [
    ["Endpoints", "/endpoints"],
    ["Providers", "/providers"],
    ["Settings", "/settings"],
  ]) {
    const item = management.getByRole("menuitem", { name, exact: true });
    await expect(item).toBeVisible();
    await expect(item).toHaveAttribute("href", href);
  }
  await management.getByRole("menuitem", { name: "Providers", exact: true }).click();
  await expect(page).toHaveURL(/\/providers$/u);
  await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
}

async function exerciseRemoteEndpoint(page, harness) {
  await openManagement(page, "Endpoints");
  await expect(page.getByRole("heading", { name: "Endpoints", exact: true })).toBeVisible();
  const trigger = page.getByRole("button", { name: "Add remote Endpoint", exact: true });
  await expect(trigger).toBeVisible();
  await trigger.click();
  const dialog = page.getByRole("dialog", { name: "Add remote Endpoint" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("textbox", { name: "Endpoint label" }).fill(REMOTE_LABEL);
  await dialog.getByRole("textbox", { name: "Endpoint URL" }).fill(harness.endpoint.baseUrl);
  const credential = dialog.getByRole("textbox", { name: "Controller credential" });
  await expect(credential).toHaveAttribute("type", "password");
  await credential.fill(harness.controllerSecret);
  await dialog.getByRole("button", { name: "Add Endpoint", exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("heading", { name: REMOTE_LABEL, exact: true })).toBeVisible();
}

async function exerciseEndpointProbe(page, harness) {
  const identity = await harness.endpointIdentity();
  await openManagement(page, "Endpoints");
  await expect(page).toHaveURL(/\/endpoints$/u);
  await expect(page.getByRole("heading", { name: "Endpoints", exact: true })).toBeVisible();
  const card = page.getByRole("article").filter({ hasText: REMOTE_LABEL });
  await expect(card).toBeVisible();
  const probe = card.getByRole("button", { name: "Refresh Endpoint status", exact: true });
  await expect(probe).toBeVisible();

  const onlineResponse = page.waitForResponse(
    (response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === `/v1/endpoints/${identity.endpoint_id}/probe`,
  );
  await probe.click();
  expect((await onlineResponse).status()).toBe(200);
  await expect(card).toContainText(/online|reachable/iu);

  await harness.endpoint.stop();
  const offlineResponse = page.waitForResponse(
    (response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === `/v1/endpoints/${identity.endpoint_id}/probe`,
  );
  await probe.click();
  const response = await offlineResponse;
  expect(response.status()).toBe(503);
  expect((await response.json()).error.code).toBe("endpoint_unavailable");
  await expect(card).toContainText(/unreachable/iu);
  await expect(page.getByText(/non-authoritative/iu)).toBeVisible();
}

async function openManagement(page, name) {
  const switcher = page.getByRole("menu", { name: "Manage Zode", exact: true });
  if (!(await switcher.isVisible())) {
    await page.getByRole("button", { name: "Manage Zode", exact: true }).click();
  }
  await page.getByRole("menu", { name: "Manage Zode", exact: true })
    .getByRole("menuitem", { name, exact: true }).click();
}

async function preseedRemoteEndpoint(harness) {
  const response = await fetch(`${harness.managementUrl}/v1/endpoints`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": `navigation-probe-preseed-${crypto.randomUUID()}`,
    },
    body: JSON.stringify({
      label: REMOTE_LABEL,
      base_url: harness.endpoint.baseUrl,
      control_auth: { kind: "bearer", secret: harness.controllerSecret },
    }),
  });
  const body = await response.json();
  expect(response.status).toBe(201);
  expect(body.endpoint_id).toEqual(expect.any(String));
  return body;
}

async function runCase(page, testCase) {
  const captureRequested = process.env[CAPTURE_CASE_ENV] === testCase.key;
  if (!captureRequested) assertCassetteIdentity(testCase);
  const harness = await createWebE2EHarness({
    e2eName: testCase.e2eName,
    uiMode: "assets",
    includeServerOrigins: true,
  });
  if (testCase.key === "endpoint-probe") await preseedRemoteEndpoint(harness);
  const captureSetId = harness.beginCaptureSet({ e2eName: testCase.e2eName, maxMembers: 32 });
  let primaryError;
  try {
    await openShell(page, harness);
    try {
      if (testCase.key === "navigation") await exerciseNavigation(page);
      else if (testCase.key === "endpoint-probe") await exerciseEndpointProbe(page, harness);
      else await exerciseRemoteEndpoint(page, harness);
    } catch (error) {
      throw new ProductBehaviorFailure(
        testCase.classification,
        testCase.firstObserved,
        { cause: error instanceof Error ? error.message : String(error) },
      );
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      if (!page.isClosed()) await page.close();
      await harness.journal.waitForIdle();
      const records = recordsFor(harness, captureSetId);
      const firstFailure = firstPageRecord(records);
      if (!firstFailure) throw new Error("armed navigation capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) {
          expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        }
        if (captureRequested && primaryError.classification === testCase.classification) {
          const promoted = await harness.journal.promoteFlushedCaptureSet(captureSetId, {
            e2eName: testCase.e2eName,
            classification: testCase.classification,
            firstObserved: testCase.firstObserved,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: harness.managementUrl,
              boundaryBaseUrls: { "management-access-edge": harness.managementUrl },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            testCase.classification,
            `${primaryError.message}; cassette=${promoted.cassettePath}`,
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
}

for (const testCase of CASES) {
  test(testCase.e2eName, async ({ page }) => {
    test.setTimeout(120_000);
    await runCase(page, testCase);
  });
}
