const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
} = require("../support/harness.cjs");
const { openExecutionChoices } = require("../support/radix.cjs");

const E2E_NAME = "e2e_browser_unshared_profile_is_not_offered_for_endpoint_session";
const CLASSIFICATION = "UNSHARED_PROFILE_OFFERED_FOR_ENDPOINT_SESSION";
const FIRST_OBSERVED =
  "an API-key profile with sharing mode none was offered by the session selector for a remote Endpoint, so the browser could submit a profile the Endpoint was not allowed to receive";
const PROVIDER = "profile-sharing-session-fixture";
const MODEL = "profile-sharing-session-model";
const ENDPOINT_LABEL = "Session sharing Endpoint";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const INCIDENT_CASSETTE = path.join(
  INCIDENT_DIRECTORY,
  "0002-5c387b0b-f64e-43ec-965c-6d96613b4571-1954e9d1-a7e3-46c2-9b8a-13c88c3a81d4.v1.json",
);

function assertCassetteIdentity() {
  const cassette = JSON.parse(fs.readFileSync(INCIDENT_CASSETTE, "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.e2e_name).toBe(E2E_NAME);
  expect(cassette.classification).toBe(CLASSIFICATION);
  expect(cassette.first_observed).toBe(FIRST_OBSERVED);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges).toHaveLength(2);
  expect(cassette.exchanges[0]).toMatchObject({
    boundary: "management-access-edge",
    method: "GET",
    path: "/v1/providers",
    response: { status: 200 },
  });
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function firstPublicRecord(records) {
  return records.find((record) =>
    record.boundary === "management-access-edge"
      && record.method === "GET"
      && record.path === "/v1/providers") || records[0];
}

async function configureProvider(page, harness) {
  await openManagement(page, "Providers");
  await page.getByRole("button", { name: "Configure provider", exact: true }).click();
  const form = page.locator("form.editor-panel").filter({ hasText: "Configure provider" });
  await form.getByLabel("Provider ID").fill(PROVIDER);
  await form.getByLabel("Base URL").fill(`${harness.providerProxy.baseUrl}/v1`);
  await form.getByLabel("Models").fill(MODEL);
  await Promise.all([
    page.waitForResponse((response) =>
      response.request().method() === "PUT"
        && new URL(response.url()).pathname === `/v1/providers/${PROVIDER}`),
    form.getByRole("button", { name: "Save provider", exact: true }).click(),
  ]);
  await expect(form).toBeHidden();
}

async function addRemoteEndpoint(page, harness) {
  await openManagement(page, "Endpoints");
  await page.getByRole("button", { name: "Add remote Endpoint", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add remote Endpoint" });
  await dialog.getByLabel("Endpoint label").fill(ENDPOINT_LABEL);
  await dialog.getByLabel("Endpoint URL").fill(harness.endpoint.baseUrl);
  await dialog.getByLabel("Controller credential").fill(harness.controllerSecret);
  await Promise.all([
    page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/endpoints"),
    dialog.getByRole("button", { name: "Add Endpoint", exact: true }).click(),
  ]);
  await expect(dialog).toBeHidden();
}

async function createProfile(page, harness, label, makeDefault, shareEndpoint) {
  await openManagement(page, "Providers");
  const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
  await card.getByRole("button", { name: "Add API key profile", exact: true }).click();
  const form = card.locator("form.nested-editor");
  await form.getByLabel("Profile label").fill(label);
  const secret = `${harness.providerSecret}-${label.replaceAll(" ", "-")}`;
  harness.ledger.add(`session_${label.toLowerCase().replaceAll(" ", "_")}`, secret);
  await form.getByLabel("API key").fill(secret);
  if (shareEndpoint) {
    await form.getByRole("checkbox", { name: `Share with ${ENDPOINT_LABEL}`, exact: true }).check();
  }
  const defaultControl = form.getByRole("checkbox", { name: "Make this the default profile", exact: true });
  await defaultControl.setChecked(makeDefault);
  const [response] = await Promise.all([
    page.waitForResponse((candidate) =>
      candidate.request().method() === "POST"
        && new URL(candidate.url()).pathname === `/v1/providers/${PROVIDER}/auth-profiles`),
    form.getByRole("button", { name: "Create profile", exact: true }).click(),
  ]);
  if (response.status() !== 201) throw new Error(`profile create returned ${response.status()}`);
  const created = await response.json();
  await expect(form).toBeHidden();
  return created;
}

async function openManagement(page, name) {
  const settingsLink = page.getByRole("link", { name, exact: true });
  if (await settingsLink.isVisible()) {
    await settingsLink.click();
    return;
  }
  let link = page.getByRole("menuitem", { name, exact: true });
  if (!(await link.isVisible())) {
    await page.getByRole("button", { name: "Manage Zode", exact: true }).click();
    link = page.getByRole("menuitem", { name, exact: true });
  }
  await link.click();
}

async function armProviderRead(page) {
  await page.evaluate(async () => {
    const response = await fetch("/v1/providers", { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`provider read returned ${response.status}`);
    await response.text();
  });
}

test(E2E_NAME, async ({ page }) => {
  test.setTimeout(180_000);
  if (process.env.ZODE_CAPTURE_PROFILE_SHARING_SESSION !== "1") assertCassetteIdentity();
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-server",
  });
  let captureSetId;
  let primaryError;
  try {
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "What do you want to work on?", exact: true })).toBeVisible();
    await addRemoteEndpoint(page, harness);
    await configureProvider(page, harness);
    const sharedProfile = await createProfile(page, harness, "Shared profile", true, true);
    const unsharedProfile = await createProfile(page, harness, "Unshared profile", false, false);
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 24 });
    await armProviderRead(page);
    try {
      await page.getByRole("navigation", { name: "Primary", exact: true })
        .getByRole("link", { name: "New session", exact: true }).click();
      const form = page.locator("form#home-session-composer");
      await expect(
        form.getByRole("combobox", { name: "Environment", exact: true }),
      ).toContainText(ENDPOINT_LABEL);
      const selectedModel = await openExecutionChoices(
        page,
        form.getByRole("button", { name: "Choose model and reasoning", exact: true }),
        MODEL,
      );
      await expect(page.getByRole("menuitem", { name: "Unshared profile", exact: true })).toHaveCount(0);
      await expect(selectedModel).toHaveAttribute("data-zode-selected", "true");
      await page.keyboard.press("Escape");
      await form.getByRole("textbox", { name: "New session message", exact: true }).fill(
        "shared profile placement",
      );
      const sessionRequest = page.waitForRequest(
        (request) => request.method() === "POST" && /\/v1\/endpoints\/[^/]+\/sessions$/u.test(
          new URL(request.url()).pathname,
        ),
      );
      await form.getByRole("button", { name: "Start session", exact: true }).click();
      const body = (await sessionRequest).postDataJSON();
      expect(body.model.auth_profile_id).toBe(sharedProfile.auth_profile_id);
      expect(body.model.auth_profile_id).not.toBe(unsharedProfile.auth_profile_id);
    } catch (error) {
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        cause: error instanceof Error ? error.message : String(error),
      });
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      if (!page.isClosed()) await page.close();
      await harness.journal.waitForIdle();
      const records = recordsFor(harness, captureSetId);
      const firstFailure = firstPublicRecord(records);
      if (!firstFailure) throw new Error("session sharing capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        if (process.env.ZODE_CAPTURE_PROFILE_SHARING_SESSION === "1" && primaryError.classification === CLASSIFICATION) {
          const promoted = await harness.journal.promoteCaptureSet(captureSetId, {
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
