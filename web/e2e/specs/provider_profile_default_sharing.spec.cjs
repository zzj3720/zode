const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
} = require("../support/harness.cjs");

const E2E_NAME = "e2e_browser_provider_two_api_key_profiles_have_explicit_default_and_distinct_sharing";
const CLASSIFICATION = "PROVIDER_PROFILE_DEFAULT_ACTION_MISSING";
const FIRST_OBSERVED =
  "the second API-key profile form did not expose an explicit default selection, so the UI could not preserve one declared default while sharing profiles to different Endpoints";
const PROVIDER = "profile-default-fixture";
const MODEL = "profile-default-model";
const ENDPOINT_LABEL = "Profile test Endpoint";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const INCIDENT_CASSETTE = path.join(
  INCIDENT_DIRECTORY,
  "0002-62a08ca1-3bdd-4223-a68e-f7339c2364f3-68aafbda-6e0b-4f14-a4d7-c66036598d69.v1.json",
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
  expect(cassette.exchanges).toHaveLength(3);
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
  return records.find((record) => record.boundary === "management-access-edge" && record.method === "GET" && record.path === "/v1/providers")
    || records[0];
}

async function configureProvider(page, harness) {
  await openManagement(page, "Providers");
  await expect(page).toHaveURL(/\/providers$/u);
  await page.getByRole("button", { name: "Configure provider", exact: true }).click();
  const form = page.locator("form.editor-panel").filter({ hasText: "Configure provider" });
  await form.getByLabel("Provider ID").fill(PROVIDER);
  await form.getByLabel("Base URL").fill(`${harness.providerProxy.baseUrl}/v1`);
  await form.getByLabel("Models").fill(MODEL);
  await Promise.all([
    page.waitForResponse((response) => response.request().method() === "PUT" && new URL(response.url()).pathname === `/v1/providers/${PROVIDER}`),
    form.getByRole("button", { name: "Save provider", exact: true }).click(),
  ]);
  await expect(form).toBeHidden();
}

async function addRemoteEndpoint(page, harness, label) {
  await openManagement(page, "Endpoints");
  await expect(page).toHaveURL(/\/endpoints$/u);
  await page.getByRole("button", { name: "Add remote Endpoint", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add remote Endpoint" });
  await dialog.getByLabel("Endpoint label").fill(label);
  await dialog.getByLabel("Endpoint URL").fill(harness.endpoint.baseUrl);
  const credential = dialog.getByLabel("Controller credential");
  await credential.fill(harness.controllerSecret);
  await Promise.all([
    page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/endpoints"),
    dialog.getByRole("button", { name: "Add Endpoint", exact: true }).click(),
  ]);
  await expect(dialog).toBeHidden();
  await expect(page.locator("article.resource-card").filter({ hasText: label })).toBeVisible();
}

async function createProfile(page, harness, label, makeDefault, shareEndpoint) {
  await openManagement(page, "Providers");
  const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
  await card.getByRole("button", { name: "Add API key profile", exact: true }).click();
  const form = card.locator("form.nested-editor");
  await form.getByLabel("Profile label").fill(label);
  const secret = `${harness.providerSecret}-${label.replaceAll(" ", "-")}`;
  harness.ledger.add(`profile_${label.toLowerCase().replaceAll(" ", "_")}`, secret);
  await form.getByLabel("API key").fill(secret);
  if (shareEndpoint) {
    await form.getByRole("checkbox", { name: `Share with ${ENDPOINT_LABEL}`, exact: true }).check();
  }
  const defaultControl = form.getByRole("checkbox", { name: "Make this the default profile", exact: true });
  if (makeDefault === false) {
    await expect(defaultControl).toBeVisible();
    await defaultControl.setChecked(false);
  } else if ((await defaultControl.count()) > 0) {
    await defaultControl.setChecked(true);
  }
  const [response] = await Promise.all([
    page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === `/v1/providers/${PROVIDER}/auth-profiles`),
    form.getByRole("button", { name: "Create profile", exact: true }).click(),
  ]);
  if (response.status() !== 201) {
    throw new Error(`profile create returned ${response.status()}: ${await response.text()}`);
  }
  await expect(form).toBeHidden();
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
  if (process.env.ZODE_CAPTURE_PROFILE_DEFAULT !== "1") assertCassetteIdentity();
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
    await addRemoteEndpoint(page, harness, ENDPOINT_LABEL);
    await configureProvider(page, harness);
    await createProfile(page, harness, "Primary profile", true, true);
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 32 });
    await armProviderRead(page);
    try {
      await createProfile(page, harness, "Secondary profile", false, false);
      const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
      const primary = card.locator(".profile-row").filter({ hasText: "Primary profile" });
      const secondary = card.locator(".profile-row").filter({ hasText: "Secondary profile" });
      await expect(primary).toContainText("Default profile");
      await expect(primary).toContainText(ENDPOINT_LABEL);
      await expect(secondary).not.toContainText("Default profile");
      await expect(secondary).toContainText("Not shared");
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        cause,
      });
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      if (!page.isClosed()) await page.close();
      await harness.journal.waitForIdle();
      if (!captureSetId) {
        if (!primaryError) throw new Error("profile default capture was never opened");
        throw primaryError;
      }
      const records = recordsFor(harness, captureSetId);
      const firstFailure = firstPublicRecord(records);
      if (!firstFailure) throw new Error("profile default capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) {
          expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        }
        if (process.env.ZODE_CAPTURE_PROFILE_DEFAULT === "1" && primaryError.classification === CLASSIFICATION) {
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
