const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const { ProductBehaviorFailure, createWebE2EHarness } = require("../support/harness.cjs");

const E2E_NAME = "e2e_browser_provider_profile_default_action_updates_server_pointer";
const CLASSIFICATION = "PROVIDER_PROFILE_DEFAULT_ACTION_MISSING";
const FIRST_OBSERVED =
  "a non-default provider profile had no Set as default action, so the browser could not move the Server-owned provider default pointer";
const LATER_CLASSIFICATION = `${CLASSIFICATION}__later_test_reproduction_of_gap`;
const LATER_FIRST_OBSERVED = `relation=later_test_reproduction_of_gap; ${FIRST_OBSERVED}`;
const PROVIDER = "profile-default-action-fixture";
const MODEL = "profile-default-action-model";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const INCIDENT_CASSETTE = path.join(
  INCIDENT_DIRECTORY,
  "0002-82884989-3395-4b11-b7ca-be86bc4a8f26-665e9002-a57c-4492-b042-3dbeacd6a9cc.v1.json",
);
const INCIDENT_CASSETTE_LATER = path.join(
  INCIDENT_DIRECTORY,
  "0002-provider-default-action-later.v1.json",
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
  expect(cassette.exchanges).toHaveLength(1);
  expect(cassette.exchanges[0]).toMatchObject({
    boundary: "management-access-edge",
    method: "GET",
    path: "/v1/providers",
    response: { status: 200 },
  });
}

function assertLaterCassetteIdentity() {
  const cassette = JSON.parse(fs.readFileSync(INCIDENT_CASSETTE_LATER, "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.e2e_name).toBe(E2E_NAME);
  expect(cassette.classification).toBe(LATER_CLASSIFICATION);
  expect(cassette.first_observed).toBe(LATER_FIRST_OBSERVED);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges.length).toBeGreaterThanOrEqual(2);
  expect(cassette.exchanges.some((exchange) => exchange.boundary === "management-access-edge" && exchange.method === "GET" && exchange.path === "/v1/providers" && exchange.response.status === 200)).toBe(true);
  expect(cassette.exchanges.some((exchange) => exchange.boundary === "management-access-edge" && exchange.method === "GET" && exchange.path === `/v1/providers/${PROVIDER}/auth-profiles` && exchange.response.status === 200)).toBe(true);
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function firstPublicRecord(records) {
  return records.find(
    (record) =>
      record.boundary === "management-access-edge" &&
      record.method === "GET" &&
      record.path === "/v1/providers",
  ) || records[0];
}

async function configureProvider(page, harness) {
  await page.getByRole("link", { name: "Providers", exact: true }).click();
  await page.getByRole("button", { name: "Configure provider", exact: true }).click();
  const form = page.locator("form.editor-panel").filter({ hasText: "Configure provider" });
  await form.getByLabel("Provider ID").fill(PROVIDER);
  await form.getByLabel("Provider kind").selectOption("openai_compatible");
  await form.getByLabel("Base URL").fill(`${harness.providerProxy.baseUrl}/v1`);
  await form.getByLabel("Models").fill(MODEL);
  await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === "PUT" &&
        new URL(response.url()).pathname === `/v1/providers/${PROVIDER}`,
    ),
    form.getByRole("button", { name: "Save provider", exact: true }).click(),
  ]);
  await expect(form).toBeHidden();
}

async function createProfile(page, harness, label, makeDefault) {
  const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
  await card.getByRole("button", { name: "Add API key profile", exact: true }).click();
  const form = card.locator("form.nested-editor");
  await form.getByLabel("Profile label").fill(label);
  const secret = `${harness.providerSecret}-${label.replaceAll(" ", "-")}`;
  harness.ledger.add(`profile_${label.toLowerCase().replaceAll(" ", "_")}`, secret);
  await form.getByLabel("API key").fill(secret);
  await form.getByRole("checkbox", { name: "Make this the default profile", exact: true }).setChecked(makeDefault);
  const [response] = await Promise.all([
    page.waitForResponse(
      (candidate) =>
        candidate.request().method() === "POST" &&
        new URL(candidate.url()).pathname === `/v1/providers/${PROVIDER}/auth-profiles`,
    ),
    form.getByRole("button", { name: "Create profile", exact: true }).click(),
  ]);
  expect(response.status()).toBe(201);
  await expect(form).toBeHidden();
}

test(E2E_NAME, async ({ page }) => {
  test.setTimeout(180_000);
  const captureRequested = process.env.ZODE_CAPTURE_PROFILE_DEFAULT_ACTION === "1";
  const laterCaptureRequested = process.env.ZODE_CAPTURE_PROFILE_DEFAULT_ACTION_LATER === "1";
  if (!captureRequested && !laterCaptureRequested) {
    assertCassetteIdentity();
    assertLaterCassetteIdentity();
  }
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
    await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
    await configureProvider(page, harness);
    await createProfile(page, harness, "Primary profile", true);
    await createProfile(page, harness, "Secondary profile", false);
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 32 });
    await page.goto(`${harness.managementUrl}/providers`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
    await page.evaluate(async () => {
      const response = await fetch("/v1/providers", { headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(`provider read returned ${response.status}`);
      await response.text();
    });
    try {
      const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
      const secondary = card.locator(".profile-row").filter({ hasText: "Secondary profile" });
      await expect(secondary.getByRole("button", { name: "Set as default", exact: true })).toBeVisible();
      const defaultResponsePromise = page.waitForResponse(
        (response) =>
          response.request().method() === "PUT" &&
          new URL(response.url()).pathname === `/v1/providers/${PROVIDER}/default-auth-profile`,
      );
      await secondary.getByRole("button", { name: "Set as default", exact: true }).click();
      expect((await defaultResponsePromise).status()).toBe(200);
      await expect(secondary).toContainText("Default profile");
      const projection = await page.evaluate(async (provider) => {
        const [providerResponse, profileResponse] = await Promise.all([
          fetch("/v1/providers", { headers: { accept: "application/json" } }),
          fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
            headers: { accept: "application/json" },
          }),
        ]);
        return {
          providers: await providerResponse.json(),
          profiles: await profileResponse.json(),
        };
      }, PROVIDER);
      const selectedProvider = projection.providers.providers.find((item) => item.provider === PROVIDER);
      const selectedProfile = projection.profiles.items.find((item) => item.label === "Secondary profile");
      expect(selectedProvider.default_profile_id).toBe(selectedProfile.profile_id);
      expect(selectedProfile.is_default).toBe(true);
      const idempotency = await page.evaluate(async ({ provider, profileId }) => {
        const key = "provider-default-replay-key";
        const request = (selectedProfileId) =>
          fetch(`/v1/providers/${encodeURIComponent(provider)}/default-auth-profile`, {
            method: "PUT",
            headers: { "Content-Type": "application/json", "Idempotency-Key": key },
            body: JSON.stringify({ profile_id: selectedProfileId }),
          });
        const replay = await request(profileId);
        const replayBody = await replay.json();
        const conflict = await request("profile-that-is-not-the-selected-default");
        return { replay: { status: replay.status, body: replayBody }, conflict: conflict.status };
      }, { provider: PROVIDER, profileId: selectedProfile.profile_id });
      expect(idempotency.replay.status).toBe(200);
      expect(idempotency.replay.body.is_default).toBe(true);
      expect(idempotency.conflict).toBe(409);
      await harness.restartServer();
      await page.goto(`${harness.managementUrl}/providers`, { waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
      const restartedCard = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
      await expect(
        restartedCard.locator(".profile-row").filter({ hasText: "Secondary profile" }),
      ).toContainText("Default profile");
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
      const firstFailure = firstPublicRecord(records);
      if (!firstFailure) throw new Error("provider default action capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        if (
          (captureRequested || laterCaptureRequested) &&
          primaryError.classification === CLASSIFICATION
        ) {
          const promoted = await harness.journal.promoteCaptureSet(captureSetId, {
            e2eName: E2E_NAME,
            classification: laterCaptureRequested ? LATER_CLASSIFICATION : CLASSIFICATION,
            firstObserved: laterCaptureRequested ? LATER_FIRST_OBSERVED : FIRST_OBSERVED,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) =>
              harness.journal.replay(envelope, {
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
