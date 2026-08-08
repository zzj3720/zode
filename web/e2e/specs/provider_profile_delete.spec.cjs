const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const { ProductBehaviorFailure, createWebE2EHarness } = require("../support/harness.cjs");

const E2E_NAME = "e2e_browser_provider_profile_delete_tombstones_endpoint_replica";
const CLASSIFICATION = "PROVIDER_PROFILE_DELETE_ACTION_MISSING";
const FIRST_OBSERVED =
  "a shared API-key profile had no Delete profile action in the real Providers page, so the browser could not request Server-owned profile deletion and Endpoint tombstone distribution";
const PROVIDER = "profile-delete-fixture";
const MODEL = "profile-delete-model";
const ENDPOINT_LABEL = "Delete target Endpoint";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");
const INCIDENT_CASSETTE = path.join(
  INCIDENT_DIRECTORY,
  "0002-ad0c969f-49d4-4aaf-9462-19a61e13027d-bed6a91d-21cc-4282-8295-d741ae3c9f2f.v1.json",
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
  expect(cassette.exchanges.length).toBeGreaterThanOrEqual(2);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "GET" &&
    exchange.path === "/v1/providers" &&
    exchange.response.status === 200,
  )).toBe(true);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "GET" &&
    exchange.path === `/v1/providers/${PROVIDER}/auth-profiles` &&
    exchange.response.status === 200,
  )).toBe(true);
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function firstPublicRecord(records) {
  return records.find((record) =>
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
    page.waitForResponse((response) =>
      response.request().method() === "PUT" &&
      new URL(response.url()).pathname === `/v1/providers/${PROVIDER}`,
    ),
    form.getByRole("button", { name: "Save provider", exact: true }).click(),
  ]);
  await expect(form).toBeHidden();
}

async function addRemoteEndpoint(page, harness) {
  await page.getByRole("link", { name: "Endpoints", exact: true }).click();
  await page.getByRole("button", { name: "Add remote Endpoint", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add remote Endpoint" });
  await dialog.getByLabel("Endpoint label").fill(ENDPOINT_LABEL);
  await dialog.getByLabel("Endpoint URL").fill(harness.endpoint.baseUrl);
  await dialog.getByLabel("Controller credential").fill(harness.controllerSecret);
  await Promise.all([
    page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/endpoints",
    ),
    dialog.getByRole("button", { name: "Add Endpoint", exact: true }).click(),
  ]);
  await expect(dialog).toBeHidden();
}

async function createSharedProfile(page, harness) {
  await page.getByRole("link", { name: "Providers", exact: true }).click();
  const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
  await card.getByRole("button", { name: "Add API key profile", exact: true }).click();
  const form = card.locator("form.nested-editor");
  await form.getByLabel("Profile label").fill("Delete me profile");
  const secret = `${harness.providerSecret}-delete-me`;
  harness.ledger.add("profile_delete_me", secret);
  await form.getByLabel("API key").fill(secret);
  await form.getByRole("checkbox", { name: `Share with ${ENDPOINT_LABEL}`, exact: true }).check();
  await form.getByRole("checkbox", { name: "Make this the default profile", exact: true }).check();
  const [response] = await Promise.all([
    page.waitForResponse((candidate) =>
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
  const captureRequested = process.env.ZODE_CAPTURE_PROFILE_DELETE === "1";
  if (!captureRequested) assertCassetteIdentity();
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
    await addRemoteEndpoint(page, harness);
    await configureProvider(page, harness);
    await createSharedProfile(page, harness);
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 32 });
    await page.goto(`${harness.managementUrl}/providers`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
    await page.evaluate(async (provider) => {
      const responses = await Promise.all([
        fetch("/v1/providers", { headers: { accept: "application/json" } }),
        fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
          headers: { accept: "application/json" },
        }),
      ]);
      for (const response of responses) {
        if (!response.ok) throw new Error(`provider read returned ${response.status}`);
        await response.text();
      }
    }, PROVIDER);
    const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
    const profile = card.locator(".profile-row").filter({ hasText: "Delete me profile" });
    try {
      await expect(profile).toContainText("Default profile");
      await expect(profile.getByRole("button", { name: "Delete profile", exact: true })).toBeVisible();
    } catch (error) {
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        cause: error instanceof Error ? error.message : String(error),
      });
    }
    {
      const profileId = await page.evaluate(async (provider) => {
        const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
          headers: { accept: "application/json" },
        });
        const body = await response.json();
        return body.items.find((item) => item.label === "Delete me profile").profile_id;
      }, PROVIDER);
      await profile.getByRole("button", { name: "Delete profile", exact: true }).click();
      const dialog = page.getByRole("dialog", { name: "Delete profile" });
      await expect(dialog).toContainText(/best[- ]effort/i);
      await expect(dialog).toContainText(/provider-side.*(rotation|revocation)/i);
      const confirm = dialog.getByRole("button", { name: "Delete profile permanently", exact: true });
      await expect(confirm).toBeDisabled();
      await dialog.getByRole("checkbox", { name: /understand|acknowledge/i }).check();
      const deleteResponse = page.waitForResponse((response) =>
        response.request().method() === "DELETE" &&
        new URL(response.url()).pathname ===
          `/v1/providers/${PROVIDER}/auth-profiles/${profileId}`,
      );
      await confirm.click();
      const deleteResult = await deleteResponse;
      expect(deleteResult.status()).toBe(200);
      const deleteKey = deleteResult.request().headers()["idempotency-key"];
      const replay = await page.evaluate(async ({ provider, profileId, idempotencyKey }) => {
        const response = await fetch(
          `/v1/providers/${encodeURIComponent(provider)}/auth-profiles/${encodeURIComponent(profileId)}`,
          { method: "DELETE", headers: { "Idempotency-Key": idempotencyKey } },
        );
        return { status: response.status, body: await response.json() };
      }, { provider: PROVIDER, profileId, idempotencyKey: deleteKey });
      expect(replay.status).toBe(200);
      expect(replay.body.status).toBe("deleted");
      await expect(dialog).toBeHidden();
      await expect(card.locator(".profile-row").filter({ hasText: "Delete me profile" })).toHaveCount(0);
      await expect(page.getByText(/Endpoint revocation was acknowledged/i)).toBeVisible();
      const endpointResponse = await fetch(
        `${harness.endpoint.baseUrl}/v1/auth-replicas/${encodeURIComponent(profileId)}`,
        { headers: { authorization: `Bearer ${harness.controllerSecret}` } },
      );
      const endpointBody = await endpointResponse.json();
      expect(endpointResponse.status).toBe(200);
      expect(endpointBody.status).toBe("tombstoned");
      expect(endpointBody.revision).toBeGreaterThan(1);
      await harness.restartServer();
      await page.goto(`${harness.managementUrl}/providers`, { waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
      const restartedCard = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
      await expect(restartedCard.locator(".profile-row").filter({ hasText: "Delete me profile" })).toHaveCount(0);
      const restartedProjection = await page.evaluate(async (provider) => {
        const response = await fetch("/v1/providers", { headers: { accept: "application/json" } });
        const body = await response.json();
        return body.providers.find((item) => item.provider === provider);
      }, PROVIDER);
      expect(restartedProjection.default_profile_id).toBeNull();
      expect(restartedProjection.auth_profile_count).toBe(0);
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await harness.journal.waitForIdle();
      const records = recordsFor(harness, captureSetId);
      const firstFailure = firstPublicRecord(records);
      if (!firstFailure) throw new Error("profile delete capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        for (const record of records) expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        if (captureRequested && primaryError.classification === CLASSIFICATION) {
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
