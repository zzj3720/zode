const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
} = require("../support/harness.cjs");

const E2E_NAME = "e2e_browser_provider_profile_list_keeps_active_after_many_tombstones";
const CLASSIFICATION = "PROVIDER_PROFILE_LIST_ACTIVE_HIDDEN_AFTER_TOMBSTONES";
const RELATION = "later_test_reproduction_of_gap";
const FIRST_OBSERVED =
  `relation=${RELATION}; after more than 100 permanently deleted profiles, the active provider profile was missing from the real Server list and Providers UI`;
const PROVIDER = "profile-list-tombstone-limit-fixture";
const MODEL = "profile-list-tombstone-limit-model";
const DELETED_PROFILE_COUNT = 101;
const INCIDENT_DIRECTORY = path.resolve(__dirname, "../fixtures/incidents");

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

function responseJson(exchange) {
  return JSON.parse(Buffer.concat(
    exchange.response.chunks.map((chunk) => Buffer.from(chunk.data_base64, "base64")),
  ).toString("utf8"));
}

function assertCassetteIdentity() {
  const matches = matchingCassettes();
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(fs.readFileSync(matches[0], "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.e2e_name).toBe(E2E_NAME);
  expect(cassette.classification).toBe(CLASSIFICATION);
  expect(cassette.first_observed).toBe(FIRST_OBSERVED);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges).toHaveLength(1);
  const listExchange = cassette.exchanges.find((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "GET" &&
    exchange.path === `/v1/providers/${PROVIDER}/auth-profiles` &&
    exchange.response.status === 200,
  );
  expect(listExchange).toBeDefined();
  expect(responseJson(listExchange).items).not.toEqual(expect.arrayContaining([
    expect.objectContaining({ label: "Survivor profile" }),
  ]));
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function firstFailureRecord(records) {
  return records.find((record) =>
    record.boundary === "management-access-edge" &&
    record.method === "GET" &&
    record.path === `/v1/providers/${PROVIDER}/auth-profiles` &&
    record.response.status === 200,
  ) || records.at(-1);
}

async function configureProvider(page, harness) {
  await page.getByRole("link", { name: "Providers", exact: true }).click();
  await page.getByRole("button", { name: "Configure provider", exact: true }).click();
  const form = page.locator("form.editor-panel").filter({ hasText: "Configure provider" });
  await form.getByLabel("Provider ID").fill(PROVIDER);
  await form.getByLabel("Provider kind").selectOption("openai_compatible");
  await form.getByLabel("Base URL").fill(`${harness.providerProxy.baseUrl}/v1`);
  await form.getByLabel("Models").fill(MODEL);
  const response = page.waitForResponse((candidate) =>
    candidate.request().method() === "PUT" &&
    new URL(candidate.url()).pathname === `/v1/providers/${PROVIDER}`,
  );
  await form.getByRole("button", { name: "Save provider", exact: true }).click();
  expect((await response).status()).toBe(200);
  await expect(form).toBeHidden();
}

async function seedProfiles(page, harness) {
  const profileSecrets = [];
  for (let index = 0; index < DELETED_PROFILE_COUNT; index += 1) {
    const secret = `${harness.providerSecret}-tombstone-seed-${index}`;
    harness.ledger.add(`tombstone_seed_${index}`, secret);
    profileSecrets.push(secret);
  }
  const profiles = await page.evaluate(async ({ provider, secrets }) => {
    const created = [];
    for (const [index, apiKey] of secrets.entries()) {
      const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "idempotency-key": `tombstone-seed-${index}`,
        },
        body: JSON.stringify({
          kind: "api_key",
          label: `Tombstone seed ${index}`,
          api_key: apiKey,
          make_default: false,
          sharing: { mode: "none", endpoint_ids: [] },
        }),
      });
      const body = await response.json();
      if (response.status !== 201) throw new Error(`seed profile ${index} returned ${response.status}`);
      created.push(body.auth_profile_id);
    }
    return created;
  }, { provider: PROVIDER, secrets: profileSecrets });
  expect(profiles).toHaveLength(DELETED_PROFILE_COUNT);
  return profiles;
}

async function deleteProfiles(page, provider, profileIds) {
  await page.evaluate(async ({ provider: selectedProvider, ids }) => {
    for (const [index, profileId] of ids.entries()) {
      const response = await fetch(
        `/v1/providers/${encodeURIComponent(selectedProvider)}/auth-profiles/${encodeURIComponent(profileId)}`,
        {
          method: "DELETE",
          headers: {
            accept: "application/json",
            "idempotency-key": `tombstone-delete-${index}`,
          },
        },
      );
      const body = await response.json();
      if (response.status !== 200 || !["deleted", "removal_pending"].includes(body.status)) {
        throw new Error(`delete profile ${index} returned ${response.status}`);
      }
    }
  }, { provider, ids: profileIds });
}

async function createSurvivor(page, harness) {
  const secret = `${harness.providerSecret}-survivor`;
  harness.ledger.add("survivor_profile", secret);
  const profile = await page.evaluate(async ({ provider, apiKey }) => {
    const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "idempotency-key": "tombstone-survivor",
      },
      body: JSON.stringify({
        kind: "api_key",
        label: "Survivor profile",
        api_key: apiKey,
        make_default: true,
        sharing: { mode: "none", endpoint_ids: [] },
      }),
    });
    const body = await response.json();
    if (response.status !== 201) throw new Error(`survivor profile returned ${response.status}`);
    return body;
  }, { provider: PROVIDER, apiKey: secret });
  expect(profile.label).toBe("Survivor profile");
}

async function readProfiles(page) {
  return page.evaluate(async (provider) => {
    const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
      headers: { accept: "application/json" },
    });
    return { status: response.status, body: await response.json() };
  }, PROVIDER);
}

test(E2E_NAME, async ({ page }) => {
  test.setTimeout(240_000);
  const captureRequested = process.env.ZODE_CAPTURE_PROFILE_LIST_TOMBSTONE_LIMIT === "1";
  if (!captureRequested) assertCassetteIdentity();
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-server",
  });
  let preseedCaptureSetId;
  let captureSetId;
  let primaryError;
  try {
    preseedCaptureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 256 });
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
    await configureProvider(page, harness);
    const profileIds = await seedProfiles(page, harness);
    await deleteProfiles(page, PROVIDER, profileIds);
    await createSurvivor(page, harness);
    await harness.journal.waitForIdle();
    harness.journal.flushCaptureSet(preseedCaptureSetId);
    // Arm immediately before the public list request that exposes the bug.
    // The profile creation/deletion sequence is a deterministic preseed; it
    // is not replayed as if it were the failing exchange.
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 256 });
    const listed = await readProfiles(page);
    try {
      expect(listed.status).toBe(200);
      expect(listed.body.items).toEqual(expect.arrayContaining([
        expect.objectContaining({ label: "Survivor profile" }),
      ]));
    } catch (error) {
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        relation: RELATION,
        deletedProfileCount: DELETED_PROFILE_COUNT,
        listStatus: listed.status,
        listCount: listed.body.items?.length,
        cause: error instanceof Error ? error.message : String(error),
      });
    }
    await page.goto(`${harness.managementUrl}/providers`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Providers", exact: true })).toBeVisible();
    const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
    await expect(card.locator(".profile-row").filter({ hasText: "Survivor profile" })).toBeVisible();
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await harness.journal.waitForIdle();
      if (preseedCaptureSetId && !captureSetId) {
        const preseedRecords = recordsFor(harness, preseedCaptureSetId);
        if (preseedRecords.length) harness.journal.flushCaptureSet(preseedCaptureSetId);
      }
      if (!captureSetId) throw primaryError || new Error("profile tombstone failure capture was not armed");
      const records = recordsFor(harness, captureSetId);
      const firstFailure = firstFailureRecord(records);
      if (!firstFailure) throw new Error("profile tombstone limit capture contained no public exchange");
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        for (const record of records) {
          expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
        }
        if (captureRequested && primaryError.classification === CLASSIFICATION) {
          const promoted = await harness.journal.promoteCaptureSet(captureSetId, {
            e2eName: E2E_NAME,
            classification: CLASSIFICATION,
            firstObserved: FIRST_OBSERVED,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: harness.managementUrl,
              boundaryBaseUrls: {
                "management-access-edge": harness.managementUrl,
              },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            CLASSIFICATION,
            `${FIRST_OBSERVED}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: firstFailure.recordingId, relation: RELATION },
          );
          const metadataPath = path.join(
            harness.journal.rootDir,
            `${captureSetId}.later-reproduction.v1.json`,
          );
          fs.writeFileSync(metadataPath, `${JSON.stringify({
            schema: "zode.evidence-gap-later-reproduction.v1",
            version: 1,
            owning_e2e: E2E_NAME,
            capture_set_id: captureSetId,
            relation: RELATION,
            related_capture_set_ids: [preseedCaptureSetId],
            classification: CLASSIFICATION,
            first_failure_recording_id: firstFailure.recordingId,
            first_observed: FIRST_OBSERVED,
            raw_exchange_retained: true,
            source_digest: capture.sourceDigest,
            do_not_relabel_as_first: true,
          }, null, 2)}\n`, { mode: 0o600 });
        }
      } else {
        harness.journal.flushCaptureSet(captureSetId);
      }
    } catch (captureError) {
      primaryError = captureError;
    }
    try { await harness.close(); } catch (cleanupError) { primaryError ||= cleanupError; }
  }
  if (primaryError) throw primaryError;
});
