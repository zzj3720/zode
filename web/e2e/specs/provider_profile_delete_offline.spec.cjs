const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  RealProcess,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require("../support/harness.cjs");

const E2E_NAME = "e2e_provider_profile_delete_offline_tombstone_reconciles_after_restart";
const CLASSIFICATION = "AUTH_PROFILE_DELETE_TOMBSTONE_NOT_RECONCILED_AFTER_RESTART";
const RELATION = "later_test_reproduction_of_gap";
const FIRST_OBSERVED =
  "a profile deleted while its Endpoint was offline remained ready at the Endpoint after Server and Endpoint restart instead of being reconciled by the durable tombstone";
const PROVIDER = "delete-offline-fixture";
const MODEL = "delete-offline-model";
const ENDPOINT_LABEL = "Offline delete Endpoint";
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
  expect(cassette.exchanges.length).toBeGreaterThanOrEqual(2);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "server-endpoint-control" &&
    exchange.method === "GET" &&
    exchange.path.includes("/v1/auth-replicas/"),
  )).toBe(true);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "GET" &&
    exchange.path.includes("/v1/auth-profiles/") &&
    exchange.path.endsWith("/replicas"),
  )).toBe(true);
  const endpointExchange = cassette.exchanges.find((exchange) =>
    exchange.boundary === "server-endpoint-control" &&
    exchange.method === "GET" &&
    exchange.path.includes("/v1/auth-replicas/"),
  );
  const managementExchange = cassette.exchanges.find((exchange) =>
    exchange.boundary === "management-access-edge" &&
    exchange.method === "GET" &&
    exchange.path.includes("/v1/auth-profiles/") &&
    exchange.path.endsWith("/replicas"),
  );
  const responseJson = (exchange) => JSON.parse(Buffer.concat(
    exchange.response.chunks.map((chunk) => Buffer.from(chunk.data_base64, "base64")),
  ).toString("utf8"));
  const endpointBody = responseJson(endpointExchange);
  const managementBody = responseJson(managementExchange);
  expect(endpointBody.status).toBe("ready");
  expect(endpointBody.revision).toBe(1);
  expect(managementBody.items).toEqual(expect.arrayContaining([
    expect.objectContaining({ status: "unreachable", revision: 2 }),
  ]));
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function firstPublicRecord(records) {
  return records.find((record) =>
    record.boundary === "management-access-edge" && record.method === "DELETE",
  ) || records[0];
}

function firstPostCheckRecord(records) {
  return records.find((record) =>
    record.boundary === "server-endpoint-control" &&
    record.method === "GET" &&
    record.path.includes("/v1/auth-replicas/"),
  ) || records.find((record) =>
    record.boundary === "management-access-edge" &&
    record.method === "GET" &&
    record.path.includes("/v1/auth-profiles/") &&
    record.path.endsWith("/replicas"),
  ) || records[0];
}

async function mutableEndpointProxy(harness) {
  let target = harness.endpoint;
  const proxy = await startHttpServer((request, response) => proxyHttp({
    targetBaseUrl: target.baseUrl,
    request,
    response,
    // Replay envelopes intentionally omit controller authorization. Restore
    // it only at this test-only Endpoint boundary; it never enters the
    // promoted cassette or a production path.
    extraHeaders: { authorization: `Bearer ${harness.controllerSecret}` },
    boundary: "server-endpoint-control",
    journal: harness.journal,
    ledger: harness.ledger,
    captureSetId: harness.journal.currentCaptureSetId,
    canonicalOrigin: target.baseUrl,
  }).catch((error) => {
    harness.journal._fail(error);
    if (!response.headersSent) response.writeHead(502, { "content-type": "application/json" });
    if (!response.writableEnded) response.end(JSON.stringify({
      error: { code: "endpoint_unavailable", retryable: true },
    }));
  }));
  return {
    proxy,
    setTarget(next) { target = next; },
    async close() { await proxy.close(); },
  };
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

async function addRemoteEndpoint(page, proxyUrl, harness) {
  await page.getByRole("link", { name: "Endpoints", exact: true }).click();
  await page.getByRole("button", { name: "Add remote Endpoint", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add remote Endpoint" });
  await dialog.getByLabel("Endpoint label").fill(ENDPOINT_LABEL);
  await dialog.getByLabel("Endpoint URL").fill(proxyUrl);
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
  await form.getByLabel("Profile label").fill("Offline delete profile");
  await form.getByLabel("API key").fill(`${harness.providerSecret}-offline-delete`);
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

async function restartEndpoint(harness, { alreadyStopped = false } = {}) {
  if (!alreadyStopped) await harness.endpoint.stop();
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
    logDir: path.join(harness.runRoot, "logs", "endpoint-offline-restart"),
    startupCaptureRoot: path.join(harness.journal.rootDir, "startup", "endpoint-offline-restart"),
    startupConfigBytes: fs.readFileSync(configPath),
    e2eName: E2E_NAME,
  });
}

async function profileId(page) {
  return page.evaluate(async (provider) => {
    const response = await fetch(`/v1/providers/${encodeURIComponent(provider)}/auth-profiles`, {
      headers: { accept: "application/json" },
    });
    const body = await response.json();
    return body.items.find((item) => item.label === "Offline delete profile").profile_id;
  }, PROVIDER);
}

test(E2E_NAME, async ({ page }) => {
  test.setTimeout(180_000);
  const captureRequested = process.env.ZODE_CAPTURE_PROFILE_DELETE_OFFLINE === "1";
  if (!captureRequested) assertCassetteIdentity();
  const harness = await createWebE2EHarness({
    e2eName: E2E_NAME,
    uiMode: "assets",
    includeServerOrigins: true,
    authorityId: "web-e2e-server",
  });
  const endpointProxy = await mutableEndpointProxy(harness);
  let captureSetId;
  let postCheckCaptureSetId;
  let primaryError;
  try {
    captureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 96 });
    await page.goto(`${harness.managementUrl}/`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
    await addRemoteEndpoint(page, endpointProxy.proxy.baseUrl, harness);
    await configureProvider(page, harness);
    await createSharedProfile(page, harness);

    await harness.endpoint.stop();
    await page.getByRole("link", { name: "Providers", exact: true }).click();
    const card = page.locator("article.resource-card").filter({ hasText: PROVIDER }).first();
    const profile = card.locator(".profile-row").filter({ hasText: "Offline delete profile" });
    const id = await profileId(page);
    await profile.getByRole("button", { name: "Delete profile", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Delete profile" });
    await dialog.getByRole("checkbox", { name: /understand|acknowledge/i }).check();
    const deleteResponse = page.waitForResponse((response) =>
      response.request().method() === "DELETE" &&
      new URL(response.url()).pathname === `/v1/providers/${PROVIDER}/auth-profiles/${id}`,
    );
    await dialog.getByRole("button", { name: "Delete profile permanently", exact: true }).click();
    const deleted = await deleteResponse;
    expect(deleted.status()).toBe(200);
    const deletedBody = await deleted.json();
    expect(deletedBody.status).toBe("removal_pending");
    expect(deletedBody.distribution.some((item) => item.status === "unreachable")).toBe(true);
    await expect(dialog).toBeHidden();

    await harness.restartServer();
    await page.goto(`${harness.managementUrl}/providers`, { waitUntil: "domcontentloaded" });
    const restartedEndpoint = await restartEndpoint(harness, { alreadyStopped: true });
    endpointProxy.setTarget(restartedEndpoint);
    harness.endpoint = restartedEndpoint;
    postCheckCaptureSetId = harness.beginCaptureSet({ e2eName: E2E_NAME, maxMembers: 96 });

    let latest;
    const readObservations = async () => {
      const endpointResponse = await fetch(
        `${endpointProxy.proxy.baseUrl}/v1/auth-replicas/${encodeURIComponent(id)}`,
        { headers: { authorization: `Bearer ${harness.controllerSecret}` } },
      );
      const endpointBody = await endpointResponse.json();
      const serverReplicaResponse = await fetch(
        `${harness.managementUrl}/v1/auth-profiles/${encodeURIComponent(id)}/replicas`,
        { headers: { accept: "application/json" } },
      );
      const serverReplica = await serverReplicaResponse.json();
      return { endpointBody, serverReplica };
    };
    try {
      await expect.poll(async () => {
        latest = await readObservations();
        return latest.endpointBody.status === "tombstoned" &&
          latest.endpointBody.revision > 1 &&
          latest.serverReplica.items?.some((item) => item.status === "removed");
      }, { timeout: 15_000, intervals: [250, 500, 1000] }).toBe(true);
    } catch (error) {
      throw new ProductBehaviorFailure(CLASSIFICATION, FIRST_OBSERVED, {
        relation: RELATION,
        endpointStatus: latest?.endpointBody?.status,
        endpointRevision: latest?.endpointBody?.revision,
        serverItems: latest?.serverReplica?.items,
        cause: error instanceof Error ? error.message : String(error),
      });
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await harness.journal.waitForIdle();
      if (postCheckCaptureSetId) {
        const postCheckRecords = recordsFor(harness, postCheckCaptureSetId);
        const postCheckFirstFailure = firstPostCheckRecord(postCheckRecords);
        if (!postCheckFirstFailure) throw new Error("offline tombstone replay capture contained no post-restart exchange");
        const postCheckCapture = harness.journal.flushCaptureSet(postCheckCaptureSetId, {
          firstFailureRecordingId: postCheckFirstFailure.recordingId,
        });
        if (captureRequested && primaryError?.classification === CLASSIFICATION) {
          const promoted = await harness.journal.promoteCaptureSet(postCheckCaptureSetId, {
            e2eName: E2E_NAME,
            classification: CLASSIFICATION,
            firstObserved: FIRST_OBSERVED,
            firstFailureRecordingId: postCheckFirstFailure.recordingId,
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
            CLASSIFICATION,
            `${FIRST_OBSERVED}; relation=${RELATION}; cassette=${promoted.cassettePath}`,
            { captureSetId: postCheckCaptureSetId, recordingId: postCheckFirstFailure.recordingId },
          );
        }
      }
      const records = recordsFor(harness, captureSetId);
      if (primaryError) {
        const firstFailure = firstPublicRecord(records);
        if (!firstFailure) throw new Error("offline profile delete capture contained no public exchange");
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
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
          original_evidence_gap: "profile deletion offline tombstone was not retried after restart",
          recording_id: firstFailure.recordingId,
          first_failure_recording_id: firstFailure.recordingId,
          classification: primaryError.classification || CLASSIFICATION,
          first_observed: FIRST_OBSERVED,
          raw_exchange_retained: primaryError.classification === CLASSIFICATION,
          source_digest: capture.sourceDigest,
          do_not_relabel_as_first: true,
        }, null, 2)}\n`, { mode: 0o600 });
      } else if (captureSetId) {
        harness.journal.flushCaptureSet(captureSetId);
      }
    } catch (captureError) {
      primaryError = captureError;
    }
    try { await endpointProxy.close(); } catch (error) { primaryError ||= error; }
    try { await harness.close(); } catch (error) { primaryError ||= error; }
  }
  if (primaryError) throw primaryError;
});
