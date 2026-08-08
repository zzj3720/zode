const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  RecordingJournal,
  createWebE2EHarness,
  proxyHttp,
  startHttpServer,
} = require("../support/harness.cjs");

const E2E = "e2e_browser_callback_surface_isolated_and_management_system_no_store";
const CAPTURE_ENV = "ZODE_CAPTURE_UI_SURFACE_LATER_GAP";
const RECOVER_ENV = "ZODE_RECOVER_UI_SURFACE_LATER_GAP";
const RELATION = "later_test_reproduction_of_gap";
const CLASSIFICATION = `UI_CALLBACK_SURFACE_EXPOSED__${RELATION}`;
const ORIGINAL_GAP =
  "server/tests/fixtures/ui_delivery/ui-delivery-first-404-evidence-gap.v1.json";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "..", "fixtures", "incidents");
const HISTORY_PATH = "/endpoints/endpoint-ui/sessions/ui-surface-history";

function matchingCassettePaths() {
  if (!fs.existsSync(INCIDENT_DIRECTORY)) return [];
  return fs
    .readdirSync(INCIDENT_DIRECTORY)
    .filter((name) => name.endsWith(".v1.json"))
    .map((name) => path.join(INCIDENT_DIRECTORY, name))
    .filter((candidate) => {
      try {
        const value = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return value.e2e_name === E2E && value.classification === CLASSIFICATION;
      } catch {
        return false;
      }
    });
}

function assertCassetteIdentity() {
  const matches = matchingCassettePaths();
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(fs.readFileSync(matches[0], "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.first_observed).toContain(`relation=${RELATION}`);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.boundary).toBe("browser-capture-set");
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "management-access-edge"
      && exchange.path === "/v1/system"
      && exchange.response.status === 200)).toBe(true);
  expect(cassette.exchanges.some((exchange) =>
    exchange.boundary === "callback-public-edge"
      && exchange.path === "/"
      && exchange.response.status !== 404)).toBe(true);
  return matches[0];
}

function recoveryMetadata(rootDir) {
  const stat = fs.lstatSync(rootDir);
  expect(stat.isDirectory()).toBe(true);
  expect(stat.isSymbolicLink()).toBe(false);
  const paths = fs
    .readdirSync(rootDir)
    .filter((name) => name.endsWith(".later-reproduction.v1.json"))
    .map((name) => path.join(rootDir, name));
  expect(paths).toHaveLength(1);
  expect(fs.statSync(paths[0]).mode & 0o777).toBe(0o600);
  const metadata = JSON.parse(fs.readFileSync(paths[0], "utf8"));
  expect(metadata.schema).toBe("zode.evidence-gap-later-reproduction.v1");
  expect(metadata.version).toBe(1);
  expect(metadata.owning_e2e).toBe(E2E);
  expect(metadata.relation).toBe(RELATION);
  expect(metadata.original_evidence_gap).toBe(ORIGINAL_GAP);
  expect(metadata.classification).toBe(CLASSIFICATION);
  expect(metadata.raw_exchange_retained).toBe(true);
  expect(metadata.do_not_relabel_as_first).toBe(true);
  expect(metadata.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  return metadata;
}

async function startRecoveryCallbackEdge(harness, journal) {
  return startHttpServer((request, response) => {
    const capturedAccessProbe = request.headers.forwarded !== undefined
      || request.headers["x-forwarded-host"] !== undefined;
    return proxyHttp({
      targetBaseUrl: harness.server.baseUrl,
      request,
      response,
      extraHeaders: capturedAccessProbe
        ? { "cf-access-jwt-assertion": harness.access.issue() }
        : {},
      boundary: "callback-public-edge",
      journal,
      ledger: harness.ledger,
      canonicalOrigin: harness.callbackOrigin,
    }).catch((error) => {
      journal._fail(error);
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "application/json" });
      }
      if (!response.writableEnded) {
        response.end(JSON.stringify({ error: { code: "callback_unavailable", retryable: true } }));
      }
    });
  });
}

async function recoverAndPromoteLaterFailure(harness, rootDir) {
  const metadata = recoveryMetadata(rootDir);
  const journal = RecordingJournal.openFlushedCaptureRoot({
    rootDir,
    ledger: harness.ledger,
  });
  const reloaded = journal.reloadCaptureSet(metadata.capture_set_id);
  expect(reloaded.state).toBe("flushed");
  expect(reloaded.e2eName).toBe(E2E);
  expect(reloaded.sourceDigest).toBe(metadata.source_digest);
  expect(reloaded.firstFailureRecordingId).toBe(metadata.first_failure_recording_id);
  expect(reloaded.records).toHaveLength(9);
  for (const record of reloaded.records) {
    expect(fs.statSync(record.rawPath).mode & 0o777).toBe(0o600);
  }

  const callbackEdge = await startRecoveryCallbackEdge(harness, journal);
  try {
    return await journal.promoteFlushedCaptureSet(metadata.capture_set_id, {
      e2eName: E2E,
      classification: CLASSIFICATION,
      firstObserved:
        `relation=${RELATION}; callback Host exposed management responses and management /v1/system omitted Cache-Control:no-store`,
      firstFailureRecordingId: metadata.first_failure_recording_id,
      destinationDirectory: INCIDENT_DIRECTORY,
      replay: (envelope) => journal.replay(envelope, {
        baseUrl: harness.managementUrl,
        boundaryBaseUrls: {
          "management-access-edge": harness.managementUrl,
          "callback-public-edge": callbackEdge.baseUrl,
        },
      }),
    });
  } finally {
    await callbackEdge.close();
  }
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function writePrivateDurableJson(filePath, value) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(filePath));
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

function firstFailureRecord(records) {
  return records.find((record) =>
    record.boundary === "callback-public-edge"
      && record.path === "/"
      && record.response.status !== 404)
    || records.find((record) =>
      record.boundary === "management-access-edge"
        && record.path === "/v1/system")
    || records.at(-1);
}

function hasNoStore(headers) {
  return (headers["cache-control"] || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .includes("no-store");
}

async function summarize(response) {
  return {
    status: response.status(),
    headers: response.headers(),
    body: await response.text(),
  };
}

function checkCallback(label, response, failures) {
  if (response.status !== 404) failures.push(`${label}:status=${response.status}`);
  if (!hasNoStore(response.headers)) failures.push(`${label}:cache_control_not_no_store`);
  if ((response.headers["content-type"] || "").toLowerCase().includes("text/html")) {
    failures.push(`${label}:html_exposed`);
  }
  if (/<(?:html|script|link|main|nav)\b/iu.test(response.body)) {
    failures.push(`${label}:management_markup_exposed`);
  }
}

function versionedAssetPath(html) {
  const match = html.match(/["'](\/assets\/[^"'?#]+-[A-Za-z0-9]{8,}\.(?:js|mjs|css))["']/u);
  if (!match) throw new Error("real management HTML did not reference a versioned asset");
  return match[1];
}

async function exerciseSurface(page, context, harness) {
  const managementRoot = await page.goto(`${harness.managementUrl}/`, {
    waitUntil: "domcontentloaded",
  });
  if (managementRoot?.status() !== 200) {
    throw new Error(`management UI prerequisite returned HTTP ${managementRoot?.status() ?? 0}`);
  }
  const assetPath = versionedAssetPath(await managementRoot.text());
  const captureSetId = harness.beginCaptureSet({ e2eName: E2E, maxMembers: 16 });
  const failures = [];

  const system = await summarize(await context.request.get(`${harness.managementUrl}/v1/system`));
  if (system.status !== 200) failures.push(`management_system:status=${system.status}`);
  if (!hasNoStore(system.headers)) failures.push("management_system:cache_control_not_no_store");

  const callbackPaths = ["/", assetPath, HISTORY_PATH, "/v1/system"];
  const baselineRootResponse = await page.goto(`${harness.callbackUrl}/`, {
    waitUntil: "domcontentloaded",
  });
  if (!baselineRootResponse) throw new Error("callback browser navigation returned no response");
  checkCallback("callback_root_without_access", await summarize(baselineRootResponse), failures);

  for (const requestPath of callbackPaths.slice(1)) {
    const response = await summarize(await context.request.get(`${harness.callbackUrl}${requestPath}`));
    checkCallback(`callback_without_access:${requestPath}`, response, failures);
  }

  for (const requestPath of callbackPaths) {
    const response = await summarize(await context.request.get(`${harness.callbackUrl}${requestPath}`, {
      headers: {
        "cf-access-jwt-assertion": harness.access.issue(),
        forwarded: "host=127.0.0.1",
        "x-forwarded-host": new URL(harness.managementOrigin).host,
      },
    }));
    checkCallback(`callback_with_access_and_spoof:${requestPath}`, response, failures);
  }

  if (failures.length > 0) {
    throw new ProductBehaviorFailure(
      CLASSIFICATION,
      `callback/cache public contract failed: ${failures.join("; ")}`,
      { relation: RELATION, failures },
    );
  }
  return captureSetId;
}

test(E2E, async ({ page, context }) => {
  test.setTimeout(120_000);
  const captureMode = process.env[CAPTURE_ENV] === "1";
  const recoveryRoot = process.env[RECOVER_ENV];
  if (!captureMode && !recoveryRoot) assertCassetteIdentity();

  const harness = await createWebE2EHarness({
    e2eName: E2E,
    uiMode: "assets",
    includeServerOrigins: true,
  });
  let captureSetId;
  let primaryError;
  let capture;
  if (recoveryRoot) {
    try {
      const promoted = await recoverAndPromoteLaterFailure(harness, recoveryRoot);
      primaryError = new ProductBehaviorFailure(
        CLASSIFICATION,
        `recovered public callback/cache red; relation=${RELATION}; cassette=${promoted.cassettePath}`,
        { relation: RELATION, cassettePath: promoted.cassettePath },
      );
    } catch (error) {
      primaryError = error;
    }
    try {
      await harness.close();
    } catch (cleanupError) {
      primaryError ||= cleanupError;
    }
    if (primaryError) throw primaryError;
    return;
  }
  try {
    captureSetId = await exerciseSurface(page, context, harness);
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await harness.journal.waitForIdle();
      if (!captureSetId) {
        captureSetId = harness.journal.currentCaptureSetId;
      }
      const records = recordsFor(harness, captureSetId);
      if (primaryError) {
        const firstFailure = firstFailureRecord(records);
        if (!firstFailure) throw new Error("armed UI surface capture contained no public exchange");
        capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: firstFailure.recordingId,
        });
        const metadataPath = path.join(
          harness.journal.rootDir,
          `${captureSetId}.later-reproduction.v1.json`,
        );
        writePrivateDurableJson(metadataPath, {
          schema: "zode.evidence-gap-later-reproduction.v1",
          version: 1,
          owning_e2e: E2E,
          recording_id: firstFailure.recordingId,
          capture_set_id: captureSetId,
          relation: RELATION,
          original_evidence_gap: ORIGINAL_GAP,
          classification: primaryError.classification || "UI_SURFACE_HARNESS_FAILURE",
          first_failure_recording_id: firstFailure.recordingId,
          raw_exchange_retained: true,
          source_digest: capture.sourceDigest,
          do_not_relabel_as_first: true,
        });

        if (captureMode && primaryError.classification === CLASSIFICATION) {
          const promoted = await harness.journal.promoteFlushedCaptureSet(captureSetId, {
            e2eName: E2E,
            classification: CLASSIFICATION,
            firstObserved:
              `relation=${RELATION}; callback Host exposed management responses and management /v1/system omitted Cache-Control:no-store`,
            firstFailureRecordingId: firstFailure.recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: harness.managementUrl,
              boundaryBaseUrls: {
                "management-access-edge": harness.managementUrl,
                "callback-public-edge": harness.callbackUrl,
              },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            CLASSIFICATION,
            `${primaryError.message}; relation=${RELATION}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: firstFailure.recordingId, relation: RELATION },
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
