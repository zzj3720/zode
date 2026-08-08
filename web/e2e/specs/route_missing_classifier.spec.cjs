const fs = require("node:fs");
const path = require("node:path");

const { expect, test } = require("@playwright/test");
const {
  ProductBehaviorFailure,
  createWebE2EHarness,
} = require("../support/harness.cjs");

const E2E = "e2e_browser_management_route_missing_returns_typed_json";
const CLASSIFICATION = "MANAGEMENT_ROUTE_MISSING_BARE_FALLBACK";
const CAPTURE_ENV = "ZODE_CAPTURE_ROUTE_MISSING_FIRST";
const REQUEST_PATH = "/v1/__route_missing_classifier__";
const FIRST_OBSERVED = "an unknown management /v1 route returned a bare fallback 404 instead of the typed public route-missing error";
const INCIDENT_DIRECTORY = path.resolve(__dirname, "..", "fixtures", "incidents");

function matchingCassettes() {
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
  const matches = matchingCassettes();
  expect(matches).toHaveLength(1);
  const cassette = JSON.parse(fs.readFileSync(matches[0], "utf8"));
  expect(cassette.schema).toBe("zode.http-incident-recording.v1");
  expect(cassette.version).toBe(1);
  expect(cassette.boundary).toBe("browser-capture-set");
  expect(cassette.first_observed).toBe(FIRST_OBSERVED);
  expect(cassette.source_digest).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.integrity_sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(cassette.exchanges).toHaveLength(1);
  expect(cassette.exchanges[0].boundary).toBe("management-access-edge");
  expect(cassette.exchanges[0].method).toBe("GET");
  expect(cassette.exchanges[0].path).toBe(REQUEST_PATH);
  expect(cassette.exchanges[0].response.status).toBe(404);
}

function hasNoStore(headers) {
  return (headers["cache-control"] || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .includes("no-store");
}

function recordsFor(harness, captureSetId) {
  return harness.journal.records
    .filter((record) => record.captureSetId === captureSetId)
    .sort((left, right) => String(left.recordingId).localeCompare(String(right.recordingId)));
}

test(E2E, async ({ context }) => {
  test.setTimeout(120_000);
  const captureRequested = process.env[CAPTURE_ENV] === "1";
  if (!captureRequested) assertCassetteIdentity();

  const harness = await createWebE2EHarness({
    e2eName: E2E,
    uiMode: "assets",
    includeServerOrigins: true,
  });
  const captureSetId = harness.beginCaptureSet({ e2eName: E2E, maxMembers: 1 });
  let primaryError;
  try {
    const response = await context.request.get(`${harness.managementUrl}${REQUEST_PATH}`, {
      headers: { accept: "application/json" },
    });
    const headers = response.headers();
    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
    const expected = {
      error: {
        code: "route_not_found",
        message: "public route was not found",
        retryable: false,
      },
    };
    if (response.status() !== 404
      || !hasNoStore(headers)
      || !(headers["content-type"] || "").toLowerCase().includes("application/json")
      || JSON.stringify(body) !== JSON.stringify(expected)) {
      throw new ProductBehaviorFailure(
        CLASSIFICATION,
        `${FIRST_OBSERVED}; status=${response.status()}`,
        { status: response.status(), requestPath: REQUEST_PATH },
      );
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await harness.journal.waitForIdle();
      const records = recordsFor(harness, captureSetId);
      expect(records).toHaveLength(1);
      if (primaryError) {
        const capture = harness.journal.flushCaptureSet(captureSetId, {
          firstFailureRecordingId: records[0].recordingId,
        });
        expect(capture.sourceDigest).toMatch(/^[0-9a-f]{64}$/u);
        expect(fs.statSync(records[0].rawPath).mode & 0o777).toBe(0o600);
        if (captureRequested && primaryError.classification === CLASSIFICATION) {
          const promoted = await harness.journal.promoteFlushedCaptureSet(captureSetId, {
            e2eName: E2E,
            classification: CLASSIFICATION,
            firstObserved: FIRST_OBSERVED,
            firstFailureRecordingId: records[0].recordingId,
            destinationDirectory: INCIDENT_DIRECTORY,
            replay: (envelope) => harness.journal.replay(envelope, {
              baseUrl: harness.managementUrl,
              boundaryBaseUrls: { "management-access-edge": harness.managementUrl },
            }),
          });
          primaryError = new ProductBehaviorFailure(
            CLASSIFICATION,
            `${primaryError.message}; cassette=${promoted.cassettePath}`,
            { captureSetId, recordingId: records[0].recordingId },
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
