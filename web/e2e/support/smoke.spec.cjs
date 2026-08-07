'use strict';

const { test } = require('@playwright/test');

const { BrowserSecretGuard } = require('./browser.cjs');
const {
  HarnessFailure,
  ProductBehaviorFailure,
  ProductRouteMissing,
  SecretLeakFailure,
  collectBrowserSse,
  createWebE2EHarness,
} = require('./harness.cjs');

function safeFailure(error) {
  if (error instanceof HarnessFailure) return error;
  return new HarnessFailure('HARNESS_UNCLASSIFIED_FAILURE', 'browser harness smoke failed before a classified product result');
}

function failureReport(error, evidence) {
  const safe = safeFailure(error);
  const parts = [`${safe.classification}: ${safe.message}`];
  if (evidence?.record) parts.push(`first_exchange=${evidence.record.recordingId}`);
  if (evidence?.record?.rawPath) parts.push(`quarantine=${evidence.record.rawPath}`);
  if (evidence?.cassettePath) parts.push(`cassette=${evidence.cassettePath}`);
  if (evidence?.replay?.[0]) parts.push(`replay_status=${evidence.replay[0].status}`);
  if (safe.details?.nonEvidence) parts.push('evidence_status=non_evidence_only');
  return new Error(parts.join('; '));
}

function retainFailure(current, next) {
  if (!next) return current;
  if (next instanceof SecretLeakFailure) return next;
  return current || next;
}

test.describe('Zode web E2E public infrastructure', () => {
  test('e2e_web_harness_real_process_smoke @harness-smoke', async ({ page }, testInfo) => {
    test.setTimeout(60_000);
    const guard = new BrowserSecretGuard({ ledger: { find: () => undefined } });
    let harness;
    let primaryError;
    let evidence;
    guard.attachContext(page.context());

    try {
      harness = await createWebE2EHarness({ uiMode: 'assets' });
      guard.ledger = harness.ledger;
      await harness.endpointIdentity();

      const systemResponse = await page.goto(`${harness.managementUrl}/v1/system`, {
        waitUntil: 'domcontentloaded',
      });
      await guard.scanPage(page);
      const status = systemResponse?.status() ?? 0;
      if (status === 404) {
        throw new ProductRouteMissing({ path: '/v1/system', status, surface: 'management system' });
      }
      if (status !== 200) {
        throw new ProductBehaviorFailure('MANAGEMENT_SYSTEM_BEHAVIOR_FAILURE', 'management system probe returned an unexpected status', { status });
      }
      const systemText = await page.locator('body').innerText();
      let system;
      try { system = JSON.parse(systemText); } catch {
        throw new ProductBehaviorFailure('MANAGEMENT_SYSTEM_SCHEMA_FAILURE', 'management system probe did not return JSON');
      }
      if (system?.schema !== 'zode.system.v1') {
        throw new ProductBehaviorFailure('MANAGEMENT_SYSTEM_SCHEMA_FAILURE', 'management system probe returned the wrong public schema');
      }
      try {
        await harness.access.waitForJwksRequest();
      } catch {
        throw new ProductBehaviorFailure('ACCESS_ASSERTION_VERIFICATION_NOT_OBSERVED', 'real Access edge forwarded an assertion but the Server did not request the fixture JWKS');
      }

      const uiResponse = await page.goto(`${harness.managementUrl}/`, {
        waitUntil: 'domcontentloaded',
      });
      await guard.scanPage(page);
      const uiStatus = uiResponse?.status() ?? 0;
      if (uiStatus === 404) {
        throw new ProductRouteMissing({ path: '/', status: uiStatus, surface: 'management UI' });
      }
      if (uiStatus < 200 || uiStatus >= 400) {
        throw new ProductBehaviorFailure('MANAGEMENT_UI_BEHAVIOR_FAILURE', 'management UI navigation returned an unexpected status', { status: uiStatus });
      }
      const renderedText = await page.locator('body').innerText();
      if (!renderedText.trim()) {
        throw new ProductBehaviorFailure('MANAGEMENT_UI_EMPTY_RENDER', 'management UI returned an empty document');
      }
      await guard.scanPage(page);
    } catch (error) {
      primaryError = safeFailure(error);
      if (harness) {
        await guard.captureSafeScreenshot(page, testInfo);
        try {
          evidence = await harness.captureAndReplayFailure(primaryError, 'e2e_web_harness_real_process_smoke');
        } catch (replayError) {
          primaryError = new HarnessFailure('FIRST_FAILURE_REPLAY_GAP', 'first real failure was retained but secret-safe replay did not reproduce it');
          evidence = { error: replayError, record: evidence?.record };
        }
      }
    }

    try {
      await guard.scanPage(page);
    } catch (error) {
      primaryError = retainFailure(primaryError, error);
    }
    if (harness) {
      try {
        await harness.close();
      } catch (error) {
        primaryError = retainFailure(primaryError, error);
      }
    }
    try {
      guard.assertNoLeaks();
    } catch (error) {
      primaryError = retainFailure(primaryError, error);
    }
    if (primaryError) {
      testInfo.annotations.push({
        type: 'failure-classification',
        description: safeFailure(primaryError).classification,
      });
      throw failureReport(primaryError, evidence);
    }
  });
});

module.exports = { collectBrowserSse, SecretLeakFailure };
