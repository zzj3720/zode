import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, open, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { promisify } from "node:util";

import { expect, test, type Page, type Response, type TestInfo } from "@playwright/test";

import {
  createWebE2EHarness,
  HarnessFailure,
  ProductBehaviorFailure,
  SecretLeakFailure,
} from "../support/harness.cjs";
import { BrowserSecretGuard } from "../support/browser.cjs";

const E2E_NAME =
  "e2e_browser_codex_desktop_shell_matches_approved_1920x1080_reference";
const SESSION_STATES_E2E_NAME =
  "e2e_browser_codex_desktop_session_states_match_approved_reference";
const INDEXED_DB_GATE_E2E_NAME =
  "e2e_browser_harness_indexeddb_secret_guard_fail_closed";
const SYNTHETIC_SECRET_MARKER = "zode-visual-e2e-synthetic-secret-marker";
const VIEWPORT = { width: 1920, height: 1080 } as const;
const REPO_ROOT = process.env.ZODE_REPO_ROOT ?? locateRepositoryRoot();
const WEB_ROOT = resolve(REPO_ROOT, "web");
const UI_DIST_DIR = resolve(REPO_ROOT, "target/web-e2e-ui-dist");
const FIXTURE_ROOT = resolve(
  REPO_ROOT,
  "web/e2e/fixtures/codex_desktop_visual",
);
const CONTRACT_PATH = resolve(FIXTURE_ROOT, "contract.v1.json");
const GOLDEN_PATH = resolve(
  FIXTURE_ROOT,
  "codex-desktop-shell.golden.png",
);
const CALIBRATION_SOURCE_ENV = "ZODE_CODEX_DESKTOP_REFERENCE";
const CALIBRATION_ENABLE_ENV = "ZODE_CODEX_DESKTOP_CALIBRATION";
const ACCEPT_GOLDEN_ENV = "ZODE_CODEX_DESKTOP_ACCEPT_GOLDEN";
const CALIBRATION_QUARANTINE_ROOT = resolve(
  REPO_ROOT,
  "target/test-recordings/quarantine/codex-desktop-visual",
);
const SERVER_WRAPPER_PATH = resolve(
  REPO_ROOT,
  "target/web-e2e-playwright/codex-desktop-visual-server-wrapper.cjs",
);

type Box = {
  x: number;
  y: number;
  width: number;
  height: number;
  right: number;
  bottom: number;
};

type Contract = {
  schema: string;
  viewport: {
    width: number;
    height: number;
    device_scale_factor: number;
  };
  geometry: {
    sidebar_width: number;
    main_header_height: number;
    thread_column_width: number;
    composer_width: number;
    composer_bottom_inset: number;
    composer_radius: number;
    navigation_row_height: number;
    navigation_row_radius: number;
    icon_size: number;
    body_font_size: number;
    body_line_height: number;
    maximum_deviation_css_px: number;
  };
  palette: Record<string, string>;
  selectors: {
    shell: string;
    sidebar: string;
    main_surface: string;
    header: string;
    thread_column: string;
    composer: string;
    secondary_surface: string;
    navigation_row: string;
    selected_row: string;
    sidebar_icon: string;
    primary_text: string;
    secondary_text: string;
    attention: string;
    dynamic: string[];
  };
  visual_diff: {
    maximum_changed_pixel_ratio: number;
    maximum_masked_pixel_ratio: number;
    maximum_channel_deviation: number;
    mask_color: [number, number, number, number];
  };
  session_states: Record<string, string>;
};

type PixelMismatch = {
  changedPixels: number;
  changedPixelRatio: number;
  maximumChannelDeviation: number;
  firstChangedPixel?: { x: number; y: number };
};

type BuiltUi = {
  directory: string;
  assetHref: string;
};

type RestoredServerEnvironment = () => void;
type VisualHarness = Awaited<ReturnType<typeof createWebE2EHarness>>;

type IndexedDbScan = {
  unavailable?: boolean;
  truncated?: boolean;
  [key: string]: unknown;
};

type VisualEvidenceOwner = {
  e2eName: string;
  quarantineRoot: string;
  goldenPath: string;
};

const SHELL_VISUAL_EVIDENCE_OWNER: VisualEvidenceOwner = {
  e2eName: E2E_NAME,
  quarantineRoot: resolve(CALIBRATION_QUARANTINE_ROOT, "shell"),
  goldenPath: GOLDEN_PATH,
};
const SESSION_VISUAL_EVIDENCE_OWNER: VisualEvidenceOwner = {
  e2eName: SESSION_STATES_E2E_NAME,
  quarantineRoot: resolve(CALIBRATION_QUARANTINE_ROOT, "session-states"),
  goldenPath: GOLDEN_PATH,
};

const execFileAsync = promisify(execFile);

class BlockedShallow404 extends HarnessFailure {
  constructor(path: string, status: number) {
    super(
      "BLOCKED_SHALLOW_404",
      `BLOCKED_SHALLOW_404: real management route is still a shallow 404 at ${path} (status ${status}); no visual red or cassette was produced`,
      { path, status, nonEvidence: true },
    );
  }
}

function locateRepositoryRoot(): string {
  const cwd = process.cwd();
  if (existsSync(resolve(cwd, "web/e2e"))) return cwd;
  if (existsSync(resolve(cwd, "../web/e2e"))) return resolve(cwd, "..");
  return resolve(cwd, "../..");
}

function assertContract(contract: Contract): void {
  if (
    contract.schema !== "zode.browser-visual-contract.v1" ||
    contract.viewport.width !== VIEWPORT.width ||
    contract.viewport.height !== VIEWPORT.height ||
    contract.viewport.device_scale_factor !== 1
  ) {
    throw new Error("codex desktop visual contract has an invalid fixed viewport");
  }
}

async function loadContract(): Promise<Contract> {
  const contract = JSON.parse(await readFile(CONTRACT_PATH, "utf8")) as Contract;
  assertContract(contract);
  return contract;
}

function isVersionedAssetHref(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value, "http://zode.invalid");
  } catch {
    return false;
  }
  if (parsed.origin !== "http://zode.invalid" || !parsed.pathname.startsWith("/assets/")) {
    return false;
  }
  const fileName = parsed.pathname.slice("/assets/".length);
  return /^[^/]+-[A-Za-z0-9_-]{8,}\.(?:js|mjs|css)$/i.test(fileName);
}

function parseVersionedAssetHref(html: string, label: string): string {
  const candidates = [...html.matchAll(/(?:src|href)=["']([^"']+)["']/gi)]
    .map((match) => match[1])
    .filter((candidate): candidate is string => typeof candidate === "string")
    .map((candidate) => new URL(candidate, "http://zode.invalid").pathname);
  const assetHref = candidates.find((candidate) => isVersionedAssetHref(candidate));
  if (!assetHref) {
    throw new HarnessFailure(
      "STATIC_ASSET_BEHAVIOR_FAILURE",
      `${label} did not contain an actual hashed asset href/src`,
      { label, nonEvidence: true },
    );
  }
  return assetHref;
}

async function buildTestOwnedUiDist(): Promise<BuiltUi> {
  try {
    await execFileAsync(
      "vp",
      ["build", "--outDir", UI_DIST_DIR],
      { cwd: WEB_ROOT, env: { ...process.env }, timeout: 120_000 },
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new HarnessFailure(
      "STATIC_UI_BUILD_BLOCKED",
      `real vp build did not produce the test-owned UI dist: ${detail}`,
      { directory: UI_DIST_DIR, nonEvidence: true },
    );
  }
  const indexPath = join(UI_DIST_DIR, "index.html");
  const indexMetadata = await stat(indexPath).catch(() => undefined);
  if (!indexMetadata?.isFile()) {
    throw new HarnessFailure(
      "STATIC_UI_BUILD_BLOCKED",
      "real vp build did not produce test-owned dist/index.html",
      { directory: UI_DIST_DIR, nonEvidence: true },
    );
  }
  const index = await readFile(indexPath, "utf8");
  return { directory: UI_DIST_DIR, assetHref: parseVersionedAssetHref(index, "test-owned dist/index.html") };
}

async function installUiAssetsServerWrapper(builtUi: BuiltUi): Promise<RestoredServerEnvironment> {
  const realServerBinary =
    process.env.ZODE_SERVER_BIN ?? resolve(REPO_ROOT, "server/target/debug/zode-server");
  const wrapper = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const args = process.argv.slice(2);
const configIndex = args.indexOf("--config");
const configPath = configIndex >= 0 ? args[configIndex + 1] : undefined;
const realBinary = process.env.ZODE_SERVER_REAL_BIN;
const assetsDirectory = process.env.ZODE_UI_ASSETS_DIRECTORY;
if (!configPath || !realBinary || !assetsDirectory) {
  throw new Error("visual E2E Server wrapper requires --config, real binary, and UI assets directory");
}
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const confinedAssetsDirectory = path.join(path.dirname(configPath), ".zode-visual-ui-" + process.pid);
fs.cpSync(assetsDirectory, confinedAssetsDirectory, {
  recursive: true,
  force: false,
  errorOnExist: true,
});
config.ui_mode = "assets";
config.ui_assets_directory = path.basename(confinedAssetsDirectory);
fs.writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
fs.chmodSync(configPath, 0o600);
const child = spawn(realBinary, args, { cwd: process.cwd(), env: process.env, stdio: "inherit" });
let shuttingDown = false;
for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.on(signal, () => {
    if (!shuttingDown) {
      shuttingDown = true;
      child.kill(signal);
    }
  });
}
child.on("error", (error) => {
  console.error(error);
  process.exitCode = 1;
});
child.on("exit", (code, signal) => {
  process.exitCode = signal ? 128 : (code ?? 1);
});
`;
  await mkdir(dirname(SERVER_WRAPPER_PATH), { recursive: true, mode: 0o700 });
  await writeFile(SERVER_WRAPPER_PATH, wrapper, { mode: 0o700 });
  await chmod(SERVER_WRAPPER_PATH, 0o700);

  const previous = {
    serverBinary: process.env.ZODE_SERVER_BIN,
    realServerBinary: process.env.ZODE_SERVER_REAL_BIN,
    assetsDirectory: process.env.ZODE_UI_ASSETS_DIRECTORY,
  };
  process.env.ZODE_SERVER_BIN = SERVER_WRAPPER_PATH;
  process.env.ZODE_SERVER_REAL_BIN = realServerBinary;
  process.env.ZODE_UI_ASSETS_DIRECTORY = builtUi.directory;
  return () => {
    if (previous.serverBinary === undefined) delete process.env.ZODE_SERVER_BIN;
    else process.env.ZODE_SERVER_BIN = previous.serverBinary;
    if (previous.realServerBinary === undefined) delete process.env.ZODE_SERVER_REAL_BIN;
    else process.env.ZODE_SERVER_REAL_BIN = previous.realServerBinary;
    if (previous.assetsDirectory === undefined) delete process.env.ZODE_UI_ASSETS_DIRECTORY;
    else process.env.ZODE_UI_ASSETS_DIRECTORY = previous.assetsDirectory;
  };
}

function hexToRgb(value: string): [number, number, number] {
  const normalized = value.trim().replace(/^#/, "");
  if (!/^[0-9a-f]{6}$/i.test(normalized)) {
    throw new Error(`invalid visual contract color ${value}`);
  }
  return [
    Number.parseInt(normalized.slice(0, 2), 16),
    Number.parseInt(normalized.slice(2, 4), 16),
    Number.parseInt(normalized.slice(4, 6), 16),
  ];
}

function cssColorToRgb(value: string): [number, number, number] {
  const match = value.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
  if (!match) throw new Error(`computed color is not RGB: ${value}`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function assertColor(actual: string, expected: string, label: string): void {
  const [actualR, actualG, actualB] = cssColorToRgb(actual);
  const [expectedR, expectedG, expectedB] = hexToRgb(expected);
  const deviation = Math.max(
    Math.abs(actualR - expectedR),
    Math.abs(actualG - expectedG),
    Math.abs(actualB - expectedB),
  );
  if (deviation > 1) {
    throw new Error(`${label} color deviated by ${deviation} channels`);
  }
}

async function visibleBox(page: Page, selector: string, label: string): Promise<Box> {
  const locator = page.locator(selector).first();
  await expect(locator, `${label} must be rendered by the real UI`).toBeVisible();
  const box = await locator.boundingBox();
  if (!box) throw new Error(`${label} has no measurable box`);
  return {
    ...box,
    right: box.x + box.width,
    bottom: box.y + box.height,
  };
}

function assertWithin(actual: number, expected: number, tolerance: number, label: string): void {
  if (Math.abs(actual - expected) > tolerance) {
    throw new Error(`${label} expected ${expected}±${tolerance}, received ${actual}`);
  }
}

async function assertShellGeometry(page: Page, contract: Contract): Promise<void> {
  const selectors = contract.selectors;
  const sidebar = await visibleBox(page, selectors.sidebar, "sidebar");
  const main = await visibleBox(page, selectors.main_surface, "main surface");
  const header = await visibleBox(page, selectors.header, "main header");
  const thread = await visibleBox(page, selectors.thread_column, "thread column");
  const composer = await visibleBox(page, selectors.composer, "composer");
  const tolerance = contract.geometry.maximum_deviation_css_px;

  assertWithin(sidebar.x, 0, tolerance, "sidebar left edge");
  assertWithin(sidebar.width, contract.geometry.sidebar_width, tolerance, "sidebar width");
  assertWithin(sidebar.height, VIEWPORT.height, tolerance, "sidebar height");
  assertWithin(main.x, contract.geometry.sidebar_width, tolerance, "main left edge");
  assertWithin(main.width, VIEWPORT.width - contract.geometry.sidebar_width, tolerance, "main width");
  assertWithin(header.height, contract.geometry.main_header_height, tolerance, "main header height");
  assertWithin(thread.width, contract.geometry.thread_column_width, tolerance, "thread column width");
  assertWithin(composer.width, contract.geometry.composer_width, tolerance, "composer width");
  assertWithin(
    thread.x,
    contract.geometry.sidebar_width +
      (VIEWPORT.width - contract.geometry.sidebar_width - contract.geometry.thread_column_width) / 2,
    tolerance,
    "thread column centering",
  );
  assertWithin(composer.x, thread.x, tolerance, "composer left alignment");
  assertWithin(composer.bottom, VIEWPORT.height - contract.geometry.composer_bottom_inset, tolerance, "composer bottom inset");

  const bodyStyle = await page.locator("body").evaluate((element) => {
    const style = getComputedStyle(element);
    return { fontSize: Number.parseFloat(style.fontSize), lineHeight: Number.parseFloat(style.lineHeight) };
  });
  if (!Number.isFinite(bodyStyle.fontSize) || !Number.isFinite(bodyStyle.lineHeight)) {
    throw new Error("body typography did not expose numeric font-size and line-height values");
  }
  assertWithin(bodyStyle.fontSize, contract.geometry.body_font_size, tolerance, "body font size");
  assertWithin(bodyStyle.lineHeight, contract.geometry.body_line_height, tolerance, "body line height");

  const navigationRows = page.locator(selectors.navigation_row);
  const rowCount = await navigationRows.count();
  if (rowCount < 4) throw new Error("sidebar did not expose the four primary navigation destinations");
  for (let index = 0; index < rowCount; index += 1) {
    const row = navigationRows.nth(index);
    const rowBox = await row.boundingBox();
    if (!rowBox) throw new Error(`navigation row ${index} has no measurable box`);
    assertWithin(rowBox.height, contract.geometry.navigation_row_height, tolerance, `navigation row ${index} height`);
    const radius = await row.evaluate((element) => getComputedStyle(element).borderRadius);
    if (!radius.startsWith(`${contract.geometry.navigation_row_radius}px`)) {
      throw new Error(`navigation row ${index} radius is ${radius}`);
    }
  }

  const icons = page.locator(selectors.sidebar_icon);
  if ((await icons.count()) === 0) throw new Error("sidebar did not expose monochrome navigation icons");
  for (let index = 0; index < await icons.count(); index += 1) {
    const iconBox = await icons.nth(index).boundingBox();
    if (!iconBox) throw new Error(`navigation icon ${index} has no measurable box`);
    assertWithin(iconBox.width, contract.geometry.icon_size, tolerance, `navigation icon ${index} width`);
    assertWithin(iconBox.height, contract.geometry.icon_size, tolerance, `navigation icon ${index} height`);
  }

  const composerRadius = await page.locator(selectors.composer).first().evaluate((element) => getComputedStyle(element).borderRadius);
  if (!composerRadius.startsWith(`${contract.geometry.composer_radius}px`)) {
    throw new Error(`composer radius is ${composerRadius}`);
  }

}

async function assertShellPalette(page: Page, contract: Contract): Promise<void> {
  const paletteSelectors: Array<[string, string, string]> = [
    [contract.selectors.sidebar, "backgroundColor", contract.palette.sidebar],
    [contract.selectors.selected_row, "backgroundColor", contract.palette.selected_row],
    [contract.selectors.main_surface, "backgroundColor", contract.palette.main],
    [contract.selectors.composer, "backgroundColor", contract.palette.composer],
    [contract.selectors.secondary_surface, "backgroundColor", contract.palette.secondary_surface],
    [contract.selectors.primary_text, "color", contract.palette.primary_text],
    [contract.selectors.secondary_text, "color", contract.palette.secondary_text],
    [contract.selectors.attention, "color", contract.palette.attention],
  ];
  for (const [selector, property, expected] of paletteSelectors) {
    const locator = page.locator(selector).first();
    await expect(locator, `${selector} must expose its semantic visual surface`).toBeVisible();
    const actual = await locator.evaluate((element, styleProperty) => {
      const style = getComputedStyle(element);
      return style.getPropertyValue(styleProperty) ||
        (style as unknown as Record<string, string>)[styleProperty] ||
        "";
    }, property);
    assertColor(actual, expected, `${selector} ${property}`);
  }

  const fontFamily = await page.locator(contract.selectors.shell).first().evaluate((element) => getComputedStyle(element).fontFamily);
  if (!/(?:-apple-system|BlinkMacSystemFont|Segoe UI)/i.test(fontFamily)) {
    throw new Error(`shell typography is not the approved system sans stack: ${fontFamily}`);
  }
}

async function assertShellStates(page: Page, contract: Contract): Promise<void> {
  const selected = page.locator(contract.selectors.selected_row).first();
  await expect(selected, "selected navigation state must be explicit").toBeVisible();
  const selectedState = await selected.getAttribute("data-zode-state");
  if (!selectedState?.includes("selected")) throw new Error("selected navigation row did not expose selected state");

  const composer = page.locator(contract.selectors.composer).first();
  await composer.locator("textarea").first().focus();
  const focusState = await composer.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      focusWithin: element.matches(":focus-within"),
      focusVisible: element.matches(":focus-visible") || Boolean(element.querySelector(":focus-visible")),
      outlineStyle: style.outlineStyle,
      outlineWidth: style.outlineWidth,
      boxShadow: style.boxShadow,
    };
  });
  if (!focusState.focusWithin || !focusState.focusVisible || (focusState.outlineWidth === "0px" && focusState.boxShadow === "none")) {
    throw new Error("composer focus state is not visibly exposed");
  }

  const hoverTarget = page.locator(contract.selectors.navigation_row).nth(1);
  await hoverTarget.hover();
  const hoverState = await hoverTarget.evaluate((element) => element.matches(":hover"));
  if (!hoverState) throw new Error("navigation hover state could not be observed");
  await composer.locator("textarea").first().focus();
}

async function assertKeyboardAndAccessibility(page: Page, contract: Contract): Promise<void> {
  const interactive = page.locator(
    'button:visible, a:visible, input:visible, textarea:visible, select:visible, [role="button"]:visible, [tabindex]:visible',
  );
  const interactiveCount = await interactive.count();
  if (interactiveCount === 0) throw new Error("shell did not expose keyboard-accessible controls");
  for (let index = 0; index < interactiveCount; index += 1) {
    const control = interactive.nth(index);
    const name = await control.evaluate((element) => {
      const labelledBy = element.getAttribute("aria-labelledby");
      const labelledText = labelledBy
        ? labelledBy
            .split(/\s+/)
            .map((id) => document.getElementById(id)?.textContent ?? "")
            .join(" ")
        : "";
      const accessibleName =
        element.getAttribute("aria-label") ||
        labelledText ||
        element.getAttribute("title") ||
        element.getAttribute("alt") ||
        element.textContent ||
        "";
      return accessibleName.trim();
    });
    if (!name) throw new Error(`interactive control ${index} has no accessible name`);
  }

  const liveRegions = page.locator(
    '[aria-live="polite"], [aria-live="assertive"], [role="status"], [role="alert"], [role="log"]',
  );
  if ((await liveRegions.count()) === 0) throw new Error("shell did not expose a live state region");

  const originalFocus = await page.evaluateHandle(() => document.activeElement);
  await page.keyboard.press("Tab");
  const firstFocused = await page.evaluate(() => {
    const element = document.activeElement;
    if (!(element instanceof HTMLElement)) return { name: "", tag: "" };
    return {
      name: element.getAttribute("aria-label") || element.textContent?.trim() || element.getAttribute("title") || "",
      tag: element.tagName,
      focusVisible: element.matches(":focus-visible"),
    };
  });
  if (!firstFocused.name || !firstFocused.focusVisible) throw new Error("Tab did not land on an accessible focus-visible control");

  await page.keyboard.press("Shift+Tab");
  const reverseFocused = await page.evaluate((original) => {
    const element = document.activeElement;
    if (!(element instanceof HTMLElement)) {
      return { sameElement: false, name: "", focusVisible: false };
    }
    return {
      sameElement: element === original,
      name: element.getAttribute("aria-label") || element.textContent?.trim() || element.getAttribute("title") || "",
      focusVisible: element.matches(":focus-visible"),
    };
  }, originalFocus);
  await originalFocus.dispose();
  if (!reverseFocused.sameElement || !reverseFocused.name || !reverseFocused.focusVisible) {
    throw new Error("Shift+Tab did not return to the original accessible focus-visible element");
  }

  const activationTarget = page.locator(contract.selectors.navigation_row).first();
  const sessionUrl = page.url();
  await activationTarget.focus();
  await activationTarget.press("Enter");
  if (!(await activationTarget.evaluate((element) => document.activeElement === element && element.matches(":focus-visible")))) {
    throw new Error("keyboard activation did not preserve a visible focus target");
  }
  // The selected Sessions row is a real navigation control: activating it
  // returns to the session list.  Restore the public session route before
  // continuing shell assertions so this helper does not mistake a legitimate
  // route transition for a missing composer.
  if (page.url() !== sessionUrl) {
    await page.goto(sessionUrl, { waitUntil: "domcontentloaded" });
    await expect(page.locator(contract.selectors.composer).first()).toBeVisible();
  }
  await page.locator(contract.selectors.composer).first().locator("textarea").focus();
}

async function assertNoSecretMarkers(
  page: Page,
  harness: { controllerSecret?: string; providerSecret?: string },
  testInfo: TestInfo,
  responseBodies: Array<Promise<string>>,
  downloadBodies: Array<Promise<Buffer>>,
  browserSecretGuard: BrowserSecretGuard,
): Promise<void> {
  await browserSecretGuard.scanPage(page);
  await scanIndexedDbFailClosed(page, browserSecretGuard);
  const visibleText = await page.locator("body").innerText();
  const browserState = await page.evaluate(() => JSON.stringify({
    html: document.documentElement.outerHTML,
    localStorage: Object.fromEntries(Object.entries(localStorage)),
    sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
    cookies: document.cookie,
    url: location.href,
    historyState: history.state,
    accessibleNames: Array.from(document.querySelectorAll<HTMLElement>(
      'button, a, input, textarea, select, [role="button"], [tabindex]',
    )).map((element) => (
      element.getAttribute("aria-label") ||
      element.getAttribute("title") ||
      element.textContent ||
      ""
    )),
  }));
  const secretMarkers = [
    harness.controllerSecret,
    harness.providerSecret,
    "-----BEGIN RSA PRIVATE KEY-----",
    SYNTHETIC_SECRET_MARKER,
  ].filter((marker): marker is string => typeof marker === "string" && marker.length > 0);
  const evidence = [
    visibleText,
    browserState,
    await page.evaluate(async (marker) => {
      const response = await fetch("/v1/system", {
        headers: { "x-zode-e2e-synthetic-secret": marker },
      });
      return `${response.url}\n${await response.text()}`;
    }, SYNTHETIC_SECRET_MARKER),
    ...(await Promise.all(responseBodies)),
    ...(await Promise.all(downloadBodies)),
    ...browserSecretGuard.consoleMessages,
    ...browserSecretGuard.pageErrors,
    await page.screenshot({ animations: "disabled", caret: "hide", fullPage: false }),
  ];
  for (const attachment of testInfo.attachments) {
    if (!attachment.path) continue;
    evidence.push(await readFile(attachment.path).catch(() => Buffer.alloc(0)));
  }
  for (const marker of secretMarkers) {
    if (evidence.some((value) => value.toString().includes(marker))) {
      throw new Error("browser UI exposed a protected secret marker");
    }
  }
  if (evidence.some((value) => /(?:^|\W)Bearer\s+[A-Za-z0-9._~-]{20,}/i.test(value.toString()))) {
    throw new Error("browser UI exposed a bearer credential marker");
  }
  browserSecretGuard.assertNoLeaks();
}

async function scanIndexedDbFailClosed(
  page: Page,
  browserSecretGuard: BrowserSecretGuard,
): Promise<IndexedDbScan> {
  const scan = await browserSecretGuard.scanIndexedDb(page) as IndexedDbScan;
  if (scan.unavailable !== false || scan.truncated !== false) {
    throw new ProductBehaviorFailure(
      "SECRET_SCAN_INCOMPLETE",
      "browser IndexedDB secret scan is unavailable or truncated; no-leak evidence is rejected",
      { unavailable: scan.unavailable, truncated: scan.truncated },
    );
  }
  return scan;
}

async function flushVisualSecretGuard(
  page: Page,
  browserSecretGuard: BrowserSecretGuard,
): Promise<void> {
  await browserSecretGuard.scanPage(page);
  await scanIndexedDbFailClosed(page, browserSecretGuard);
  browserSecretGuard.assertNoLeaks();
}

async function waitForCurrentRunJwks(harness: VisualHarness): Promise<void> {
  try {
    await harness.access.waitForJwksRequest();
  } catch {
    throw new ProductBehaviorFailure(
      "ACCESS_ASSERTION_VERIFICATION_NOT_OBSERVED",
      "real Access edge forwarded an assertion but the Server did not request the current run's fixture JWKS",
    );
  }
}

function retainPrimaryFailure(current: unknown, next: unknown): unknown {
  if (!next) return current;
  if (next instanceof SecretLeakFailure) return next;
  return current ?? next;
}

async function retainFirstVisualFailure({
  error,
  e2eName,
  harness,
  page,
  testInfo,
  browserSecretGuard,
}: {
  error: unknown;
  e2eName: string;
  harness: VisualHarness | undefined;
  page: Page;
  testInfo: TestInfo;
  browserSecretGuard: BrowserSecretGuard | undefined;
}): Promise<unknown> {
  let retainedError = error;
  if (browserSecretGuard) {
    try {
      const screenshotPath = await browserSecretGuard.captureSafeScreenshot(page, testInfo);
      if (screenshotPath) {
        await testInfo.attach("first-visual-failure", {
          path: screenshotPath,
          contentType: "image/png",
        });
      } else if (!browserSecretGuard.violations.some((violation) => violation.surface === "failure screenshot")) {
        retainedError = new HarnessFailure(
          "FIRST_FAILURE_ARTIFACT_GAP",
          "first visual failure could not be retained as a secret-safe browser artifact",
        );
      }
    } catch {
      retainedError = new HarnessFailure(
        "FIRST_FAILURE_ARTIFACT_GAP",
        "first visual failure could not be retained as a secret-safe browser artifact",
      );
    }
  }

  if (harness) {
    try {
      const evidence = await harness.captureAndReplayFailure(error, e2eName);
      const details = error instanceof HarnessFailure
        ? (error as HarnessFailure & { details?: { nonEvidence?: boolean; path?: unknown; status?: unknown } }).details
        : undefined;
      if (
        error instanceof HarnessFailure &&
        !details?.nonEvidence &&
        typeof details?.path === "string" &&
        typeof details?.status === "number" &&
        !evidence.record
      ) {
        throw new HarnessFailure(
          "FIRST_FAILURE_REPLAY_GAP",
          "first visual HTTP failure was not retained as a replayable exchange",
        );
      }
    } catch {
      retainedError = new HarnessFailure(
        "FIRST_FAILURE_REPLAY_GAP",
        "first visual failure was retained but secret-safe replay did not reproduce it",
      );
    }
  }
  return retainedError;
}

function attachVisualBrowserSecretGuard(
  harness: Awaited<ReturnType<typeof createWebE2EHarness>>,
  page: Page,
): BrowserSecretGuard {
  harness.ledger.add("visual_synthetic_secret_marker", SYNTHETIC_SECRET_MARKER);
  return new BrowserSecretGuard({
    ledger: harness.ledger,
    context: page.context(),
  });
}

async function writeSyntheticIndexedDbMarker(page: Page): Promise<void> {
  await page.evaluate((marker) => new Promise<void>((resolve, reject) => {
    const openRequest = indexedDB.open("zode-visual-e2e-test-owned", 1);
    openRequest.onerror = () => reject(openRequest.error ?? new Error("IndexedDB open failed"));
    openRequest.onupgradeneeded = () => {
      const database = openRequest.result;
      if (!database.objectStoreNames.contains("markers")) {
        database.createObjectStore("markers");
      }
    };
    openRequest.onsuccess = () => {
      const database = openRequest.result;
      let transaction: IDBTransaction;
      try {
        transaction = database.transaction("markers", "readwrite");
        transaction.objectStore("markers").put(marker, "synthetic-secret-marker");
      } catch (error) {
        database.close();
        reject(error);
        return;
      }
      transaction.oncomplete = () => {
        database.close();
        resolve();
      };
      transaction.onerror = () => {
        database.close();
        reject(transaction.error ?? new Error("IndexedDB write failed"));
      };
      transaction.onabort = () => {
        database.close();
        reject(transaction.error ?? new Error("IndexedDB write aborted"));
      };
    };
  }), SYNTHETIC_SECRET_MARKER);
}

async function assertSyntheticIndexedDbGuardGate(
  page: Page,
  browserSecretGuard: BrowserSecretGuard,
): Promise<void> {
  await writeSyntheticIndexedDbMarker(page);
  const scan = await scanIndexedDbFailClosed(page, browserSecretGuard);
  const scanText = JSON.stringify(scan);
  if (!scanText.includes(SYNTHETIC_SECRET_MARKER)) {
    throw new ProductBehaviorFailure(
      "SECRET_SCAN_MISSED_SYNTHETIC_MARKER",
      "browser IndexedDB scan did not return the test-owned synthetic marker",
      { surface: "browser IndexedDB values" },
    );
  }
  const indexedDbViolation = browserSecretGuard.violations?.find(
    (violation: { surface?: string }) => violation.surface === "browser IndexedDB values",
  );
  if (!indexedDbViolation) {
    throw new ProductBehaviorFailure(
      "SECRET_SCAN_MISSED_SYNTHETIC_MARKER",
      "BrowserSecretGuard did not record the IndexedDB marker on the authoritative surface",
      { surface: "browser IndexedDB values" },
    );
  }
  try {
    browserSecretGuard.assertNoLeaks();
  } catch (error) {
    const details = error instanceof SecretLeakFailure
      ? (error as SecretLeakFailure & { details?: { surface?: unknown } }).details
      : undefined;
    if (details?.surface === "browser IndexedDB values") return;
    throw error;
  }
  throw new ProductBehaviorFailure(
    "SECRET_SCAN_DID_NOT_FAIL",
    "BrowserSecretGuard failed to reject a synthetic IndexedDB secret marker",
    { surface: "browser IndexedDB values" },
  );
}

async function assertSessionStateContract(
  page: Page,
  contract: Contract,
  observedStates: Set<string>,
): Promise<void> {
  const requiredStates = ["stream", "wait", "tool", "error", "reconnect", "focus"];
  for (const state of requiredStates) {
    const selector = contract.session_states[state];
    if (!selector) throw new Error(`visual contract omitted the ${state} session state selector`);
    if (!observedStates.has(state)) {
      throw new Error(`${state} state was not observed through the real public session flow`);
    }
  }
  await expect(page.locator(contract.session_states.focus).first()).toBeVisible();
}

async function driveRealSessionStateFlow(
  page: Page,
  harness: Awaited<ReturnType<typeof createWebE2EHarness>>,
  contract: Contract,
): Promise<Set<string>> {
  const observedStates = new Set<string>();
  const messageResponse = page.waitForResponse(
    (response) => new URL(response.url()).pathname.endsWith("/messages") && response.request().method() === "POST",
  );
  const composer = page.locator(contract.selectors.composer).first();
  const input = composer.locator("textarea").first();
  await input.focus();
  await input.fill("visual state stream wait tool error reconnect barrier");
  await input.press("Enter");
  const message = await messageResponse;
  if (message.status() !== 202) {
    throw new ProductBehaviorFailure(
      "SESSION_STATE_BEHAVIOR_FAILURE",
      `public Server message admission returned HTTP ${message.status()}`,
      { status: message.status() },
    );
  }
  const sessionRoute = new URL(page.url()).pathname.match(/^\/endpoints\/([^/]+)\/sessions\/([^/]+)$/);
  if (!sessionRoute) throw new Error("visual session route did not expose Endpoint and session identity");
  const eventsPath = `/v1/endpoints/${sessionRoute[1]}/sessions/${sessionRoute[2]}/events`;
  const streamProbe = await page.evaluate(async ({ path }) => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 8_000);
    try {
      const response = await fetch(path, {
        headers: { accept: "text/event-stream" },
        signal: controller.signal,
      });
      const first = response.body ? await response.body.getReader().read() : undefined;
      return {
        status: response.status,
        contentType: response.headers.get("content-type") ?? "",
        observedBytes: first?.value?.byteLength ?? 0,
      };
    } finally {
      window.clearTimeout(timer);
      controller.abort();
    }
  }, { path: eventsPath });
  expect(streamProbe.status).toBe(200);
  expect(streamProbe.contentType).toMatch(/^text\/event-stream(?:;|$)/i);
  expect(streamProbe.observedBytes).toBeGreaterThan(0);
  await expect(page.locator(contract.session_states.stream).first()).toBeVisible();
  observedStates.add("stream");
  for (const state of ["wait", "tool", "error"]) {
    await expect(page.locator(contract.session_states[state]).first()).toBeVisible({
      timeout: 20_000,
    });
    observedStates.add(state);
  }

  const routeBeforeRestart = (() => {
    const current = new URL(page.url());
    return `${current.pathname}${current.search}${current.hash}`;
  })();
  await harness.server.stop();
  await expect(page.locator(contract.session_states.reconnect).first()).toBeVisible({
    timeout: 10_000,
  });
  observedStates.add("reconnect");
  await harness.restartServer();
  await assertManagementSystemBarrier(page, harness.managementUrl);
  await gotoOrBlock(
    page,
    new URL(routeBeforeRestart, harness.managementUrl).toString(),
    routeBeforeRestart,
  );
  await composer.locator("textarea").first().focus();
  await expect(composer).toBeFocused();
  observedStates.add("focus");
  return observedStates;
}

async function dynamicMaskBoxes(page: Page, contract: Contract): Promise<Box[]> {
  const result = await page.evaluate((input) => {
    const boxes: Box[] = [];
    const protectedSelector = [
      ":focus",
      ":focus-within",
      "[aria-live]",
      '[role="status"]',
      '[role="alert"]',
      '[role="log"]',
      "button",
      "a",
      "input",
      "textarea",
      "select",
      "[role=button]",
      "[data-zode-control]",
      "[tabindex]",
    ].join(",");
    const hardProtectedRegions = [
      ["sidebar", input.selectors.sidebar],
      ["header", input.selectors.header],
      ["composer", input.selectors.composer],
      ["navigation", input.selectors.navigation_row],
      ["selected navigation", input.selectors.selected_row],
      ["secondary surface", input.selectors.secondary_surface],
    ] as const;
    const largeSurfaceRegions = [
      ["shell", input.selectors.shell],
      ["main surface", input.selectors.main_surface],
      ["thread column", input.selectors.thread_column],
    ] as const;
    const rectFor = (element: Element): Box => {
      const rect = element.getBoundingClientRect();
      return {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
        right: rect.right,
        bottom: rect.bottom,
      };
    };
    const intersects = (left: Box, right: Box): boolean =>
      left.x < right.right && left.right > right.x && left.y < right.bottom && left.bottom > right.y;
    const area = (box: Box): number => Math.max(0, box.width) * Math.max(0, box.height);
    const expand = (box: Box, amount: number): Box => ({
      x: box.x - amount,
      y: box.y - amount,
      width: box.width + amount * 2,
      height: box.height + amount * 2,
      right: box.right + amount,
      bottom: box.bottom + amount,
    });
    const pixels = (value: string, fallback = 0): number => {
      const parsed = Number.parseFloat(value);
      return Number.isFinite(parsed) ? Math.max(0, parsed) : fallback;
    };
    const focusRingBox = (element: HTMLElement): Box => {
      const style = getComputedStyle(element);
      let expansion = 0;
      if (style.outlineStyle !== "none") {
        expansion = Math.max(
          expansion,
          pixels(style.outlineWidth, 2) + pixels(style.outlineOffset),
        );
      }
      if (style.boxShadow !== "none") {
        const values = style.boxShadow.match(/-?(?:\d+(?:\.\d+)?|\.\d+)px/g)?.map(Number) ?? [];
        if (values.length >= 2) {
          const blur = Math.max(0, values[2] ?? 0);
          const spread = values[3] ?? 0;
          expansion = Math.max(
            expansion,
            Math.abs(values[0] ?? 0) + blur + Math.max(0, spread),
            Math.abs(values[1] ?? 0) + blur + Math.max(0, spread),
          );
        }
      }
      return expand(rectFor(element), expansion);
    };
    const protectedGeometry = [
      ...Array.from(document.querySelectorAll<HTMLElement>(protectedSelector)).map((element) => ({
        label: `protected ${element.tagName.toLowerCase()}${element.getAttribute("role") ? ` role=${element.getAttribute("role")}` : ""}`,
        box: rectFor(element),
      })),
      ...Array.from(document.querySelectorAll<HTMLElement>(":focus-visible")).map((element) => ({
        label: `focus ring ${element.tagName.toLowerCase()}`,
        box: focusRingBox(element),
      })),
    ];
    for (const selector of input.dynamicSelectors) {
      for (const element of Array.from(document.querySelectorAll<HTMLElement>(selector))) {
        const rect = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        if (rect.width <= 0 || rect.height <= 0 || style.visibility === "hidden" || style.display === "none") continue;
        if (element.matches(protectedSelector) || element.closest(protectedSelector)) {
          throw new Error(`dynamic mask selector ${selector} overlaps focus, status, or a control`);
        }
        const box = rectFor(element);
        for (const protectedItem of protectedGeometry) {
          if (intersects(box, protectedItem.box)) {
            throw new Error(`dynamic mask selector ${selector} overlaps ${protectedItem.label}`);
          }
        }
        for (const [label, regionSelector] of hardProtectedRegions) {
          for (const region of Array.from(document.querySelectorAll<HTMLElement>(regionSelector))) {
            if (intersects(box, rectFor(region))) {
              throw new Error(`dynamic mask selector ${selector} overlaps ${label} layout`);
            }
          }
        }
        for (const [label, regionSelector] of largeSurfaceRegions) {
          for (const region of Array.from(document.querySelectorAll<HTMLElement>(regionSelector))) {
            const regionBox = rectFor(region);
            if (area(regionBox) > 0 && area(box) / area(regionBox) > 0.9) {
              throw new Error(`dynamic mask selector ${selector} covers the ${label} surface`);
            }
          }
        }
        boxes.push(box);
      }
    }
    const maskedArea = boxes.reduce((total, box) => total + area(box), 0);
    if (maskedArea > input.viewport.width * input.viewport.height * input.maximumMaskedPixelRatio) {
      throw new Error("dynamic visual masks exceed the approved total-area bound");
    }
    return boxes;
  }, {
    dynamicSelectors: contract.selectors.dynamic,
    selectors: contract.selectors,
    viewport: VIEWPORT,
    maximumMaskedPixelRatio: contract.visual_diff.maximum_masked_pixel_ratio,
  });
  return result;
}

async function extractRenderedAssetHref(page: Page, label: string): Promise<string> {
  const candidates = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLScriptElement | HTMLLinkElement>("script[src], link[href]"))
      .map((element) => element instanceof HTMLScriptElement ? element.src : element.href)
      .filter((value) => value.length > 0),
  );
  const assetHref = candidates
    .map((candidate) => new URL(candidate, page.url()))
    .find((candidate) => isVersionedAssetHref(candidate.pathname));
  if (!assetHref) {
    throw new HarnessFailure(
      "STATIC_ASSET_BEHAVIOR_FAILURE",
      `${label} did not contain an actual hashed asset href/src`,
      { label, nonEvidence: true },
    );
  }
  return `${assetHref.pathname}${assetHref.search}`;
}

function assertSafeHtmlCache(response: Response | null, label: string): void {
  const cacheControl = response?.headers()["cache-control"]?.toLowerCase() ?? "";
  if (!cacheControl.includes("no-cache") && !cacheControl.includes("no-store")) {
    throw new ProductBehaviorFailure(
      "STATIC_HTML_CACHE_BEHAVIOR_FAILURE",
      `${label} used a cacheable HTML policy`,
      { label, cacheControl },
    );
  }
}

function assertPositiveImmutableCache(cacheControl: string, label: string): void {
  const hasPositiveMaxAge = cacheControl
    .split(",")
    .map((directive) => directive.trim())
    .some((directive) => {
      const value = directive.match(/^max-age=(\d+)$/i)?.[1];
      return value !== undefined && Number.parseInt(value, 10) > 0;
    });
  if (!hasPositiveMaxAge || !cacheControl.toLowerCase().includes("immutable")) {
    throw new ProductBehaviorFailure(
      "STATIC_ASSET_CACHE_BEHAVIOR_FAILURE",
      `${label} did not use a positive immutable cache policy`,
      { label, cacheControl },
    );
  }
}

async function assertRenderedAsset(page: Page, assetHref: string, label: string): Promise<void> {
  const result = await page.evaluate(async (href) => {
    const response = await fetch(href, { cache: "no-store" });
    const body = await response.text();
    return {
      status: response.status,
      contentType: response.headers.get("content-type") ?? "",
      cacheControl: response.headers.get("cache-control") ?? "",
      bodyPrefix: body.slice(0, 256),
    };
  }, assetHref);
  if (result.status !== 200) {
    throw new ProductBehaviorFailure(
      "STATIC_ASSET_BEHAVIOR_FAILURE",
      `${label} returned HTTP ${result.status}`,
      { label, status: result.status, nonEvidence: true },
    );
  }
  if (!/(?:javascript|ecmascript|text\/css)/i.test(result.contentType)) {
    throw new ProductBehaviorFailure(
      "STATIC_ASSET_BEHAVIOR_FAILURE",
      `${label} did not return a JavaScript or CSS content type`,
      { label, contentType: result.contentType },
    );
  }
  if (/<!doctype html|<html[\s>]/i.test(result.bodyPrefix)) {
    throw new ProductBehaviorFailure(
      "STATIC_ASSET_BEHAVIOR_FAILURE",
      `${label} was swallowed by the SPA HTML fallback`,
      { label },
    );
  }
  assertPositiveImmutableCache(result.cacheControl, label);
}

async function compareScreenshotsInBrowser(
  page: Page,
  referenceBytes: Buffer,
  actualBytes: Buffer,
  boxes: Box[],
  maskColor: [number, number, number, number],
): Promise<PixelMismatch> {
  return page.evaluate(async ({ referenceData, actualData, dynamicBoxes, color }) => {
    const loadImage = (data: string) => new Promise<HTMLImageElement>((resolve, reject) => {
      const image = new Image();
      image.onload = () => resolve(image);
      image.onerror = () => reject(new Error("screenshot PNG could not be decoded by the browser"));
      image.src = `data:image/png;base64,${data}`;
    });
    const [referenceImage, actualImage] = await Promise.all([
      loadImage(referenceData),
      loadImage(actualData),
    ]);
    if (
      referenceImage.naturalWidth !== actualImage.naturalWidth ||
      referenceImage.naturalHeight !== actualImage.naturalHeight
    ) {
      throw new Error(
        `visual screenshot dimensions differ: ${actualImage.naturalWidth}x${actualImage.naturalHeight} vs ${referenceImage.naturalWidth}x${referenceImage.naturalHeight}`,
      );
    }
    const width = actualImage.naturalWidth;
    const height = actualImage.naturalHeight;
    const makeData = (image: HTMLImageElement) => {
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) throw new Error("browser canvas context is unavailable for visual diff");
      context.drawImage(image, 0, 0);
      return context.getImageData(0, 0, width, height);
    };
    const reference = makeData(referenceImage);
    const actual = makeData(actualImage);
    for (const image of [reference, actual]) {
      for (const box of dynamicBoxes) {
        const left = Math.max(0, Math.floor(box.x));
        const top = Math.max(0, Math.floor(box.y));
        const right = Math.min(width, Math.ceil(box.right));
        const bottom = Math.min(height, Math.ceil(box.bottom));
        for (let y = top; y < bottom; y += 1) {
          for (let x = left; x < right; x += 1) {
            const pixel = (y * width + x) * 4;
            image.data[pixel] = color[0];
            image.data[pixel + 1] = color[1];
            image.data[pixel + 2] = color[2];
            image.data[pixel + 3] = color[3];
          }
        }
      }
    }
    let changedPixels = 0;
    let maximumChannelDeviation = 0;
    let firstChangedPixel;
    for (let pixel = 0; pixel < actual.data.length; pixel += 4) {
      const deviation = Math.max(
        Math.abs(actual.data[pixel] - reference.data[pixel]),
        Math.abs(actual.data[pixel + 1] - reference.data[pixel + 1]),
        Math.abs(actual.data[pixel + 2] - reference.data[pixel + 2]),
        Math.abs(actual.data[pixel + 3] - reference.data[pixel + 3]),
      );
      maximumChannelDeviation = Math.max(maximumChannelDeviation, deviation);
      if (deviation === 0) continue;
      changedPixels += 1;
      if (!firstChangedPixel) {
        const index = pixel / 4;
        firstChangedPixel = { x: index % width, y: Math.floor(index / width) };
      }
    }
    return {
      changedPixels,
      changedPixelRatio: changedPixels / (width * height),
      maximumChannelDeviation,
      firstChangedPixel,
    };
  }, {
    referenceData: referenceBytes.toString("base64"),
    actualData: actualBytes.toString("base64"),
    dynamicBoxes: boxes,
    color: maskColor,
  });
}

function calibrationSourcePath(): string | undefined {
  if (process.env.CI || process.env[CALIBRATION_ENABLE_ENV] !== "1") return undefined;
  const source = process.env[CALIBRATION_SOURCE_ENV];
  if (!source) {
    throw new HarnessFailure(
      "CALIBRATION_SOURCE_MISSING",
      `${CALIBRATION_SOURCE_ENV} is required when ${CALIBRATION_ENABLE_ENV}=1`,
      { nonEvidence: true },
    );
  }
  if (!isAbsolute(source)) {
    throw new HarnessFailure(
      "CALIBRATION_SOURCE_NOT_ABSOLUTE",
      "visual calibration source must be an absolute external path",
      { nonEvidence: true },
    );
  }
  return source;
}

function visualMismatchExceeded(mismatch: PixelMismatch, contract: Contract): boolean {
  return (
    mismatch.changedPixelRatio > contract.visual_diff.maximum_changed_pixel_ratio ||
    mismatch.maximumChannelDeviation > contract.visual_diff.maximum_channel_deviation
  );
}

async function writeFirstOnly(
  path: string,
  content: Buffer | string,
  mode: number,
): Promise<boolean> {
  let handle;
  try {
    handle = await open(path, "wx", mode);
    await handle.writeFile(content);
    await handle.sync();
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    return false;
  } finally {
    await handle?.close();
  }
}

async function retainCalibrationMismatch(
  mismatch: PixelMismatch,
  actualBytes: Buffer,
  referenceBytes: Buffer,
  owner: VisualEvidenceOwner,
): Promise<void> {
  await mkdir(owner.quarantineRoot, { recursive: true, mode: 0o700 });
  await chmod(owner.quarantineRoot, 0o700);
  const evidence = {
    schema: "zode.browser-visual-calibration-mismatch.v1",
    e2e_name: owner.e2eName,
    viewport: VIEWPORT,
    reference_sha256: createHash("sha256").update(referenceBytes).digest("hex"),
    actual_sha256: createHash("sha256").update(actualBytes).digest("hex"),
    changed_pixels: mismatch.changedPixels,
    changed_pixel_ratio: mismatch.changedPixelRatio,
    maximum_channel_deviation: mismatch.maximumChannelDeviation,
    first_changed_pixel: mismatch.firstChangedPixel ?? null,
  };
  await writeFirstOnly(
    join(owner.quarantineRoot, "first-mismatch.v1.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
    0o600,
  );
  await writeFirstOnly(
    join(owner.quarantineRoot, "first-mismatch.actual.png"),
    actualBytes,
    0o600,
  );
}

async function promoteAcceptedGolden(
  actualBytes: Buffer,
  goldenPath: string,
): Promise<void> {
  await mkdir(FIXTURE_ROOT, { recursive: true });
  const promoted = await writeFirstOnly(goldenPath, actualBytes, 0o600);
  if (!promoted) {
    throw new HarnessFailure(
      "VISUAL_GOLDEN_EXISTS",
      "accepted visual golden already exists and will not be overwritten",
      { nonEvidence: true },
    );
  }
  await chmod(goldenPath, 0o444);
}

async function assertMaskedReference(
  page: Page,
  contract: Contract,
  owner: VisualEvidenceOwner,
): Promise<void> {
  const calibrationSource = calibrationSourcePath();
  const referencePath = calibrationSource ?? owner.goldenPath;
  const referenceMetadata = await stat(referencePath).catch(() => undefined);
  if (!referenceMetadata?.isFile()) {
    throw new HarnessFailure(
      calibrationSource ? "CALIBRATION_SOURCE_MISSING" : "VISUAL_GOLDEN_MISSING",
      calibrationSource
        ? "visual calibration source is unavailable"
        : "accepted Zode visual golden is unavailable",
      { nonEvidence: true },
    );
  }
  const [referenceBytes, actualBytes] = await Promise.all([
    readFile(referencePath),
    page.screenshot({ animations: "disabled", caret: "hide", fullPage: false }),
  ]);
  const dpr = await page.evaluate(() => window.devicePixelRatio);
  if (dpr !== 1) throw new Error("visual comparison requires devicePixelRatio 1");
  const dynamicBoxes = await dynamicMaskBoxes(page, contract);
  if (dynamicBoxes.length === 0) {
    throw new Error("visual comparison did not find any explicitly marked dynamic content to mask");
  }
  const mismatch = await compareScreenshotsInBrowser(
    page,
    referenceBytes,
    actualBytes,
    dynamicBoxes,
    contract.visual_diff.mask_color,
  );
  const mismatchExceeded = visualMismatchExceeded(mismatch, contract);
  if (calibrationSource && mismatchExceeded) {
    await retainCalibrationMismatch(mismatch, actualBytes, referenceBytes, owner);
    if (process.env[ACCEPT_GOLDEN_ENV] !== "1") {
      throw new ProductBehaviorFailure(
        "VISUAL_CALIBRATION_MISMATCH",
        "Zode rendered pixels differ from the private reference; first mismatch is in ignored calibration quarantine",
        {
          changedPixelRatio: mismatch.changedPixelRatio,
          maximumChannelDeviation: mismatch.maximumChannelDeviation,
        },
      );
    }
  }
  if (calibrationSource && process.env[ACCEPT_GOLDEN_ENV] === "1") {
    await promoteAcceptedGolden(actualBytes, owner.goldenPath);
  }
  if (!calibrationSource && mismatchExceeded) {
    throw new Error(
      `${owner.e2eName} visual mismatch: changed_pixel_ratio=${mismatch.changedPixelRatio}, maximum_channel_deviation=${mismatch.maximumChannelDeviation}, first_changed_pixel=${JSON.stringify(mismatch.firstChangedPixel ?? null)}`,
    );
  }
}

async function assertUiAssetsDirectoryConfigured(
  harness: Awaited<ReturnType<typeof createWebE2EHarness>>,
  builtUi: BuiltUi,
): Promise<void> {
  const configPath = join(harness.runRoot, "server", "server-config.json");
  const config = JSON.parse(await readFile(configPath, "utf8")) as {
    ui_mode?: string;
    ui_assets_directory?: string;
  };
  const configuredDirectory = config.ui_assets_directory === undefined
    ? ""
    : isAbsolute(config.ui_assets_directory)
      ? resolve(config.ui_assets_directory)
      : resolve(dirname(configPath), config.ui_assets_directory);
  const serverRoot = resolve(dirname(configPath));
  const configuredRealDirectory = await realpath(configuredDirectory).catch(() => "");
  const relativeConfiguredDirectory = configuredRealDirectory
    ? relative(serverRoot, configuredRealDirectory)
    : "";
  const confined =
    configuredRealDirectory !== "" &&
    relativeConfiguredDirectory !== "" &&
    !relativeConfiguredDirectory.startsWith("..") &&
    !isAbsolute(relativeConfiguredDirectory) &&
    configuredRealDirectory !== resolve(builtUi.directory);
  const configuredIndex = confined
    ? await readFile(join(configuredRealDirectory, "index.html")).catch(() => undefined)
    : undefined;
  const builtIndex = await readFile(join(builtUi.directory, "index.html")).catch(() => undefined);
  const configuredAsset = confined
    ? await readFile(join(configuredRealDirectory, builtUi.assetHref.replace(/^\/+/, ""))).catch(() => undefined)
    : undefined;
  const builtAsset = await readFile(join(builtUi.directory, builtUi.assetHref.replace(/^\/+/, ""))).catch(() => undefined);
  const sameBuild =
    configuredIndex !== undefined &&
    builtIndex !== undefined &&
    configuredAsset !== undefined &&
    builtAsset !== undefined &&
    createHash("sha256").update(configuredIndex).digest("hex") === createHash("sha256").update(builtIndex).digest("hex") &&
    createHash("sha256").update(configuredAsset).digest("hex") === createHash("sha256").update(builtAsset).digest("hex");
  if (config.ui_mode !== "assets" || !confined || !sameBuild) {
    throw new HarnessFailure(
      "UI_ASSETS_DIRECTORY_UNWIRED",
      "installed/browser E2E requires ui_mode=assets and a confined copy of the test-owned vp build under the Server config root",
      { configuredDirectory, configuredRealDirectory, builtDirectory: builtUi.directory, nonEvidence: true },
    );
  }
}

async function gotoOrBlock(page: Page, url: string, path: string): Promise<Response | null> {
  const response = await page.goto(url, { waitUntil: "domcontentloaded" });
  const status = response?.status() ?? 0;
  if (status === 404) throw new BlockedShallow404(path, status);
  if (status < 200 || status >= 400) {
    throw new ProductBehaviorFailure(
      "MANAGEMENT_UI_BEHAVIOR_FAILURE",
      `management UI route returned unexpected status ${status}`,
      { path, status },
    );
  }
  return response;
}

async function assertSystemResponse(
  response: Response | null,
  label: string,
): Promise<void> {
  const status = response?.status() ?? 0;
  const body = response
    ? await response.json().catch(() => undefined)
    : undefined;
  const schema = body && typeof body === "object" && "schema" in body
    ? (body as { schema?: unknown }).schema
    : undefined;
  if (status !== 200 || schema !== "zode.system.v1") {
    throw new ProductBehaviorFailure(
      "SERVER_SYSTEM_BEHAVIOR_FAILURE",
      `${label} did not pass the public /v1/system readiness barrier`,
      { status, schema },
    );
  }
}

async function gotoRootWithSystemBarrier(
  page: Page,
  managementUrl: string,
): Promise<Response | null> {
  const managementOrigin = new URL(managementUrl).origin;
  const firstSystemResponse = page.waitForResponse((response) => {
    const responseUrl = new URL(response.url());
    return (
      response.request().method() === "GET" &&
      responseUrl.origin === managementOrigin &&
      responseUrl.pathname === "/v1/system"
    );
  });
  const rootResponse = await gotoOrBlock(page, `${managementUrl}/`, "/");
  await assertSystemResponse(
    await firstSystemResponse,
    "first root GET /v1/system",
  );
  return rootResponse;
}

async function assertManagementSystemBarrier(page: Page, managementUrl: string): Promise<void> {
  const response = await page.goto(
    new URL("/v1/system", managementUrl).toString(),
    { waitUntil: "domcontentloaded" },
  );
  await assertSystemResponse(response, "new management origin /v1/system");
}

async function createVisualSession(
  page: Page,
  harness: Awaited<ReturnType<typeof createWebE2EHarness>>,
): Promise<string> {
  const endpointLabel = "Visual Endpoint";
  const providerId = "visual-e2e-provider";
  const profileLabel = "Visual profile";

  await page.getByRole("link", { name: /^Endpoints$/i }).click();
  await page.getByRole("button", { name: /add remote endpoint/i }).click();
  const endpointDialog = page.getByRole("dialog", { name: /add remote endpoint/i });
  await endpointDialog.getByLabel("Endpoint label", { exact: true }).fill(endpointLabel);
  await endpointDialog.getByLabel("Endpoint URL", { exact: true }).fill(harness.endpoint.baseUrl);
  await endpointDialog.getByLabel("Controller credential", { exact: true }).fill(harness.controllerSecret);
  const endpointResponse = page.waitForResponse(
    (response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/endpoints",
  );
  await endpointDialog.getByRole("button", { name: /add endpoint/i }).click();
  const endpointResult = await endpointResponse;
  if (endpointResult.status() !== 201) {
    throw new ProductBehaviorFailure(
      "VISUAL_SESSION_FIXTURE_FAILURE",
      `visual endpoint admission returned HTTP ${endpointResult.status()}`,
      { status: endpointResult.status() },
    );
  }
  await expect(page.getByText(endpointLabel, { exact: true })).toBeVisible();

  await page.getByRole("link", { name: /^Providers$/i }).click();
  await page.getByRole("button", { name: /configure provider/i }).click();
  const providerForm = page.locator("form.editor-panel").filter({ hasText: "Configure provider" });
  await providerForm.getByLabel("Provider ID", { exact: true }).fill(providerId);
  await providerForm.getByLabel("Base URL", { exact: true }).fill(`${harness.providerProxy.baseUrl}/v1`);
  await providerForm.getByLabel("Models", { exact: true }).fill("visual-e2e-model");
  await providerForm.getByRole("button", { name: /save provider/i }).click();
  const providerCard = page.locator("article.resource-card").filter({ hasText: providerId }).first();
  await expect(providerCard).toBeVisible();
  await providerCard.getByRole("button", { name: /add api[- ]key profile/i }).click();
  const profileForm = providerCard.locator("form.nested-editor");
  await profileForm.getByLabel("Profile label", { exact: true }).fill(profileLabel);
  await profileForm.getByLabel("API key", { exact: true }).fill(harness.providerSecret);
  await profileForm.getByLabel(`Share with ${endpointLabel}`, { exact: true }).check();
  await profileForm.getByRole("button", { name: /create profile/i }).click();
  const profileRow = providerCard.locator(".profile-row").filter({ hasText: profileLabel });
  await expect(profileRow).toContainText(/ready/i, { timeout: 20_000 });

  await page.getByRole("link", { name: /^Sessions$/i }).click();
  await page.getByRole("button", { name: /new session|create session/i }).click();
  const sessionForm = page.locator("form.editor-panel").filter({ hasText: "New session" });
  await sessionForm.getByLabel("Endpoint", { exact: true }).selectOption({ label: endpointLabel });
  await sessionForm.getByLabel("Provider", { exact: true }).selectOption(providerId);
  await sessionForm.getByLabel("Model", { exact: true }).selectOption("visual-e2e-model");
  await expect(sessionForm.getByLabel("Auth profile", { exact: true })).toHaveValue(/.+/);
  await sessionForm.getByRole("button", { name: /start session/i }).click();
  await expect(page).toHaveURL(/\/endpoints\/[^/]+\/sessions\/[A-Z0-9]+$/);
  return new URL(page.url()).pathname;
}

test.describe("approved Codex Desktop v0 visual shell", () => {
  test(`${INDEXED_DB_GATE_E2E_NAME} @harness-gate`, async ({ page }, testInfo) => {
    test.setTimeout(90_000);
    let harness: VisualHarness | undefined;
    let browserSecretGuard: BrowserSecretGuard | undefined;
    let restoreServerEnvironment: RestoredServerEnvironment | undefined;
    let primaryError: unknown;
    let secretGuardFlushed = false;
    let firstFailureRetained = false;
    const retainFailureEvidence = async (error: unknown): Promise<void> => {
      if (firstFailureRetained) return;
      firstFailureRetained = true;
      primaryError = await retainFirstVisualFailure({
        error,
        e2eName: INDEXED_DB_GATE_E2E_NAME,
        harness,
        page,
        testInfo,
        browserSecretGuard,
      });
    };

    try {
      const builtUi = await buildTestOwnedUiDist();
      restoreServerEnvironment = await installUiAssetsServerWrapper(builtUi);
      harness = await createWebE2EHarness({ includeServerOrigins: true, authorityId: "web-e2e-server" });
      browserSecretGuard = attachVisualBrowserSecretGuard(harness, page);
      await harness.endpointIdentity();
      await assertUiAssetsDirectoryConfigured(harness, builtUi);
      await gotoRootWithSystemBarrier(page, harness.managementUrl);
      await waitForCurrentRunJwks(harness);
      await assertSyntheticIndexedDbGuardGate(page, browserSecretGuard);
      secretGuardFlushed = true;
    } catch (error) {
      primaryError = error;
      await retainFailureEvidence(error);
    } finally {
      if (browserSecretGuard && !secretGuardFlushed) {
        try {
          await flushVisualSecretGuard(page, browserSecretGuard);
          secretGuardFlushed = true;
        } catch (error) {
          const hadPrimaryError = Boolean(primaryError);
          primaryError = retainPrimaryFailure(primaryError, error);
          if (!hadPrimaryError) await retainFailureEvidence(primaryError);
        }
      }
      try {
        await harness?.close();
      } catch (error) {
        primaryError = retainPrimaryFailure(primaryError, error);
      }
      restoreServerEnvironment?.();
    }

    if (primaryError instanceof HarnessFailure) {
      testInfo.annotations.push({
        type: "failure-classification",
        description: (primaryError as HarnessFailure).classification,
      });
    }
    if (primaryError) throw primaryError;
  });

  test(E2E_NAME, async ({ page }, testInfo) => {
    test.setTimeout(90_000);
    const contract = await loadContract();
    expect(contract.viewport).toEqual({ ...VIEWPORT, device_scale_factor: 1 });
    await page.setViewportSize(VIEWPORT);

    let harness: Awaited<ReturnType<typeof createWebE2EHarness>> | undefined;
    let browserSecretGuard: BrowserSecretGuard | undefined;
    let restoreServerEnvironment: RestoredServerEnvironment | undefined;
    let primaryError: unknown;
    let secretGuardFlushed = false;
    let firstFailureRetained = false;
    const browserRequests: string[] = [];
    const responseBodies: Array<Promise<string>> = [];
    const downloadBodies: Array<Promise<Buffer>> = [];
    const retainFailureEvidence = async (error: unknown): Promise<void> => {
      if (firstFailureRetained) return;
      firstFailureRetained = true;
      primaryError = await retainFirstVisualFailure({
        error,
        e2eName: E2E_NAME,
        harness,
        page,
        testInfo,
        browserSecretGuard,
      });
    };
    page.on("request", (request) => browserRequests.push(request.url()));
    page.on("response", (response) => {
      if (!new URL(response.url()).pathname.startsWith("/v1")) return;
      responseBodies.push(response.text().catch(() => ""));
    });
    page.on("download", (download) => {
      downloadBodies.push((async () => {
        const stream = await download.createReadStream();
        if (!stream) return Buffer.alloc(0);
        const chunks: Buffer[] = [];
        for await (const chunk of stream) chunks.push(Buffer.from(chunk));
        return Buffer.concat(chunks);
      })());
    });

    try {
      const builtUi = await buildTestOwnedUiDist();
      restoreServerEnvironment = await installUiAssetsServerWrapper(builtUi);
      harness = await createWebE2EHarness({ includeServerOrigins: true, authorityId: "web-e2e-server" });
      // This is a real Endpoint process barrier. Browser traffic below still
      // enters only through the Access edge and never calls Endpoint directly.
      await harness.endpointIdentity();
      await assertUiAssetsDirectoryConfigured(harness, builtUi);
      const rootResponse = await gotoRootWithSystemBarrier(page, harness.managementUrl);
      await waitForCurrentRunJwks(harness);
      assertSafeHtmlCache(rootResponse, "management root");
      const rootAssetHref = await extractRenderedAssetHref(page, "management root");
      if (rootAssetHref !== builtUi.assetHref) {
        throw new ProductBehaviorFailure(
          "STATIC_ASSET_BEHAVIOR_FAILURE",
          "management root did not serve the hashed asset produced by the test-owned vp build",
          { expected: builtUi.assetHref, actual: rootAssetHref },
        );
      }
      await assertRenderedAsset(page, rootAssetHref, "management versioned asset");
      const visualSessionPath = await createVisualSession(page, harness);
      browserSecretGuard = attachVisualBrowserSecretGuard(harness, page);
      const historyResponse = await gotoOrBlock(
        page,
        `${harness.managementUrl}${visualSessionPath}`,
        visualSessionPath,
      );
      assertSafeHtmlCache(historyResponse, "management canonical history route");
      const historyAssetHref = await extractRenderedAssetHref(page, "management canonical history route");
      if (historyAssetHref !== rootAssetHref) {
        throw new ProductBehaviorFailure(
          "STATIC_ASSET_BEHAVIOR_FAILURE",
          "management root and canonical history route referenced different hashed assets",
          { rootAssetHref, historyAssetHref },
        );
      }

      if (!browserRequests.some((url) => url.startsWith(harness!.managementUrl))) {
        throw new Error("browser did not enter through the Access-protected management origin");
      }
      if (browserRequests.some((url) => url.startsWith(harness!.endpoint.baseUrl))) {
        throw new Error("browser bypassed Server and called the Endpoint directly");
      }
      await flushVisualSecretGuard(page, browserSecretGuard!);
      const shell = page.locator(contract.selectors.shell).first();
      await expect(shell).toBeVisible();
      const renderedText = await page.locator("body").innerText();
      if (/\b(?:log[ -]?in|sign[ -]?in|password)\b/i.test(renderedText)) {
        throw new Error("management UI exposed a local Zode login surface");
      }
      await expect(page.locator('input[type="password"], [data-zode-login]')).toHaveCount(0);

      let shellAssertionError: unknown;
      for (const assertion of [
        () => assertShellGeometry(page, contract),
        () => assertShellPalette(page, contract),
        () => assertShellStates(page, contract),
        () => assertKeyboardAndAccessibility(page, contract),
      ]) {
        try {
          await assertion();
        } catch (error) {
          shellAssertionError ??= error;
        }
      }
      let visualAssertionError: unknown;
      if (!shellAssertionError) {
        try {
          await assertMaskedReference(page, contract, SHELL_VISUAL_EVIDENCE_OWNER);
        } catch (error) {
          visualAssertionError = error;
        }
      }
      await assertNoSecretMarkers(
        page,
        harness,
        testInfo,
        responseBodies,
        downloadBodies,
        browserSecretGuard!,
      );
      secretGuardFlushed = true;
      primaryError = shellAssertionError ?? visualAssertionError;
      if (primaryError) await retainFailureEvidence(primaryError);
    } catch (error) {
      primaryError = error;
      await retainFailureEvidence(error);
    } finally {
      if (browserSecretGuard && !secretGuardFlushed) {
        try {
          await flushVisualSecretGuard(page, browserSecretGuard);
          secretGuardFlushed = true;
        } catch (error) {
          const hadPrimaryError = Boolean(primaryError);
          primaryError = retainPrimaryFailure(primaryError, error);
          if (!hadPrimaryError) await retainFailureEvidence(primaryError);
        }
      }
      try {
        await harness?.close();
      } catch (error) {
        primaryError = retainPrimaryFailure(primaryError, error);
      }
      restoreServerEnvironment?.();
    }

    if (primaryError instanceof HarnessFailure) {
      testInfo.annotations.push({
        type: "failure-classification",
        description: (primaryError as HarnessFailure).classification,
      });
    }
    if (primaryError) throw primaryError;
  });

  test(SESSION_STATES_E2E_NAME, async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const contract = await loadContract();
    expect(contract.viewport).toEqual({ ...VIEWPORT, device_scale_factor: 1 });
    await page.setViewportSize(VIEWPORT);

    let harness: Awaited<ReturnType<typeof createWebE2EHarness>> | undefined;
    let browserSecretGuard: BrowserSecretGuard | undefined;
    let restoreServerEnvironment: RestoredServerEnvironment | undefined;
    let primaryError: unknown;
    let secretGuardFlushed = false;
    let firstFailureRetained = false;
    const browserRequests: string[] = [];
    const responseBodies: Array<Promise<string>> = [];
    const downloadBodies: Array<Promise<Buffer>> = [];
    const retainFailureEvidence = async (error: unknown): Promise<void> => {
      if (firstFailureRetained) return;
      firstFailureRetained = true;
      primaryError = await retainFirstVisualFailure({
        error,
        e2eName: SESSION_STATES_E2E_NAME,
        harness,
        page,
        testInfo,
        browserSecretGuard,
      });
    };
    page.on("request", (request) => browserRequests.push(request.url()));
    page.on("response", (response) => {
      if (!new URL(response.url()).pathname.startsWith("/v1")) return;
      responseBodies.push(response.text().catch(() => ""));
    });
    page.on("download", (download) => {
      downloadBodies.push((async () => {
        const stream = await download.createReadStream();
        if (!stream) return Buffer.alloc(0);
        const chunks: Buffer[] = [];
        for await (const chunk of stream) chunks.push(Buffer.from(chunk));
        return Buffer.concat(chunks);
      })());
    });
    try {
      const builtUi = await buildTestOwnedUiDist();
      restoreServerEnvironment = await installUiAssetsServerWrapper(builtUi);
      harness = await createWebE2EHarness({ includeServerOrigins: true, authorityId: "web-e2e-server" });
      await harness.endpointIdentity();
      await assertUiAssetsDirectoryConfigured(harness, builtUi);
      await gotoRootWithSystemBarrier(page, harness.managementUrl);
      await waitForCurrentRunJwks(harness);
      const visualSessionPath = await createVisualSession(page, harness);
      browserSecretGuard = attachVisualBrowserSecretGuard(harness, page);
      await gotoOrBlock(page, `${harness.managementUrl}${visualSessionPath}`, visualSessionPath);
      if (!browserRequests.some((url) => url.startsWith(harness!.managementUrl))) {
        throw new Error("browser did not enter through the Access-protected management origin");
      }
      if (browserRequests.some((url) => url.startsWith(harness!.endpoint.baseUrl))) {
        throw new Error("browser bypassed Server and called the Endpoint directly");
      }
      await flushVisualSecretGuard(page, browserSecretGuard!);
      await assertShellGeometry(page, contract);
      await assertShellPalette(page, contract);
      const observedStates = await driveRealSessionStateFlow(page, harness, contract);
      await assertSessionStateContract(page, contract, observedStates);
      await assertKeyboardAndAccessibility(page, contract);
      await assertMaskedReference(page, contract, SESSION_VISUAL_EVIDENCE_OWNER);
      await assertNoSecretMarkers(
        page,
        harness,
        testInfo,
        responseBodies,
        downloadBodies,
        browserSecretGuard!,
      );
      secretGuardFlushed = true;
    } catch (error) {
      primaryError = error;
      await retainFailureEvidence(error);
    } finally {
      if (browserSecretGuard && !secretGuardFlushed) {
        try {
          await flushVisualSecretGuard(page, browserSecretGuard);
          secretGuardFlushed = true;
        } catch (error) {
          const hadPrimaryError = Boolean(primaryError);
          primaryError = retainPrimaryFailure(primaryError, error);
          if (!hadPrimaryError) await retainFailureEvidence(primaryError);
        }
      }
      try {
        await harness?.close();
      } catch (error) {
        primaryError = retainPrimaryFailure(primaryError, error);
      }
      restoreServerEnvironment?.();
    }

    if (primaryError instanceof HarnessFailure) {
      testInfo.annotations.push({
        type: "failure-classification",
        description: (primaryError as HarnessFailure).classification,
      });
    }
    if (primaryError) throw primaryError;
  });
});
