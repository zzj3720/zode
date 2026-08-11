import type { Locator, Page } from "@playwright/test";

function escapeAttributeValue(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

export async function selectRadixValue(page: Page, trigger: Locator, value: string): Promise<void> {
  await trigger.click();
  const escaped = escapeAttributeValue(value);
  await page.locator(`[role="option"][data-value="${escaped}"]`).last().click();
}

export async function openExecutionChoices(
  page: Page,
  trigger: Locator,
  model: string,
): Promise<Locator> {
  await closeExecutionChoices(page);
  await trigger.click();
  const advanced = page.getByRole("menuitem", { name: "Show advanced options", exact: true });
  if (await advanced.isVisible()) await advanced.click();
  await page.getByRole("menuitem", { name: /^Model\b/u }).hover();
  const escaped = escapeAttributeValue(model);
  const modelItem = page.locator(`[role="menuitem"][data-zode-model="${escaped}"]`);
  await modelItem.hover();
  return modelItem;
}

export async function closeExecutionChoices(page: Page): Promise<void> {
  for (let index = 0; index < 4; index += 1) {
    if ((await page.locator('[role="menu"]:visible').count()) === 0) return;
    await page.keyboard.press("Escape");
  }
}

export async function selectExecutionProfile(
  page: Page,
  trigger: Locator,
  model: string,
  profileLabel: string,
): Promise<void> {
  const modelItem = await openExecutionChoices(page, trigger, model);
  const profileItem = page.getByRole("menuitem", { name: profileLabel, exact: true });
  const profileVisible = await profileItem
    .waitFor({ state: "visible", timeout: 3_000 })
    .then(() => true, () => false);
  if (profileVisible) await profileItem.click();
  else await modelItem.click();
}

export async function expectSelectedExecutionProfile(
  page: Page,
  trigger: Locator,
  model: string,
  profileLabel: string,
): Promise<void> {
  const modelItem = await openExecutionChoices(page, trigger, model);
  const profileItem = page.getByRole("menuitem", { name: profileLabel, exact: true });
  const profileVisible = await profileItem
    .waitFor({ state: "visible", timeout: 3_000 })
    .then(() => true, () => false);
  if (profileVisible) {
    if ((await profileItem.getAttribute("data-zode-selected")) !== "true") {
      throw new Error(`execution profile ${profileLabel} was not selected`);
    }
  } else if ((await modelItem.getAttribute("data-zode-selected")) !== "true") {
    throw new Error(`execution model ${model} was not selected`);
  }
  await closeExecutionChoices(page);
}
