const { expect } = require("@playwright/test");

function escapeAttributeValue(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

async function selectRadixValue(page, trigger, value) {
  await trigger.click();
  const escaped = escapeAttributeValue(value);
  await page.locator(`[role="option"][data-value="${escaped}"]`).last().click();
}

async function openManagement(page, name) {
  const directLink = page.getByRole("link", { name, exact: true });
  if (await directLink.isVisible()) {
    await directLink.click();
    return;
  }
  const menu = page.getByRole("menu", { name: "Manage Zode", exact: true });
  if (!(await menu.isVisible())) {
    await page.getByRole("button", { name: "Manage Zode", exact: true }).click();
  }
  await menu.getByRole("menuitem", { name, exact: true }).click();
}

async function openExecutionChoices(page, trigger, model) {
  await closeExecutionChoices(page);
  await expect(trigger).toBeVisible();
  await expect(trigger).toBeEnabled({ timeout: 20_000 });
  await trigger.click();
  const advanced = page.getByRole("menuitem", { name: "Show advanced options", exact: true });
  const modelMenu = page.getByRole("menuitem", { name: /^Model\b/u });
  await expect.poll(async () =>
    (await advanced.isVisible()) || (await modelMenu.isVisible()),
  ).toBe(true);
  if (await advanced.isVisible()) await advanced.click();
  await modelMenu.waitFor({ state: "visible" });
  await modelMenu.click();
  const modelItem = page.locator(
    `[role="menuitem"][data-zode-model="${escapeAttributeValue(model)}"]`,
  );
  await modelItem.waitFor({ state: "visible" });
  return modelItem;
}

async function closeExecutionChoices(page) {
  for (let index = 0; index < 4; index += 1) {
    if ((await page.locator('[role="menu"]:visible').count()) === 0) return;
    await page.keyboard.press("Escape");
  }
}

async function selectExecutionProfile(page, trigger, model, profileLabel) {
  const modelItem = await openExecutionChoices(page, trigger, model);
  const hasProfileSubmenu = (await modelItem.getAttribute("aria-haspopup")) === "menu";
  const profileItem = page.getByRole("menuitem", { name: profileLabel, exact: true });
  if (hasProfileSubmenu) {
    await modelItem.click();
    await profileItem.waitFor({ state: "visible" });
    await profileItem.click();
  } else {
    await modelItem.click();
  }
}

async function expectSelectedExecutionProfile(page, trigger, model, profileLabel) {
  const modelItem = await openExecutionChoices(page, trigger, model);
  const hasProfileSubmenu = (await modelItem.getAttribute("aria-haspopup")) === "menu";
  const profileItem = page.getByRole("menuitem", { name: profileLabel, exact: true });
  if (hasProfileSubmenu) {
    await modelItem.click();
    await profileItem.waitFor({ state: "visible" });
    if ((await profileItem.getAttribute("data-zode-selected")) !== "true") {
      throw new Error(`execution profile ${profileLabel} was not selected`);
    }
  } else if ((await modelItem.getAttribute("data-zode-selected")) !== "true") {
    throw new Error(`execution model ${model} was not selected`);
  }
  await closeExecutionChoices(page);
}

module.exports = {
  closeExecutionChoices,
  expectSelectedExecutionProfile,
  openExecutionChoices,
  openManagement,
  selectExecutionProfile,
  selectRadixValue,
};
