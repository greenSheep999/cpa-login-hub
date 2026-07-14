// Reproduce the submit-login JSON error the user hit.
import { chromium } from "playwright";
const BASE = "https://cpa.muxpay.xyz";
const KEY  = "BIlQWHncJYcHvGiSx9PvSi2jFy9toK70wJvhZWIh";

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  extraHTTPHeaders: { Authorization: "Bearer " + KEY },
});
const page = await ctx.newPage();

// Capture every network response's body verbatim.
page.on("response", async (r) => {
  if (!r.url().includes("cpa-login-hub") && !r.url().includes("/v0/")) return;
  const status = r.status();
  const ct = r.headers()["content-type"] || "";
  let bodyPreview = "";
  try {
    const buf = await r.body();
    bodyPreview = buf.toString("utf-8").slice(0, 400);
  } catch (e) {
    bodyPreview = `<body unavailable: ${e.message}>`;
  }
  console.log(`  ${status} ${r.request().method()} ${r.url()}`);
  console.log(`    ct=${ct}`);
  console.log(`    body=${JSON.stringify(bodyPreview)}`);
});
page.on("console", (m) => console.log(`  [console.${m.type()}] ${m.text()}`));
page.on("pageerror", (e) => console.log(`  [pageerror] ${e.message}`));

// 1. StartLogin to get a state
const startResp = await ctx.request.get(`${BASE}/v0/management/cpa-login-hub-auth-url`);
const { state } = await startResp.json();
console.log(`state=${state}\n`);

// 2. Open panel with state, wait for schema, then simulate submit
await page.goto(
  `${BASE}/v0/resource/plugins/cpa-login-hub/panel?state=${state}&lang=zh-CN`,
  { waitUntil: "networkidle" }
);

// 3. Fill mgmt key, kiro form, click submit
await page.evaluate((k) => sessionStorage.setItem("cpa-login-hub:mgmt-key", k), KEY);
await page.locator("#mgmt-key").fill(KEY);
await page.locator("#provider").selectOption("kiro");
await page.locator('input[data-field-key="email"]').fill("smoke@example.com");
await page.locator('input[data-field-key="password"]').fill("not-real");
console.log("\n→ clicking submit\n");
await page.locator("#submit").click();
await page.waitForTimeout(3500);

const status = await page.locator("#status-line").textContent();
console.log(`\nstatus line after submit: ${JSON.stringify(status)}`);
await browser.close();
