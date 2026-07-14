// End-to-end probe: home view + login view + real submit.
import { chromium } from "playwright";
const BASE = "https://cpa.muxpay.xyz";
const KEY  = "BIlQWHncJYcHvGiSx9PvSi2jFy9toK70wJvhZWIh";

const browser = await chromium.launch({ headless: true });

// -------- 1. Home view (no state) --------
{
  const ctx = await browser.newContext({
    extraHTTPHeaders: { Authorization: "Bearer " + KEY },
  });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  await page.goto(`${BASE}/v0/resource/plugins/cpa-login-hub/panel?lang=zh-CN`, { waitUntil: "networkidle" });
  await page.evaluate((k) => sessionStorage.setItem("cpa-login-hub:mgmt-key", k), KEY);
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForTimeout(1500);

  const info = await page.evaluate(() => {
    const hero = document.querySelector(".home-hero");
    const providers = document.querySelectorAll("#home-providers li");
    const authFiles = document.getElementById("home-auth-files");
    const startBtn = document.getElementById("home-start");
    return {
      heroTitle: hero?.querySelector("h2")?.textContent,
      heroBlurb: hero?.querySelector("p")?.textContent,
      startBtnText: startBtn?.textContent,
      providersCount: providers.length,
      authFilesHTML: authFiles?.innerHTML?.slice(0, 400),
    };
  });
  console.log("HOME VIEW:", JSON.stringify(info, null, 2));
  await page.screenshot({ path: "/tmp/panel-home.png", fullPage: true });
  console.log("errors:", errors);
  await ctx.close();
}

// -------- 2. Login view (with state) + real submit --------
{
  const ctx = await browser.newContext({
    extraHTTPHeaders: { Authorization: "Bearer " + KEY },
  });
  const page = await ctx.newPage();
  const errors = [];
  const responses = [];
  page.on("pageerror", e => errors.push(e.message));
  page.on("response", async r => {
    if (r.url().includes("submit-login") || r.url().includes("auth-url")) {
      const buf = await r.body().catch(() => Buffer.from(""));
      responses.push({
        url: r.url(),
        status: r.status(),
        body: buf.toString("utf-8").slice(0, 500),
      });
    }
  });

  const startResp = await ctx.request.get(`${BASE}/v0/management/cpa-login-hub-auth-url`);
  const { state } = await startResp.json();
  console.log("\nstate:", state);

  await page.goto(`${BASE}/v0/resource/plugins/cpa-login-hub/panel?state=${state}&lang=zh-CN`, { waitUntil: "networkidle" });
  await page.evaluate((k) => sessionStorage.setItem("cpa-login-hub:mgmt-key", k), KEY);
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForTimeout(1000);

  // Fill and submit
  await page.locator("#mgmt-key").fill(KEY);
  await page.locator("#provider").selectOption("kiro");
  await page.locator('input[data-field-key="email"]').fill("smoke@example.com");
  await page.locator('input[data-field-key="password"]').fill("not-real");
  console.log("→ submitting kiro form");
  await page.locator("#submit").click();
  await page.waitForTimeout(3000);

  const statusText = await page.locator("#status-line").textContent();
  console.log("\nLOGIN VIEW status:", JSON.stringify(statusText));
  console.log("\nRESPONSES:");
  responses.forEach(r => console.log(`  ${r.status} ${r.url}\n    body=${r.body}`));
  console.log("\nerrors:", errors);
  await page.screenshot({ path: "/tmp/panel-login.png", fullPage: true });
  await ctx.close();
}

await browser.close();
