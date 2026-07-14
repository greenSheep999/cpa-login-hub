// Live-probe the deployed panel through a real browser.
// Node 20+ / npx playwright installed.
import { chromium } from "playwright";

const BASE = "https://cpa.muxpay.xyz";
const KEY  = "BIlQWHncJYcHvGiSx9PvSi2jFy9toK70wJvhZWIh";

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  extraHTTPHeaders: { Authorization: "Bearer " + KEY },
});
const page = await ctx.newPage();

const consoleMsgs = [];
page.on("console", m => consoleMsgs.push(`[${m.type()}] ${m.text()}`));
page.on("pageerror", e => consoleMsgs.push(`[pageerror] ${e.message}`));
const netFailures = [];
page.on("response", async r => {
  if (r.url().includes("cpa-login-hub") || r.url().includes("/v0/")) {
    console.log(`  ${r.status()} ${r.request().method()} ${r.url()}`);
    if (!r.ok() && r.status() !== 401) netFailures.push({ url: r.url(), status: r.status() });
  }
});

// 1. Grab a fresh state token via CPA-native StartLogin.
console.log("→ triggering StartLogin to obtain a state token");
const startResp = await ctx.request.get(`${BASE}/v0/management/cpa-login-hub-auth-url`);
const startJson = await startResp.json();
console.log("  startLogin →", JSON.stringify(startJson));
const state = startJson.state;
if (!state) { console.error("no state"); process.exit(1); }

// 2. Open the panel with that state.
console.log(`\n→ opening panel with state=${state.slice(0,16)}…`);
const panelURL = `${BASE}/v0/resource/plugins/cpa-login-hub/panel?state=${state}`;
await page.goto(panelURL, { waitUntil: "networkidle", timeout: 15000 });

// 3. Screenshot + inspect DOM.
await page.screenshot({ path: "/tmp/cpa-panel.png", fullPage: true });
console.log(`\n→ screenshot saved to /tmp/cpa-panel.png`);

// 4. Report DOM state.
const dump = await page.evaluate(() => {
  const doc = document.documentElement;
  const bodyStyle = getComputedStyle(document.body);
  const headerH1 = document.querySelector(".panel-header h1");
  const submitBtn = document.getElementById("submit");
  const providerSel = document.getElementById("provider");
  const logoImg = document.querySelector(".panel-header .logo");
  const themePicker = document.getElementById("theme-picker");
  const langPicker = document.getElementById("lang-picker");
  const cpaI18n = typeof window.cpaI18n;
  return {
    dataTheme: doc.getAttribute("data-theme"),
    htmlLang: doc.lang,
    bodyBg: bodyStyle.backgroundColor,
    bodyColor: bodyStyle.color,
    headerH1Text: headerH1?.textContent,
    submitText: submitBtn?.textContent,
    submitBg: submitBtn ? getComputedStyle(submitBtn).backgroundColor : null,
    submitVisible: !!submitBtn && submitBtn.offsetParent !== null,
    providerOptionsCount: providerSel?.options.length ?? 0,
    logoSrc: logoImg?.src,
    logoNaturalW: logoImg?.naturalWidth,
    themePickerVal: themePicker?.value,
    langPickerVal: langPicker?.value,
    langPickerOpts: langPicker ? Array.from(langPicker.options).map(o => o.value) : [],
    cpaI18nType: cpaI18n,
    // Grab a few actual i18n'd strings to see if they landed.
    subtitleText: document.querySelector(".subtitle")?.textContent,
    footerSuffixText: document.querySelector(".panel-footer span[data-i18n]")?.textContent,
    // Grab computed bg of the .panel-header (was black earlier)
    headerBg: document.querySelector(".panel-header") ? getComputedStyle(document.querySelector(".panel-header")).backgroundColor : null,
    // How many stylesheets loaded successfully?
    stylesheets: Array.from(document.styleSheets).map(s => {
      let rules = 0;
      try { rules = s.cssRules.length; } catch(e) {}
      return { href: s.href, rules };
    }),
    // Content of a raw CSS var
    cssVarBgSec: getComputedStyle(doc).getPropertyValue("--bg-secondary").trim(),
    cssVarTextPrimary: getComputedStyle(doc).getPropertyValue("--text-primary").trim(),
    cssVarPrimary: getComputedStyle(doc).getPropertyValue("--primary-color").trim(),
  };
});

console.log("\n=== DOM STATE ===");
console.log(JSON.stringify(dump, null, 2));

console.log("\n=== CONSOLE / PAGE ERRORS ===");
consoleMsgs.forEach(m => console.log("  " + m));

if (netFailures.length) {
  console.log("\n=== NETWORK FAILURES ===");
  netFailures.forEach(f => console.log(`  ${f.status} ${f.url}`));
}

await browser.close();
