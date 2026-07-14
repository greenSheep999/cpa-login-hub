// Probe all 4 themes end-to-end. Screenshots go under /tmp/panel-theme-*.png
// so the user can eyeball each. Uses Playwright's colorScheme emulation to
// exercise the "auto" branch too.
import { chromium } from "playwright";

const BASE = "https://cpa.muxpay.xyz";
const KEY  = "BIlQWHncJYcHvGiSx9PvSi2jFy9toK70wJvhZWIh";

const browser = await chromium.launch({ headless: true });

async function grab(theme, colorScheme) {
  const ctx = await browser.newContext({
    extraHTTPHeaders: { Authorization: "Bearer " + KEY },
    colorScheme, // "dark" | "light"
  });
  const page = await ctx.newPage();
  const startResp = await ctx.request.get(`${BASE}/v0/management/cpa-login-hub-auth-url`);
  const { state } = await startResp.json();
  await page.goto(
    `${BASE}/v0/resource/plugins/cpa-login-hub/panel?state=${state}&theme=${theme}&lang=zh-CN`,
    { waitUntil: "networkidle" }
  );
  const info = await page.evaluate(() => {
    const doc = document.documentElement;
    const body = getComputedStyle(document.body);
    const picker = document.getElementById("theme-picker");
    return {
      dataTheme: doc.getAttribute("data-theme"),
      bodyBg: body.backgroundColor,
      bodyColor: body.color,
      pickerValue: picker?.value,
      pickerOpts: Array.from(picker?.options || []).map(o => ({ v: o.value, t: o.textContent })),
    };
  });
  const filename = `/tmp/panel-theme-${theme}-${colorScheme}.png`;
  await page.screenshot({ path: filename, fullPage: true });
  await ctx.close();
  return { theme, colorScheme, filename, ...info };
}

const cases = [
  ["auto", "light"],
  ["auto", "dark"],
  ["white", "light"],
  ["wool", "light"],
  ["dark", "light"],
];

console.log("theme → picker order + resolved data-theme + body bg\n");
for (const [th, cs] of cases) {
  const r = await grab(th, cs);
  console.log(`  ?theme=${r.theme} colorScheme=${r.colorScheme}  →  data-theme=${r.dataTheme}  bg=${r.bodyBg}  file=${r.filename}`);
  if (th === "auto" && cs === "light") {
    console.log(`  picker options: ${r.pickerOpts.map(o => `${o.v}=${o.t}`).join(" | ")}`);
  }
}

await browser.close();
