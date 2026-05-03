import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("C:/Users/stejo/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const screenshotDir = path.join(__dirname, "screenshots");
const baseUrl = process.env.CLOUDGUARD_FRONTEND_URL || "http://127.0.0.1:5500/";

async function waitForSettledUi(page) {
  await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
  await page.waitForTimeout(800);
}

async function capture(page, filename) {
  await page.screenshot({
    path: path.join(screenshotDir, filename),
    fullPage: true,
  });
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });

await page.goto(baseUrl, { waitUntil: "networkidle" });
await waitForSettledUi(page);
await capture(page, "dashboard-initial.png");

await page.click("#btnAttackPath");
await waitForSettledUi(page);
await capture(page, "attack-path.png");

await page.click("#btnRiskScore");
await waitForSettledUi(page);
await capture(page, "risk-score.png");

await page.click("#btnAssetAnalysis");
await waitForSettledUi(page);
await capture(page, "asset-analysis.png");

await browser.close();
