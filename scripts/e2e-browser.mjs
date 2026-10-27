// e2e-browser.mjs - drives Chromium against a throwaway Peek server to check
// the viewer's trust boundary.
//
// Invoked by scripts/e2e-browser.sh. Env:
//   BASE   - Peek base URL
//   SLUG   - slug of the uploaded probe page (scripts/e2e-browser-page.html)
//   CHROME - Chrome / Chromium executable path
import { chromium } from "playwright-core";

const { BASE, SLUG, CHROME } = process.env;
for (const [key, value] of Object.entries({ BASE, SLUG, CHROME })) {
  if (!value) throw new Error(`missing required env var: ${key}`);
}

let checks = 0;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function fail(message) {
  console.error(`browser e2e: FAIL: ${message}`);
  process.exitCode = 1;
}

function check(ok, message) {
  if (!ok) throw new Error(message);
  checks++;
}

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${BASE}/p/${SLUG}`);
  await page.waitForSelector("#hn-frame");

  const findFrame = () => page.frames().find((f) => f.url().includes("/raw/"));
  const deadline = Date.now() + 15000;
  let frame;
  while (Date.now() < deadline) {
    frame = findFrame();
    if (frame) {
      const ready = await frame
        .evaluate(() => typeof window.peek?.fetch === "function")
        .catch(() => false);
      if (ready) break;
    }
    frame = undefined;
    await sleep(100);
  }
  check(frame, "page frame with peek.fetch did not load");

  // 1. Paths that leave the page's backend prefix are rejected.
  for (const p of [
    "/../../api/tokens",
    "/%2e%2e/%2e%2e/api/tokens",
    "/../../../other-k7m2xq/v/1/x",
  ]) {
    const got = await frame.evaluate((x) => window.probe(x), p);
    check(got === "err:invalid peek.fetch path", `peek.fetch(${p}) returned ${got}, want err:invalid peek.fetch path`);
  }

  // 2. Positive control: a path inside the prefix is relayed.
  const control = await frame.evaluate(() => window.probe("/ok"));
  check(typeof control === "string" && control.startsWith("ok:"), `positive control peek.fetch("/ok") returned ${control}, want ok:<status>`);

  // 3. Messages that do not come from the page frame are ignored.
  await page.evaluate(() => window.postMessage({ hn: "togglebar" }, "*"));
  await frame.evaluate(() => parent.postMessage({ hn: "togglebar" }, "*"));
  try {
    await page.waitForSelector("#hn-bar", { state: "hidden", timeout: 5000 });
  } catch {
    check(false, "frame togglebar message did not hide #hn-bar");
  }
  await sleep(500);
  check(await page.locator("#hn-bar").isHidden(), "#hn-bar became visible again: the page's own togglebar message was honoured");

  // 4. Comment round-trip.
  await frame.evaluate(() => parent.postMessage({ hn: "togglebar" }, "*"));
  await page.waitForSelector("#hn-bar", { state: "visible", timeout: 5000 });
  // First-time anonymous viewers are asked for a name on load; skip it.
  if (await page.locator("#hn-name-modal").isVisible()) {
    await page.click("#hn-name-skip");
    await page.waitForSelector("#hn-name-modal", { state: "hidden", timeout: 5000 });
  }
  await page.click("#hn-comment-btn");
  // The comment-mode hint overlays the top centre of the frame; click the left edge of the text.
  await frame.click("#t", { position: { x: 5, y: 5 } });
  await page.waitForSelector("#hn-body", { state: "visible", timeout: 5000 });
  await page.fill("#hn-body", "e2e comment");
  await page.click("#hn-comment-form [type=submit]");
  try {
    await page.waitForSelector("#hn-name-modal", { state: "visible", timeout: 2000 });
    await page.click("#hn-name-skip");
  } catch {
    // no name prompt
  }
  let posted = false;
  const until = Date.now() + 10000;
  while (Date.now() < until && !posted) {
    const res = await fetch(`${BASE}/api/uploads/${SLUG}/comments`);
    posted = (await res.text()).includes("e2e comment");
    if (!posted) await sleep(200);
  }
  check(posted, "posted comment did not appear in /api/uploads/<slug>/comments");

  console.log(`browser e2e: OK (${checks} checks)`);
} catch (err) {
  fail(err.message);
} finally {
  await browser.close();
}
