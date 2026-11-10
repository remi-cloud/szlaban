// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
const { chromium } = require('playwright-core');
const BASE = process.env.BASE || 'http://127.0.0.1:8765';
const OUT = process.env.OUT || require('path').join(__dirname, '..', 'docs', 'screenshots') + '/';
const U = BASE + '/r/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045?range=15000000-20000000';
(async () => {
  const b = await chromium.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  let p = await (await b.newContext({ viewport: { width: 1366, height: 900 } })).newPage();
  await p.goto(U); await p.waitForFunction(() => /Gotowe/.test(document.getElementById('status').textContent), null, { timeout: 300000 });
  await p.waitForTimeout(800);
  await p.screenshot({ path: OUT + 'screenshot.png', fullPage: true });
  await p.locator('.hero').screenshot({ path: OUT + 'hero.png' });
  await p.locator('#timeline').screenshot({ path: OUT + 'timeline.png' });
  await p.locator('#wzor').screenshot({ path: OUT + 'formula.png' });
  p = await (await b.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true })).newPage();
  await p.goto(U); await p.waitForFunction(() => /Gotowe/.test(document.getElementById('status').textContent), null, { timeout: 300000 });
  await p.waitForTimeout(800);
  await p.evaluate(() => document.querySelector('.hero').scrollIntoView());
  await p.screenshot({ path: OUT + 'screenshot-mobile.png' });
  await p.screenshot({ path: OUT + 'screenshot-mobile-full.png', fullPage: true });
  console.log('scrollWidth', await p.evaluate(() => document.documentElement.scrollWidth));
  await b.close();
})();
