// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
const { chromium } = require('playwright-core');
const fs = require('fs');
const OUT = process.env.OUT || require('path').join(__dirname, '..', 'docs', 'screenshots') + '/';
const BASE = process.env.BASE || 'http://127.0.0.1:8765';
const FAILBASE = process.env.FAILBASE || 'http://127.0.0.1:8766';
const ADDR = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
function parseSample() {
  const rows = [];
  for (const l of fs.readFileSync(process.env.SAMPLE || __dirname + '/sample.txt', 'utf8').split('\n')) {
    const m = l.match(/^(\d+)\s+(.+?)\s+(0x[0-9a-f]{40})\s+(\S+(?: \S+)*?)\s{2,}\s*(WYSOKIE|SREDNIE|NISKIE)\s+(.*)$/);
    if (m) rows.push({ token: m[2].trim(), spender: m[3], amount: m[4].trim(), risk: m[5] });
  }
  return rows;
}
async function domRows(page) {
  return page.$$eval('#tbl tbody tr', trs => trs.map(tr => {
    const td = tr.querySelectorAll('td');
    if (td.length < 9) return null;
    return { token: td[1].querySelector('a').textContent, spender: td[2].querySelector('a').href.split('/address/')[1],
      amount: td[3].textContent.trim(), usd: td[4].textContent.trim(), risk: td[5].textContent.trim().replace('ŚREDNIE', 'SREDNIE'), age: td[6].textContent, set: td[7].textContent, note: td[8].textContent };
  }).filter(Boolean));
}
async function runScan(page, mode, from, to) {
  await page.fill('#addr', ADDR);
  await page.click(`label.chip:has(input[name=range][value=${mode}]) span`);
  if (mode === 'custom') { await page.fill('#fromB', String(from)); await page.fill('#toB', String(to)); }
  await page.click('#go');
  await page.waitForFunction(() => /Gotowe/.test(document.getElementById('status').textContent) || document.getElementById('err').classList.contains('on'), null, { timeout: 600000 });
  return { status: await page.textContent('#status'), err: await page.textContent('#err') };
}
const cmp = (a, b) => JSON.stringify(a.map(r => [r.token, r.spender, r.amount, r.risk])) === JSON.stringify(b.map(r => [r.token, r.spender, r.amount, r.risk]));
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  const res = {};
  const consoleErrs = [];
  // desktop
  let ctx = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  let page = await ctx.newPage();
  page.on('console', m => { if (m.type() === 'error') consoleErrs.push(m.text()); });
  await page.goto(BASE + '/');
  // bad address
  await page.fill('#addr', '0x123'); await page.click('#go');
  res.badAddr = await page.textContent('#err');
  await page.fill('#addr', 'vitalik.eth'); await page.click('#go');
  res.ens = await page.textContent('#err');
  // custom range
  res.custom = await runScan(page, 'custom', 15000000, 20000000);
  const sample = parseSample(), dom = await domRows(page);
  res.customRows = dom.length; res.sampleRows = sample.length; res.customMatch = cmp(sample, dom);
  if (!res.customMatch) res.diff = { sample, dom };
  res.summary = [await page.textContent('#cH'), await page.textContent('#cS'), await page.textContent('#cN')];
  res.money = await page.textContent('#money'); res.grade = await page.textContent('#grade');
  res.planItems = await page.$$eval('#plan li', l => l.map(x => x.textContent.slice(0, 140)));
  res.timelineDots = await page.$$eval('#timeline circle', c => c.length);
  res.url = page.url();
  // sort click test (amount) then filter risky
  await page.click('th[data-k=amount]'); res.sortedFirstAmount = (await domRows(page))[0].amount;
  await page.click('th[data-k=risk]');
  await page.click('label.chip:has(#fRisky) span'); res.riskyRows = (await domRows(page)).length; await page.click('label.chip:has(#fRisky) span');
  res.revoke = await page.getAttribute('#revokeLink', 'href');
  await page.screenshot({ path: OUT + 'screenshot.png', fullPage: true });
  // last year
  res.year = await runScan(page, 'year');
  res.yearDom = await domRows(page);
  res.yearSummary = [await page.textContent('#cH'), await page.textContent('#cS'), await page.textContent('#cN')];
  res.yearMeta = await page.textContent('#meta');
  await page.screenshot({ path: OUT + 'screenshot-year.png' });
  await ctx.close();
  // mobile
  ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true,
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1' });
  page = await ctx.newPage();
  await page.goto(BASE + '/');
  res.mobile = await runScan(page, 'custom', 15000000, 20000000);
  res.mobileRows = (await domRows(page)).length;
  res.mobileOverflow = await page.evaluate(() => document.documentElement.scrollWidth);
  await page.screenshot({ path: OUT + 'screenshot-mobile.png', fullPage: false });
  
  await ctx.close();
  // RPC failure server
  ctx = await browser.newContext({ viewport: { width: 1366, height: 700 } });
  page = await ctx.newPage();
  await page.goto(FAILBASE + '/');
  res.rpcFail = await runScan(page, 'custom', 15000000, 20000000);
  await page.screenshot({ path: OUT + 'screenshot-rpc-error.png' });
  await ctx.close();
  // share link
  ctx = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  page = await ctx.newPage();
  await page.goto(BASE + '/r/' + ADDR + '?range=15000000-20000000');
  await page.waitForFunction(() => /Gotowe/.test(document.getElementById('status').textContent), null, { timeout: 300000 });
  res.shareRows = (await domRows(page)).length; res.shareStatus = await page.textContent('#status');
  await ctx.close();
  res.consoleErrs = consoleErrs;
  await browser.close();
  fs.writeFileSync(process.env.E2E_JSON || '/tmp/e2e.json', JSON.stringify(res, null, 1));
  const { yearDom, diff, ...brief } = res; console.log(JSON.stringify(brief, null, 1)); console.log('yearRows', yearDom.length);
})().catch(e => { console.error(e); process.exit(1); });
