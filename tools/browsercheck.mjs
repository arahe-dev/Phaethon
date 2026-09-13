// tools/browsercheck.mjs
//
// Loads a URL in headless Chrome over the DevTools Protocol and reports, as
// JSON, whether the page actually renders: console errors, failed requests,
// non-OK responses, stylesheet application, script execution markers and
// broken images.
//
//   node tools/browsercheck.mjs <url> [wait-seconds]
//
// A temp browser profile is used so the user's own Chrome session is never
// touched. Exit code is 0 when the report was produced (render health is in
// the JSON, not the exit code).
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const target = process.argv[2];
if (!target) {
  console.error('usage: node tools/browsercheck.mjs <url> [wait-seconds]');
  process.exit(2);
}
const settleMs = Math.max(1, Number(process.argv[3] || 8)) * 1000;

function findChrome() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
  ];
  for (const c of candidates) if (existsSync(c)) return c;
  throw new Error('no chrome/edge binary found; set CHROME_PATH');
}

const profile = mkdtempSync(join(tmpdir(), 'phaethon-browsercheck-'));
// Extra flags let a caller route the browser through Phaethon
// (CHROME_FLAGS="--proxy-server=http://127.0.0.1:8377") or isolate browser
// policy from the daemon's behaviour.
const extraFlags = (process.env.CHROME_FLAGS || '').split(/\s+/).filter(Boolean);
if (extraFlags.length) console.error('extra chrome flags:', extraFlags.join(' '));
const chrome = spawn(findChrome(), [
  '--headless=new',
  '--remote-debugging-port=0',
  `--user-data-dir=${profile}`,
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-gpu',
  '--disable-background-networking',
  '--disable-component-update',
  '--disable-sync',
  '--metrics-recording-only',
  '--mute-audio',
  '--window-size=1280,900',
  ...extraFlags,
  'about:blank',
], { stdio: ['ignore', 'pipe', 'pipe'] });

let mainFrameId = null;
let stderr = '';
chrome.stderr.on('data', (d) => { stderr += d.toString(); });

/** Wait for Chrome to print its DevTools endpoint. */
function devtoolsEndpoint(timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const timer = setInterval(() => {
      const m = stderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) { clearInterval(timer); resolve(m[1]); return; }
      if (Date.now() - started > timeoutMs) {
        clearInterval(timer);
        reject(new Error('chrome did not report a DevTools endpoint:\n' + stderr.slice(-2000)));
      }
    }, 100);
  });
}

/** Minimal CDP client: send commands, dispatch session-scoped events. */
class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
        return;
      }
      if (msg.method) for (const fn of this.listeners) fn(msg);
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    this.ws.send(JSON.stringify(payload));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`timeout: ${method}`));
        }
      }, 30000);
    });
  }
  on(fn) { this.listeners.push(fn); }
}

const report = {
  url: target,
  chrome: findChrome(),
  origin: null,
  document: {},
  counts: { requests: 0, failed: 0, nonOK: 0, consoleErrors: 0, exceptions: 0 },
  failedRequests: [],
  nonOKResponses: [],
  consoleErrors: [],
  exceptions: [],
  requestsByHost: {},
  resourceErrors: [],
  navigations: [],
  requestedNavigations: [],
  documentRequests: [],
};

(async () => {
  const wsUrl = await devtoolsEndpoint();
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => {
    ws.addEventListener('open', res, { once: true });
    ws.addEventListener('error', rej, { once: true });
  });
  const cdp = new CDP(ws);

  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const S = sessionId;

  const pending = new Map();
  cdp.on((msg) => {
    if (msg.sessionId !== S) return;
    const { method, params } = msg;
    if (method === 'Page.frameNavigated' && params.frame && !params.frame.parentId) {
      mainFrameId = params.frame.id;
      report.navigations.push({
        url: params.frame.url,
        at: Date.now(),
      });
      return;
    }
    if (method === 'Page.frameRequestedNavigation') {
      report.requestedNavigations.push({
        url: params.url,
        reason: params.reason,
        frameId: params.frameId,
      });
      return;
    }
    if (method === 'Network.requestWillBeSent') {
      pending.set(params.requestId, { url: params.request.url, type: params.type });
      report.counts.requests++;
      try {
        const h = new URL(params.request.url).host;
        report.requestsByHost[h] = (report.requestsByHost[h] || 0) + 1;
      } catch { /* about:blank */ }
      if (params.type === 'Document' && params.frameId === mainFrameId) {
        report.documentRequests.push(params.request.url);
      }
      return;
    }
    if (method === 'Network.responseReceived') {
      const { response } = params;
      if (response.status >= 400 || response.status === 0) {
        report.counts.nonOK++;
        report.nonOKResponses.push({ url: response.url, status: response.status, mime: response.mimeType });
      }
      return;
    }
    if (method === 'Network.loadingFailed') {
      const req = pending.get(params.requestId) || { url: '?', type: '?' };
      report.counts.failed++;
      report.failedRequests.push({
        url: req.url, type: req.type, error: params.errorText,
        blockedReason: params.blockedReason || null,
      });
      return;
    }
    if (method === 'Runtime.consoleAPICalled' && (params.type === 'error' || params.type === 'warning')) {
      report.counts.consoleErrors++;
      report.consoleErrors.push({
        level: params.type,
        text: (params.args || []).map((a) => a.value ?? a.description ?? a.type).join(' ').slice(0, 300),
      });
      return;
    }
    if (method === 'Runtime.exceptionThrown') {
      report.counts.exceptions++;
      const d = params.exceptionDetails || {};
      report.exceptions.push({
        text: (d.exception?.description || d.text || '').slice(0, 300),
        url: d.url || null,
      });
      return;
    }
    if (method === 'Log.entryAdded') {
      const e = params.entry || {};
      if (e.level === 'error') {
        report.counts.consoleErrors++;
        report.consoleErrors.push({ level: 'log', text: `${e.text} ${e.url || ''}`.slice(0, 300) });
      }
    }
  });

  await cdp.send('Network.enable', {}, S);
  await cdp.send('Page.enable', {}, S);
  await cdp.send('Runtime.enable', {}, S);
  await cdp.send('Log.enable', {}, S);

  await cdp.send('Page.navigate', { url: target }, S);
  await new Promise((r) => setTimeout(r, settleMs));

  // Ask the page itself how it turned out.
  const probe = `(() => {
    const css = [...document.styleSheets];
    const imgs = [...document.images];
    const linkHref = css.map(s => s.href).filter(Boolean);
    let cssRules = 0;
    for (const s of css) { try { cssRules += s.cssRules.length; } catch (e) { cssRules = -1; break; } }
    const bg = getComputedStyle(document.body).backgroundColor;
    const font = getComputedStyle(document.body).fontFamily;
    return {
      title: document.title,
      origin: location.origin,
      href: location.href,
      readyState: document.readyState,
      styleSheets: css.length,
      styleSheetHrefs: linkHref.slice(0, 12),
      cssRulesAccessible: cssRules,
      bodyBackground: bg,
      bodyFontFamily: font,
      scripts: document.scripts.length,
      scriptsWithSrc: [...document.scripts].filter(s => s.src).length,
      images: imgs.length,
      imagesBroken: imgs.filter(i => i.complete && i.naturalWidth === 0).length,
      imagesPending: imgs.filter(i => !i.complete).length,
      h1: (document.querySelector('h1')?.textContent || '').trim().slice(0, 80) || null,
      anchors: document.anchors.length + document.querySelectorAll('a[href]').length,
      textLength: (document.body?.innerText || '').length,
      nextData: typeof window.__NEXT_DATA__ !== 'undefined',
      reactRoot: !!document.querySelector('#__next, #root, [data-reactroot]'),
      inlineStyleTags: document.querySelectorAll('style').length,
    };
  })()`;

  try {
    const res = await cdp.send('Runtime.evaluate', {
      expression: probe, returnByValue: true, awaitPromise: false,
    }, S);
    report.document = res.result?.value ?? {};
  } catch (err) {
    report.document = { error: String(err) };
  }
  report.origin = report.document.origin ?? null;

  // Summarize failures into classes so the noise does not hide the cause.
  const classes = {};
  for (const f of report.failedRequests) {
    let key = f.error || 'unknown';
    report.resourceErrors.push({ url: f.url, type: f.type, error: key });
    const m = f.url.match(/^https?:\/\/([^/]+)(\/[^?]*)?/);
    key = `${key} :: ${m ? m[1] : '?'}${m && m[2] ? m[2].replace(/[0-9a-f]{8,}/g, '<hash>').slice(0, 60) : ''}`;
    classes[key] = (classes[key] || 0) + 1;
  }
  report.failureClasses = Object.entries(classes)
    .sort((a, b) => b[1] - a[1]).slice(0, 20)
    .map(([k, v]) => ({ pattern: k, count: v }));

  console.log(JSON.stringify(report, null, 2));
  ws.close();
})().catch((err) => {
  console.error('browsercheck failed:', err.message);
  console.log(JSON.stringify({ url: target, error: err.message, ...report }, null, 2));
  process.exitCode = 1;
}).finally(() => {
  try { chrome.kill(); } catch { /* already gone */ }
  setTimeout(() => { try { rmSync(profile, { recursive: true, force: true }); } catch { /* locked */ } }, 500);
});
