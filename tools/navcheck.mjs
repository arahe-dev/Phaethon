// tools/navcheck.mjs
//
// Loads a page, then follows same-site links within it, reporting for each
// navigation whether the response stayed on the facade, how much content
// rendered, and whether anything failed. This answers "can I actually browse
// the site" rather than "did the first document load".
//
//   node tools/navcheck.mjs <facade-url> [link-count] [wait-seconds]
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const base = process.argv[2];
if (!base) {
  console.error('usage: node tools/navcheck.mjs <facade-url> [links] [wait]');
  process.exit(2);
}
const wantLinks = Number(process.argv[3] || 5);
const settleMs = Number(process.argv[4] || 7) * 1000;

function findChrome() {
  const c = [
    process.env.CHROME_PATH,
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  ].filter(Boolean);
  for (const p of c) if (existsSync(p)) return p;
  throw new Error('no chrome found');
}

const profile = mkdtempSync(join(tmpdir(), 'phaethon-navcheck-'));
const chrome = spawn(findChrome(), [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--disable-gpu',
  '--disable-background-networking', '--disable-component-update', '--disable-sync',
  '--window-size=1280,900', 'about:blank',
], { stdio: ['ignore', 'pipe', 'pipe'] });

let stderr = '';
chrome.stderr.on('data', (d) => { stderr += d.toString(); });

class CDP {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.listeners = [];
    ws.addEventListener('message', (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id !== undefined && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id);
        this.pending.delete(m.id);
        m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result);
        return;
      }
      if (m.method) for (const f of this.listeners) f(m);
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    this.ws.send(JSON.stringify(payload));
    return new Promise((res, rej) => {
      this.pending.set(id, { resolve: res, reject: rej });
      setTimeout(() => { if (this.pending.delete(id)) rej(new Error('timeout ' + method)); }, 30000);
    });
  }
  on(f) { this.listeners.push(f); }
}

function endpoint(timeoutMs = 20000) {
  return new Promise((res, rej) => {
    const t0 = Date.now();
    const t = setInterval(() => {
      const m = stderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) { clearInterval(t); res(m[1]); }
      else if (Date.now() - t0 > timeoutMs) { clearInterval(t); rej(new Error(stderr.slice(-800))); }
    }, 100);
  });
}

const results = [];

(async () => {
  const ws = new WebSocket(await endpoint());
  await new Promise((r, j) => { ws.addEventListener('open', r, { once: true }); ws.addEventListener('error', j, { once: true }); });
  const cdp = new CDP(ws);

  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId: S } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });

  // Per-navigation counters.
  let nav = { host: '', path: '', failed: 0, nonOK: 0, exceptions: 0 };
  const urlOf = new Map();
  cdp.on((m) => {
    if (m.sessionId !== S) return;
    const { method, params } = m;
    if (method === 'Network.requestWillBeSent') {
      urlOf.set(params.requestId, params.request.url);
    } else if (method === 'Network.loadingFailed') {
      const u = urlOf.get(params.requestId) || '';
      // Ignore aborted requests: navigation cancels in-flight subresources.
      if (params.errorText === 'net::ERR_ABORTED') return;
      nav.failed++;
      nav.lastError = `${params.errorText} ${u.slice(0, 90)}`;
    } else if (method === 'Network.responseReceived') {
      if (params.response.status >= 400) { nav.nonOK++; nav.lastNonOK = `${params.response.status} ${params.response.url.slice(0, 90)}`; }
    } else if (method === 'Runtime.exceptionThrown') {
      nav.exceptions++;
    }
  });

  await cdp.send('Network.enable', {}, S);
  await cdp.send('Page.enable', {}, S);
  await cdp.send('Runtime.enable', {}, S);

  const evaluate = async (expression) => {
    const r = await cdp.send('Runtime.evaluate', { expression, returnByValue: true }, S);
    return r.result?.value;
  };

  const snapshot = () => evaluate(`(() => {
    let rules = 0; for (const s of document.styleSheets) { try { rules += s.cssRules.length; } catch(e) { rules = -1; break; } }
    return {
      title: document.title, href: location.href,
      h1: (document.querySelector('h1')?.textContent || '').trim().slice(0, 60),
      textLength: (document.body?.innerText || '').length,
      cssRules: rules, font: getComputedStyle(document.body).fontFamily,
      images: document.images.length,
      imagesBroken: [...document.images].filter(i => i.complete && i.naturalWidth === 0).length,
    };
  })()`);

  // First load.
  nav = { host: new URL(base).host, path: new URL(base).pathname, failed: 0, nonOK: 0, exceptions: 0 };
  await cdp.send('Page.navigate', { url: base }, S);
  await new Promise((r) => setTimeout(r, settleMs));
  let snap = await snapshot();
  results.push({ step: 'initial', ...snap, ...nav });

  // Collect same-facade links and follow each in the same tab.
  const links = await evaluate(`(() => {
    const out = [];
    for (const a of document.querySelectorAll('a[href]')) {
      const u = new URL(a.href, location.href);
      if (u.origin !== location.origin) continue;
      if (!u.pathname.startsWith(location.pathname.split('/').slice(0, 2).join('/'))) continue;
      if (out.includes(u.href) || u.href === location.href) continue;
      out.push(u.href);
      if (out.length >= ${wantLinks}) break;
    }
    return out;
  })()`);

  for (const link of links || []) {
    nav = { host: new URL(link).host, path: new URL(link).pathname, failed: 0, nonOK: 0, exceptions: 0 };
    await cdp.send('Page.navigate', { url: link }, S);
    await new Promise((r) => setTimeout(r, settleMs));
    snap = await snapshot();
    results.push({ step: 'link', ...snap, ...nav });
  }

  console.log(JSON.stringify({ base, results }, null, 2));
  ws.close();
})().catch((err) => {
  console.log(JSON.stringify({ base, error: err.message, results }, null, 2));
  process.exitCode = 1;
}).finally(() => {
  try { chrome.kill(); } catch {}
  setTimeout(() => { try { rmSync(profile, { recursive: true, force: true }); } catch {} }, 500);
});
