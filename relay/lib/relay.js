// Phaethon Cloudflare relay.
//
// Job: let a Phaethon daemon on a filtered network reach origins that the
// network breaks (notably a host whose TLS is intercepted), by
// having the Cloudflare edge perform the fetch.
//
// Safety properties, deliberately narrow:
//   1. A shared secret (PHAETHON_TOKEN) is required on every request.
//   2. The relay carries HTTP requests for an explicit host allowlist; it
//      is not a TCP tunnel and not an open proxy.
//   3. The allowlist is enforced HERE, server-side, so a leaked URL is
//      still useless for anything outside the list.

// Empty by default: the relay carries nothing until an operator sets
// RELAY_ALLOWLIST. Failing closed matters more than being convenient, because a
// relay deployed without configuration must not be able to fetch anything.
export const DEFAULT_ALLOWLIST = [];

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "x-phaethon-token",
  "x-phaethon-host",
  "x-forwarded-proto",
  "x-real-ip",
]);

const MAX_BODY_BYTES = 16 * 1024 * 1024;

export function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body, null, 2) + "\n", {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-phaethon-relay": "1",
      ...extraHeaders,
    },
  });
}

// allowlist from env (comma separated) or the built-in default.
export function allowlist(env) {
  const raw = env?.RELAY_ALLOWLIST;
  if (typeof raw === "string" && raw.trim() !== "") {
    return raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
  }
  return DEFAULT_ALLOWLIST;
}

// hostAllowed applies the same wildcard rule Phaethon uses locally:
// "*.suffix" matches the bare domain and any subdomain.
export function hostAllowed(host, patterns) {
  const h = String(host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h) return false;
  for (const pattern of patterns) {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(2);
      if (h === suffix || h.endsWith("." + suffix)) return true;
      continue;
    }
    if (h === pattern) return true;
  }
  return false;
}

// tokensMatch compares secrets without an early exit on mismatch.
export function tokensMatch(provided, expected) {
  if (typeof expected !== "string" || expected.length === 0) return false;
  const a = String(provided || "");
  if (a.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

// forward performs the relayed request and returns the origin's response.
export async function forward(request, env, host, restPath) {
  const patterns = allowlist(env);
  if (!hostAllowed(host, patterns)) {
    return json(
      {
        error: "host_not_allowlisted",
        host,
        allowlist: patterns,
        hint: "the relay only carries hosts in its own allowlist",
      },
      403,
    );
  }

  const url = new URL(request.url);
  const target = `https://${host}/${restPath}${url.search}`;

  const headers = new Headers();
  for (const [k, v] of request.headers) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    headers.set(k, v);
  }
  // Ask for an unencoded body so content-length stays meaningful.
  headers.set("accept-encoding", "identity");

  let body;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const buf = await request.arrayBuffer();
    if (buf.byteLength > MAX_BODY_BYTES) {
      return json({ error: "request_body_too_large", bytes: buf.byteLength }, 413);
    }
    body = buf;
  }

  const started = Date.now();
  try {
    const resp = await fetch(target, {
      method: request.method,
      headers,
      body,
      redirect: "manual",
    });
    const ttfbMs = Date.now() - started;

    const outHeaders = new Headers();
    for (const [k, v] of resp.headers) {
      if (HOP_BY_HOP.has(k.toLowerCase())) continue;
      outHeaders.set(k, v);
    }
    outHeaders.set("x-phaethon-relay", "1");
    outHeaders.set("x-phaethon-route", "relay");
    outHeaders.set("x-phaethon-colo", request.cf?.colo ?? "unknown");
    outHeaders.set("x-phaethon-ttfb-ms", String(ttfbMs));

    return new Response(resp.body, {
      status: resp.status,
      statusText: resp.statusText,
      headers: outHeaders,
    });
  } catch (err) {
    return json(
      {
        error: "relay_fetch_failed",
        host,
        target,
        error_name: err?.name ?? "Error",
        error: String(err?.message ?? err),
        elapsed_ms: Date.now() - started,
        colo: request.cf?.colo ?? null,
      },
      502,
    );
  }
}
