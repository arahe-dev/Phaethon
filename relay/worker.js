// Phaethon Cloudflare relay — single-module Worker.
//
// This is the same relay as relay/lib/relay.js, expressed as one ES module so
// it can be uploaded with a single Cloudflare API call. The Pages version
// remains for anyone deploying with Wrangler; this one exists so a downloaded
// Phaethon binary can provision a relay with no Node, no Wrangler, and no
// build step.
//
// Both versions enforce the same three safety properties, and they are the
// reason a relay is not an open proxy:
//   1. a shared secret is required on every relayed request;
//   2. only an explicit host allowlist is carried;
//   3. the allowlist is enforced HERE, server-side, so knowing the URL is not
//      enough to use the relay for anything outside the list.
//
// Configuration comes from the environment at deploy time:
//   RELAY_ALLOWLIST  plain text variable, comma separated
//   PHAETHON_TOKEN   secret, set through the secrets API, never in metadata

import { connect } from "cloudflare:sockets";

// Empty by default. The relay carries nothing until an operator sets
// RELAY_ALLOWLIST, which is the fail-closed behaviour: a relay deployed without
// configuration must not be able to fetch anything.
const DEFAULT_ALLOWLIST = [];

// The TCP allowlist is separate from the HTTP one on purpose. An HTTP entry
// names a host and implies one protocol on one port; a TCP entry has to name
// the port too, because "example.com" under TCP would mean :22, :3306 and
// everything else. Keeping them separate means turning on TCP egress cannot
// silently widen what the HTTP relay already carries, and vice versa.
//
// Entries are "host:port" or "*.suffix:port". Nothing is allowed by default.
const DEFAULT_TCP_ALLOWLIST = [];

// Names that must never be reached even if an operator lists them, because
// they resolve to the Worker's own neighbourhood, to a cloud metadata service,
// or to something on the far side of a split-horizon resolver. Cloudflare also
// refuses private addresses, but that is platform hygiene rather than policy:
// it can change, it cannot see what a name resolves to, and it knows nothing
// about the operator's intent.
const BLOCKED_SUFFIXES = [".local", ".internal", ".localhost", ".home.arpa"];
const BLOCKED_NAMES = ["localhost", "metadata", "metadata.google.internal", "instance-data"];

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

// tcpAllowlist reads "host:port" entries from the environment. Absent or empty
// means nothing is reachable over TCP, which is the fail-closed default.
function tcpAllowlist(env) {
  const raw = env && env.RELAY_TCP_ALLOWLIST;
  if (typeof raw !== "string" || raw.trim() === "") return DEFAULT_TCP_ALLOWLIST;
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// hostPortAllowed matches a host and port against "host:port" entries.
//
// The port is mandatory in an entry. A bare host is rejected rather than
// treated as "any port", because accepting it would turn one careless
// configuration line into a full TCP tunnel to that host.
function hostPortAllowed(host, port, entries) {
  const h = String(host || "").trim().toLowerCase().replace(/\.$/, "");
  const p = Number(port);
  if (!h || !Number.isInteger(p) || p < 1 || p > 65535) return false;
  for (const entry of entries) {
    const idx = entry.lastIndexOf(":");
    if (idx <= 0) continue; // no port in the entry: not a usable rule
    const entryHost = entry.slice(0, idx);
    const entryPort = Number(entry.slice(idx + 1));
    if (entryPort !== p) continue;
    if (entryHost.startsWith("*.")) {
      const suffix = entryHost.slice(2);
      if (h === suffix || h.endsWith("." + suffix)) return true;
      continue;
    }
    if (h === entryHost) return true;
  }
  return false;
}

// blockedDestinationName reports why a name may never be reached.
function blockedDestinationName(host) {
  const h = String(host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h) return "empty host";
  if (BLOCKED_NAMES.includes(h)) return "reserved name: " + h;
  for (const suffix of BLOCKED_SUFFIXES) {
    if (h === suffix.slice(1) || h.endsWith(suffix)) return "reserved suffix: " + suffix;
  }
  // An IP literal in a private, loopback, link-local, CGNAT, reserved or
  // documentation range. Cloudflare would refuse these too; refusing them here
  // means the decision is Phaethon's and travels with the code.
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 0 || a === 10 || a === 127) return "non-routable IPv4 literal";
    if (a === 172 && b >= 16 && b <= 31) return "private IPv4 literal";
    if (a === 192 && b === 168) return "private IPv4 literal";
    if (a === 169 && b === 254) return "link-local IPv4 literal";
    if (a === 100 && b >= 64 && b <= 127) return "carrier-grade NAT IPv4 literal";
    if (a >= 224) return "multicast or reserved IPv4 literal";
  }
  if (h.startsWith("[") || h.includes(":")) {
    const v6 = h.replace(/^\[|\]$/g, "");
    if (v6 === "::" || v6 === "::1") return "loopback IPv6 literal";
    if (v6.startsWith("fe80") || v6.startsWith("fc") || v6.startsWith("fd")) {
      return "link-local or unique-local IPv6 literal";
    }
  }
  return "";
}

// authorizeDestination is the single decision point for a TCP request, so the
// allowlist and the destination rules cannot drift apart.
function authorizeDestination(host, port, env) {
  const entries = tcpAllowlist(env);
  if (!hostPortAllowed(host, port, entries)) {
    return { ok: false, reason: "host_not_allowlisted: " + host + ":" + port };
  }
  const why = blockedDestinationName(host);
  if (why) {
    return { ok: false, reason: "blocked_destination: " + why };
  }
  return { ok: true };
}

// parseConnectRequest reads the opening frame. Malformed input is refused
// rather than guessed at, because a wrong host is a wrong connection.
function parseConnectRequest(data) {
  let text;
  try {
    text = typeof data === "string" ? data : new TextDecoder().decode(data);
  } catch (e) {
    return { error: "unreadable opening frame" };
  }
  let req;
  try {
    req = JSON.parse(text);
  } catch (e) {
    return { error: "opening frame must be JSON" };
  }
  if (!req || typeof req.host !== "string" || !req.host) return { error: "opening frame needs a host" };
  const port = Number(req.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { error: "opening frame needs a port between 1 and 65535" };
  }
  return { host: req.host.trim().toLowerCase(), port };
}

function json(body, status = 200, extraHeaders = {}) {
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

function allowlist(env) {
  const raw = env && env.RELAY_ALLOWLIST;
  if (typeof raw === "string" && raw.trim() !== "") {
    return raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
  }
  return DEFAULT_ALLOWLIST;
}

// hostAllowed applies the wildcard rule Phaethon uses locally: "*.suffix"
// matches the bare domain and any subdomain.
function hostAllowed(host, patterns) {
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
function tokensMatch(provided, expected) {
  if (typeof expected !== "string" || expected.length === 0) return false;
  const a = String(provided || "");
  if (a.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

function tokenFrom(request) {
  const header = request.headers.get("x-phaethon-token");
  if (header) return header;
  const auth = request.headers.get("authorization") || "";
  if (auth.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  return "";
}

async function forward(request, env, host, restPath) {
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
    outHeaders.set("x-phaethon-colo", (request.cf && request.cf.colo) || "unknown");
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
        error_name: (err && err.name) || "Error",
        error: String((err && err.message) || err),
        elapsed_ms: Date.now() - started,
        colo: (request.cf && request.cf.colo) || null,
      },
      502,
    );
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Unauthenticated liveness, so a daemon can tell "relay reachable" from
    // "relay refuses this host". It reports whether a secret is configured,
    // because a relay without one would serve anyone who knows its URL.
    if (path === "/health" || path === "/") {
      return json({
        ok: true,
        service: "phaethon-relay",
        version: 1,
        runtime: "worker",
        colo: (request.cf && request.cf.colo) || null,
        country: (request.cf && request.cf.country) || null,
        token_configured:
          typeof env.PHAETHON_TOKEN === "string" && env.PHAETHON_TOKEN.length > 0,
        allowlist: allowlist(env),
        usage: "/relay/<host>/<path>",
      });
    }

    // TCP egress. This is a separate capability with its own allowlist: it is
    // never reachable through the HTTP path, and enabling it does not widen
    // what the HTTP relay carries.
    if (path === "/connect") {
      return handleConnect(request, env);
    }

    const match = path.match(/^\/relay\/([^/]+)(\/.*)?$/);
    if (!match) {
      return json({ error: "not_found", usage: "/relay/<host>/<path>" }, 404);
    }

    const host = decodeURIComponent(match[1]);
    const restPath = match[2] ? match[2].replace(/^\//, "") : "";

    if (!tokensMatch(tokenFrom(request), env.PHAETHON_TOKEN)) {
      return json(
        {
          error: "unauthorized",
          hint: "the relay requires its own secret on every request",
        },
        401,
      );
    }

    return forward(request, env, host, restPath);
  },
};

// ---- TCP egress ------------------------------------------------------------

// WS_BACKPRESSURE_BYTES is the point at which the return path stops reading
// from the destination.
//
// Workers WebSockets have no "ready to send" signal: send() buffers, and the
// buffer counts against the 128 MB isolate. Without a threshold, a fast
// destination and a slow client grow that buffer until the isolate dies, which
// presents to the user as the tunnel mysteriously breaking on a large transfer.
const WS_BACKPRESSURE_BYTES = 1 << 20;

// handleConnect upgrades to a WebSocket and carries raw bytes to one approved
// destination.
//
// Protocol: the first frame is JSON {host, port}; every frame after it is
// payload in either direction. Authentication happens before the upgrade, so an
// unauthorized client never gets a socket at all.
async function handleConnect(request, env) {
  if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
    return json(
      {
        error: "expected_websocket",
        hint: "the TCP endpoint is reached by upgrading to WebSocket, which is the only ingress a Worker supports",
      },
      426,
    );
  }
  if (!tokensMatch(tokenFrom(request), env.PHAETHON_TOKEN)) {
    return json(
      { error: "unauthorized", hint: "the TCP endpoint requires the relay secret" },
      401,
    );
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  // ArrayBuffer delivery, set before accept() so it applies to every frame.
  //
  // This is not a preference. On compatibility dates from 2026-03-17 onward
  // binaryType defaults to "blob", and a Blob is not a TypedArray: wrapping one
  // in new Uint8Array() yields an EMPTY array rather than an error. Every byte
  // the client sent was therefore written to the destination as nothing, which
  // presents as a tunnel that connects, receives the server's greeting, and
  // then hangs forever because the server never gets a request.
  server.binaryType = "arraybuffer";
  server.accept({ allowHalfOpen: true });

  let socket = null;
  let writer = null;
  let opened = false;
  let firstFrame = true;

  const refuse = (reason) => {
    try {
      server.send(JSON.stringify({ error: reason }));
    } catch (e) {
      // The client may already be gone; the close below is the real signal.
    }
    try {
      server.close(1008, String(reason).slice(0, 120));
    } catch (e) {}
  };

  // The return path: destination to client.
  const pumpBack = async () => {
    try {
      const reader = socket.readable.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value || !value.byteLength) continue;
        // Pause rather than buffer without bound.
        while (server.bufferedAmount > WS_BACKPRESSURE_BYTES) {
          await new Promise((r) => setTimeout(r, 20));
        }
        server.send(value);
      }
    } catch (e) {
      // A read error is a closed destination, which the close below reports.
    } finally {
      // Tell the client the destination has finished writing, before closing.
      // Without this the client cannot distinguish "reply finished" from "the
      // tunnel dropped", which is the difference between ssh exiting cleanly
      // and ssh hanging.
      try {
        server.send(JSON.stringify({ eof: true }));
      } catch (e) {}
      try {
        server.close(1000, "destination closed");
      } catch (e) {}
    }
  };

  server.addEventListener("message", async (event) => {
    if (firstFrame) {
      firstFrame = false;
      const req = parseConnectRequest(event.data);
      if (req.error) {
        refuse(req.error);
        return;
      }
      const decision = authorizeDestination(req.host, req.port, env);
      if (!decision.ok) {
        refuse(decision.reason);
        return;
      }
      try {
        socket = connect(
          { hostname: req.host, port: req.port },
          // allowHalfOpen on the socket too: SSH and SFTP finish writing and
          // still expect to read, and closing the read side on their FIN would
          // truncate the reply.
          { allowHalfOpen: true },
        );
        await socket.opened;
      } catch (e) {
        refuse("connect_failed: " + String((e && e.message) || e));
        return;
      }
      writer = socket.writable.getWriter();
      opened = true;
      try {
        server.send(JSON.stringify({ ok: true, host: req.host, port: req.port }));
      } catch (e) {}
      pumpBack();
      return; // the opening frame is a request, never payload
    }

    if (!opened || !writer) return;

    // Half-close, carried in-band because WebSocket has no half-close of its
    // own. A text frame means control; binary frames are payload, so a payload
    // that happens to look like JSON can never be mistaken for a signal.
    if (typeof event.data === "string") {
      let ctl = null;
      try {
        ctl = JSON.parse(event.data);
      } catch (e) {
        ctl = null;
      }
      if (ctl && ctl.eof) {
        try {
          await writer.close();
        } catch (e) {}
        return;
      }
      if (ctl) return; // an unrecognised control frame is not payload
    }

    try {
      const bytes = await frameBytes(event.data);
      if (!bytes) return;
      // await writer.ready is the socket's own backpressure, so a slow
      // destination applies backpressure instead of filling memory here.
      await writer.ready;
      await writer.write(bytes);
    } catch (e) {
      try {
        server.close(1011, "write failed");
      } catch (e2) {}
    }
  });

  server.addEventListener("close", () => {
    // Half-close in the other direction: the client has stopped writing but may
    // still be reading. Closing the writer propagates FIN to the destination
    // without tearing down the return path.
    if (writer) {
      try {
        writer.close();
      } catch (e) {}
    }
  });

  server.addEventListener("error", () => {
    try {
      if (socket) socket.close();
    } catch (e) {}
  });

  return new Response(null, { status: 101, webSocket: client });
}
// frameBytes converts an incoming frame into a Uint8Array, whatever shape the
// runtime delivered it in.
//
// The runtime can hand over a string, an ArrayBuffer, a view, or a Blob
// depending on compatibility date and binaryType. Assuming one shape is how
// client bytes get silently discarded: a Blob wrapped in new Uint8Array()
// produces an empty array rather than an error, so the destination receives
// nothing and the session hangs with no clue why.
async function frameBytes(data) {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data && typeof data.arrayBuffer === "function") {
    return new Uint8Array(await data.arrayBuffer());
  }
  return null;
}