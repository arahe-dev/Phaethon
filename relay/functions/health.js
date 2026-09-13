// GET /health — unauthenticated liveness plus the relay's own allowlist,
// so a daemon can tell "relay reachable" from "relay refuses this host".
import { allowlist, json } from "../lib/relay.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  return json({
    ok: true,
    service: "phaethon-relay",
    version: 1,
    colo: request.cf?.colo ?? null,
    country: request.cf?.country ?? null,
    token_configured: typeof env.PHAETHON_TOKEN === "string" && env.PHAETHON_TOKEN.length > 0,
    allowlist: allowlist(env),
    usage: "/relay/<host>/<path>",
  });
}
