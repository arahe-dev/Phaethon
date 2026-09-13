// GET|POST|... /relay/<host>/<path...>
//
// The single relay entry point. Everything is decided server-side: token
// first, then the host allowlist, then the fetch.
import { forward, json, tokensMatch } from "../../lib/relay.js";

export async function onRequest(context) {
  const { request, env, params } = context;

  const expected = env.PHAETHON_TOKEN;
  if (typeof expected !== "string" || expected.length === 0) {
    return json(
      { error: "relay_not_configured", hint: "set the PHAETHON_TOKEN secret on this Pages project" },
      503,
    );
  }
  const provided = request.headers.get("x-phaethon-token") || "";
  if (!tokensMatch(provided, expected)) {
    return json({ error: "unauthorized", hint: "X-Phaethon-Token is required" }, 401);
  }

  const segments = Array.isArray(params.path) ? params.path : [params.path || ""];
  const host = String(segments[0] || "").trim();
  if (!host) {
    return json({ error: "missing_host", usage: "/relay/<host>/<path>" }, 400);
  }
  const restPath = segments.slice(1).join("/");
  return forward(request, env, host, restPath);
}
