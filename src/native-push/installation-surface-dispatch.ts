import { sha256Hex } from "../crypto";
import type { AppEnv } from "../types";
import { createSurfaceService, type SurfaceServiceOptions } from "../surface-push/composition";
import { readBody } from "../surface-push/issuer-wire";
import { SurfaceError } from "../surface-push/wire";

const issuerPrefix = "/v1/push/surface/issuer/";
const issuerActions = new Set(["challenge", "issue", "status", "withdraw"]);
const targetActions = new Set(["register", "status", "revoke", "event"]);

/** No old operator row is admitted: every operation locates genuine native provenance. */
export function createInstallationSurfaceService(options: Omit<SurfaceServiceOptions, "nativeHistoricalNegative">) {
 const service = createSurfaceService({ ...options, nativeHistoricalNegative: true });
 return async (request: Request) => {
  try {
   const path = new URL(request.url).pathname;
   if (!path.startsWith("/v1/push/surface/")) throw new SurfaceError(404, "native_surface_route_unavailable");
   const issuer = path.startsWith(issuerPrefix), action = path.slice(issuer ? issuerPrefix.length : "/v1/push/surface/".length);
   if (request.method !== "POST" || !(issuer ? issuerActions : targetActions).has(action))
    throw new SurfaceError(404, "native_surface_route_unavailable");
   let delegation: string | null = null;
   if (issuer) {
    const { value } = await readBody(request.clone());
    const input = value as { payload?: { delegation_id?: unknown } };
    if (typeof input?.payload?.delegation_id === "string") delegation = input.payload.delegation_id;
   } else {
    const match = /^Bearer (djcs_[A-Za-z0-9_-]{43})$/.exec(request.headers.get("authorization") ?? "");
    if (!match) throw new SurfaceError(401, "surface_auth_required");
    const row = await options.env.DB.prepare(`SELECT c.delegation_id FROM surface_push_capabilities c
     JOIN native_installation_surface_bindings n ON n.delegation_id=c.delegation_id WHERE c.token_hash=?`)
     .bind(await sha256Hex(match[1])).first<{ delegation_id: string }>();
    delegation = row?.delegation_id ?? null;
   }
   if (!delegation) throw new SurfaceError(403, "native_surface_provenance_required");
   const negative = issuer ? action === "status" || action === "withdraw" : action === "status" || action === "revoke";
   const row = await options.env.DB.prepare(negative
    ? "SELECT 1 FROM native_installation_surface_bindings WHERE delegation_id=?"
    : "SELECT 1 FROM native_installation_live_delegations WHERE id=?").bind(delegation).first();
   if (!row) throw new SurfaceError(403, "native_surface_provenance_required");
   return await service.handle(request);
  } catch (error) {
   return Response.json({ contract_version: 1, success: false,
    error: error instanceof SurfaceError ? error.code : "native_surface_unavailable" }, {
    status: error instanceof SurfaceError ? error.status : 503,
    headers: { "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" },
   });
  }
 };
}

/** Scoped public composition only. Generic surface/operator/activity gates stay closed. */
export function dispatchInstallationSurfaceRequest(request: Request, env: unknown): Promise<Response> | undefined {
 const url = new URL(request.url);
 if (url.origin !== "https://api.djconnect.dev") return undefined;
 const path = url.pathname;
 if (request.method !== "POST" || !path.startsWith("/v1/push/surface/")) return undefined;
 const issuer = path.startsWith(issuerPrefix);
 const action = path.slice(issuer ? issuerPrefix.length : "/v1/push/surface/".length);
 if (!(issuer ? issuerActions : targetActions).has(action)) return undefined;
 const selected = env as AppEnv, db = selected.DB;
 return createInstallationSurfaceService({ env: selected, isCurrent: () => selected.DB === db })(request);
}
