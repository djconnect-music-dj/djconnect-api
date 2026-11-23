import type { NativeAppleEvidencePolicy } from "../../coordinator/host-app-wake-receiving/native-apple-evidence.mjs";
import { createWidgetFirstKeyAppleVerifier } from "./first-key-apple";
import { createWidgetFirstKeyHandler, createWidgetFirstKeyRetirementHandler, type WidgetFirstKeyPolicy } from "./first-key-service";
import type { FirstKeyPairBinding } from "./first-key-wire";
import { authenticateInstallation } from "./installation-publisher";
import { SurfaceError } from "../surface-push/wire";

interface SelectedApplePolicy {
 readonly id: string;
 readonly expiresAt: number;
 readonly apple: Readonly<NativeAppleEvidencePolicy>;
}
interface Original extends FirstKeyPairBinding { operation_id: string }
const nowSQL = "CAST(unixepoch('subsec') * 1000 AS INTEGER)";

/** Native proof policy comes from the trusted signed-app composition, not JSON.
 * Publication is not enrollment. Only the existing Apple/Core crypto verifier
 * and first-key journal can produce a registration receipt.
 */
export function createInstallationFirstKey(db: D1Database, origin: string, current: () => boolean,
 selected?: Readonly<SelectedApplePolicy>) {
 return async (request: Request) => {
  try {
   if (!selected || selected.id !== "ios-native-push-development-40532/1" ||
       !Number.isSafeInteger(selected.expiresAt) || Date.now() >= selected.expiresAt || !current())
    throw new SurfaceError(503, "native_first_key_policy_unavailable");
   const credential = await authenticateInstallation(request, db, current);
   const live = () => current() && Date.now() < selected.expiresAt && !request.signal.aborted;
   const query = (original: Original, retirementDeadline?: number) => ({
    sql: `EXISTS (SELECT 1 FROM native_installation_pair_publications p
      JOIN install_tokens i ON i.id=p.credential_id
      WHERE p.credential_id=? AND i.token_hash=? AND i.ha_install_id=? AND i.disabled=0
      AND p.operation_id=? AND p.pairing_generation=? AND p.pair_binding=?
      AND p.owner_binding=? AND p.device_binding=? AND p.core_key_thumbprint=?
      ${retirementDeadline === undefined ? `AND p.request_expires_at_ms > ${nowSQL}
      AND NOT EXISTS (SELECT 1 FROM native_installation_consent_withdrawals w
       WHERE w.credential_id=p.credential_id AND w.pair_binding=p.pair_binding
       AND w.through_revision>=p.consent_revision)
      AND NOT EXISTS (SELECT 1 FROM native_installation_key_retirements r
       WHERE r.credential_id=p.credential_id AND r.pair_binding=p.pair_binding)` : "AND p.request_expires_at_ms=?"}
      ) AND ? > ${nowSQL}`,
    values: [credential.id, credential.token_hash, credential.ha_install_id,
     original.operation_id, original.pairing_generation, original.pair_binding,
     original.owner_binding, original.device_binding, original.core_key_thumbprint,
     ...(retirementDeadline === undefined ? [] : [retirementDeadline]), selected.expiresAt],
   });
   const policy: WidgetFirstKeyPolicy = {
    id: selected.id, expiresAt: selected.expiresAt, isCurrent: live,
    async isPairCurrent(credentialId, original) {
     if (credentialId !== credential.id || !live()) return false;
     const guard = query(original);
     return !!await db.prepare(`SELECT 1 WHERE ${guard.sql}`).bind(...guard.values).first() && live();
    },
    pairSqlGuard(credentialId, original) {
     return credentialId === credential.id && live() ? query(original) : { sql: "0", values: [] };
    },
    verifyApple: createWidgetFirstKeyAppleVerifier(selected.apple),
   };
   if (new URL(request.url).pathname === "/v1/push/native/key/retire") {
    return await createWidgetFirstKeyRetirementHandler(db, origin, event =>
     live() && event.install_credential_id === credential.id ? query(event, event.request_expires_at_ms) : null,
     "installation")(request);
   }
   return await createWidgetFirstKeyHandler(db, origin, live, policy, async (_request, decision) => {
    if (!live() || decision.install_credential_id !== credential.id) return false;
    const guard = query(decision);
    return !!await db.prepare(`SELECT 1 WHERE ${guard.sql}`).bind(...guard.values).first() && live();
   }, "installation")(request);
  } catch (error) {
   return Response.json({ error: error instanceof SurfaceError ? error.code : "native_first_key_unavailable" }, {
    status: error instanceof SurfaceError ? error.status : 503,
    headers: { "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" },
   });
  }
 };
}
