import type { AppEnv } from "../types";
import { sha256Hex } from "../crypto";
import { canonical, need, SurfaceError } from "../surface-push/wire";
import { bytes, closed, enrolment, ISSUER_VERSION, publicKey, thumbprint } from "../surface-push/issuer-wire";
import { readFirstKeyBody } from "./first-key-service";
import { authenticateInstallation } from "./installation-publisher";
import { installationNativePolicy } from "./installation-policy";

export const installationEnrolPath = "/v1/push/native/installation/issuer/enrol";
export const installationEnrolVersion = "djc-installation-surface-delegation/1";
const nowSQL = "CAST(unixepoch('subsec')*1000 AS INTEGER)";
const headers = { "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" };
interface NativeRow {
 receipt: string; key_spki: string; original_request: string; expires_at_ms: number; consent_revision: number;
 apple_evidence_expires_at_ms:number; apple_status_expires_at_ms:number;
}
export function installationEnrolSigningBytes(receipt: unknown, delegation: unknown): Uint8Array<ArrayBuffer> {
 return Uint8Array.from(new TextEncoder().encode(canonical([installationEnrolVersion, "POST", installationEnrolPath, receipt, delegation])));
}

/** Own active credential plus genuine native-key signature, never operator auth. */
export function createInstallationSurfaceEnrol(env: AppEnv, current: () => boolean) {
 return async (request: Request) => {
  try {
   need(request.method === "POST" && request.url === "https://api.djconnect.dev" + installationEnrolPath &&
    !request.headers.has("origin") && !request.headers.has("cookie"), "native_role_route_unavailable", 404);
   const db = env.DB, policy = installationNativePolicy;
   const live = () => current() && env.DB === db && Date.now() < policy.expiresAt && !request.signal.aborted;
   const credential = await authenticateInstallation(request, db, live);
   const input = await readFirstKeyBody(request, 8192, true);
   closed(input, ["contract_version", "first_key_receipt", "delegation", "signature"]);
   need(input.contract_version === 1);
   const native = input.first_key_receipt;
   need(native !== null && typeof native === "object" && !Array.isArray(native));
   const receipt = native as Record<string, unknown>;
   need(receipt.install_credential_id === credential.id && receipt.state === "registered" && receipt.key_revision === 1,
    "native_role_first_key_required", 403);
   const originalReceipt = canonical(receipt);
   let guardSQL = `EXISTS(SELECT 1 FROM native_installation_first_key k
    JOIN install_tokens i ON i.id=k.credential_id AND i.token_hash=? AND i.ha_install_id=? AND i.disabled=0
    JOIN native_installation_pair_publications p ON p.credential_id=k.credential_id AND p.operation_id=k.operation_id
    WHERE k.credential_id=? AND k.operation_id=? AND k.receipt=? AND k.policy_id=? AND k.retired=0
    AND k.expires_at_ms>${nowSQL} AND p.request_expires_at_ms>${nowSQL}
    AND k.apple_key_id_b64 IS NOT NULL AND k.apple_public_key_spki_b64 IS NOT NULL AND k.apple_assertion_policy_json IS NOT NULL
    AND k.apple_evidence_expires_at_ms>${nowSQL} AND k.apple_status_expires_at_ms>${nowSQL}
    AND json_extract(k.original_request,'$.pairing_generation')=p.pairing_generation
    AND json_extract(k.original_request,'$.pair_binding')=p.pair_binding
    AND json_extract(k.original_request,'$.owner_binding')=p.owner_binding
    AND json_extract(k.original_request,'$.device_binding')=p.device_binding
    AND json_extract(k.original_request,'$.core_key_thumbprint')=p.core_key_thumbprint
    AND NOT EXISTS(SELECT 1 FROM native_installation_key_retirements r
     WHERE r.credential_id=k.credential_id AND r.pair_binding=p.pair_binding)
    AND NOT EXISTS(SELECT 1 FROM native_installation_consent_withdrawals w
     WHERE w.credential_id=k.credential_id AND w.pair_binding=p.pair_binding AND w.through_revision>=p.consent_revision))
    AND ?>${nowSQL}`;
   const guardValues = [credential.token_hash, credential.ha_install_id, credential.id,
    receipt.operation_id, originalReceipt, policy.id, policy.expiresAt];
   const row = await db.prepare(`SELECT k.receipt,k.key_spki,k.original_request,k.expires_at_ms,p.consent_revision,k.apple_evidence_expires_at_ms,k.apple_status_expires_at_ms
    FROM native_installation_first_key k JOIN native_installation_pair_publications p
    ON p.credential_id=k.credential_id AND p.operation_id=k.operation_id
    WHERE k.credential_id=? AND k.operation_id=? AND k.receipt=? AND ${guardSQL}`)
    .bind(credential.id, receipt.operation_id, originalReceipt, ...guardValues).first<NativeRow>();
   need(row && live(), "native_role_first_key_required", 403);
   const delegation = enrolment(input.delegation, Date.now(), []);
   const p = delegation.policy;
   need(delegation.install_id === receipt.api_installation_id && delegation.approval_reference === receipt.registry_generation &&
    p.token_role === "widget" && p.platform === "ios" && p.activity_profile === null && p.external_content_allowed === false &&
    p.apns_environment === env.APNS_ENVIRONMENT && p.target.app_bundle_id === "dev.djconnect.ios" &&
    p.target.extension_bundle_id === "dev.djconnect.ios.track-insight-widget" && p.target.widget_kind === "DJConnectSessionWidget" &&
    p.original_grant_expires_at_ms <= Math.min(policy.expiresAt,row.apple_evidence_expires_at_ms,row.apple_status_expires_at_ms), "native_role_scope_mismatch", 403);
   guardSQL += ` AND EXISTS(SELECT 1 FROM native_installation_first_key WHERE credential_id=? AND operation_id=? AND receipt=?
    AND apple_evidence_expires_at_ms=? AND apple_status_expires_at_ms=? AND apple_evidence_expires_at_ms>=? AND apple_status_expires_at_ms>=?)`;
   guardValues.push(credential.id,receipt.operation_id,originalReceipt,row.apple_evidence_expires_at_ms,row.apple_status_expires_at_ms,
    p.original_grant_expires_at_ms,p.original_grant_expires_at_ms);
   const rawSPKI = Uint8Array.from(atob(row.key_spki), c => c.charCodeAt(0));
   const key = await crypto.subtle.importKey("spki", rawSPKI, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
   const jwk = await crypto.subtle.exportKey("jwk", key) as JsonWebKey;
   await publicKey(delegation.public_key);
   need(jwk.kty === delegation.public_key.kty && jwk.crv === delegation.public_key.crv &&
    jwk.x === delegation.public_key.x && jwk.y === delegation.public_key.y, "native_role_key_mismatch", 403);
   const statement = installationEnrolSigningBytes(receipt, delegation);
   need(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, bytes(input.signature as string, 64), statement)
    && live(), "native_role_signature_required", 403);
   const original = JSON.parse(row.original_request) as { pair_binding: string };
   const keyHash = await thumbprint(delegation.public_key);
   const requestHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", statement)),
    value => value.toString(16).padStart(2, "0")).join("");
   const scope = await sha256Hex(canonical([ISSUER_VERSION, "delegation", delegation.delegation_id, 1,
    delegation.install_id, delegation.device_binding, delegation.owner_binding, delegation.grant_binding,
    delegation.source_binding, delegation.binding_id, keyHash, delegation.policy]));
   const claim = crypto.randomUUID();
   // An original native first-key winner can transfer to one initial role only.
   // Existing exact replay is read below, but cannot acquire another claim.
   const initialGuard = guardSQL + ` AND NOT EXISTS(SELECT 1 FROM native_installation_surface_bindings
    WHERE credential_id=? AND native_operation_id=? AND admission_kind='initial')`;
   const initialValues = [...guardValues, credential.id, receipt.operation_id];
   await db.batch([
    db.prepare(`INSERT OR IGNORE INTO surface_push_operator_operations(operation_id,request_hash,delegation_id,kind,claim_id,outcome)
     SELECT ?,?,?,'enrol',?,'pending' WHERE ${initialGuard}`)
     .bind(delegation.operation_id, requestHash, delegation.delegation_id, claim, ...initialValues),
    db.prepare(`INSERT OR IGNORE INTO surface_push_delegations
     (id,revision,enrol_operation_id,approval_reference,install_id,device_binding,owner_binding,grant_binding,source_binding,
      binding_id,public_key_json,key_thumbprint,policy_json,scope_digest,expires_at,created_at,revoked_at)
     SELECT ?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL WHERE ${initialGuard}
      AND EXISTS(SELECT 1 FROM surface_push_operator_operations WHERE operation_id=? AND claim_id=? AND outcome='pending')`)
     .bind(delegation.delegation_id, delegation.operation_id, delegation.approval_reference, delegation.install_id,
      delegation.device_binding, delegation.owner_binding, delegation.grant_binding, delegation.source_binding,
      delegation.binding_id, canonical(delegation.public_key), keyHash, canonical(p), scope,
      p.original_grant_expires_at_ms, Date.now(), ...initialValues, delegation.operation_id, claim),
    db.prepare(`INSERT OR IGNORE INTO native_installation_surface_bindings
     (delegation_id,credential_id,credential_hash,ha_install_id,native_operation_id,publication_operation_id,native_receipt_json,pair_binding,
      consent_revision,enrolment_sha256,scope_digest)
     SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE ${initialGuard}
      AND EXISTS(SELECT 1 FROM surface_push_operator_operations WHERE operation_id=? AND claim_id=? AND outcome='pending')
      AND EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND enrol_operation_id=? AND scope_digest=? AND revoked_at IS NULL)`)
     .bind(delegation.delegation_id, credential.id, credential.token_hash, credential.ha_install_id,
      receipt.operation_id, receipt.operation_id, originalReceipt, original.pair_binding, row.consent_revision, requestHash, scope,
      ...initialValues, delegation.operation_id, claim, delegation.delegation_id, delegation.operation_id, scope),
    db.prepare(`UPDATE surface_push_operator_operations SET outcome=CASE WHEN EXISTS(
     SELECT 1 FROM native_installation_surface_bindings n JOIN native_installation_live_delegations d ON d.id=n.delegation_id
     WHERE n.delegation_id=? AND n.enrolment_sha256=? AND n.scope_digest=?) THEN 'enrolled' ELSE 'conflict' END
     WHERE operation_id=? AND claim_id=?`).bind(delegation.delegation_id, requestHash, scope, delegation.operation_id, claim),
   ]);
   const op = await db.prepare(`SELECT o.claim_id,o.outcome,o.request_hash,n.enrolment_sha256
    FROM surface_push_operator_operations o JOIN native_installation_surface_bindings n ON n.delegation_id=o.delegation_id
    JOIN native_installation_live_delegations d ON d.id=n.delegation_id WHERE o.operation_id=? AND n.credential_id=?`)
    .bind(delegation.operation_id, credential.id).first<{ claim_id: string; outcome: string; request_hash: string; enrolment_sha256: string }>();
   need(op?.outcome === "enrolled" && op.request_hash === requestHash && op.enrolment_sha256 === requestHash && live(),
    "native_role_enrolment_conflict", 409);
   const owns = op.claim_id === claim;
   return Response.json({ contract_version: 1, success: owns, state: owns ? "enrolled" : "unknown", replayed: !owns,
    delegation_id: delegation.delegation_id, delegation_revision: 1, key_thumbprint: keyHash, scope_digest: scope,
    expires_at_ms: p.original_grant_expires_at_ms, enrol_operation_id: delegation.operation_id,
    install_credential_id: credential.id, native_operation_id: receipt.operation_id,
    native_api_installation_id: receipt.api_installation_id, native_registry_generation: receipt.registry_generation,
    enrolment_sha256: requestHash }, { status: owns ? 200 : 202, headers });
  } catch (error) {
   return Response.json({ error: error instanceof SurfaceError ? error.code : "native_role_unavailable" },
    { status: error instanceof SurfaceError ? error.status : 503, headers });
  }
 };
}
