/** Genuine saved-key Widget reauthorization; no first-key replay or HostWake authority. */
import type { AppEnv } from "../types";
import { base64Url, sha256Hex } from "../crypto";
import { canonical, need, SurfaceError } from "../surface-push/wire";
import { bytes, closed, enrolment, ISSUER_VERSION, thumbprint, type Enrolment } from "../surface-push/issuer-wire";
import { readFirstKeyBody } from "./first-key-service";
import { authenticateInstallation } from "./installation-publisher";
import { installationNativePolicy } from "./installation-policy";
import { verifyNativeAssertionCrypto } from "../../coordinator/host-app-wake-receiving/native-assertion-crypto";
import { RequestWindow } from "../../coordinator/host-app-wake-receiving/request-window";
export const reauthorizationPrefix = "/v1/push/native/installation/issuer/reauthorize/";
export const reauthorizationVersion = "djc-installation-widget-reauthorization/1";
const sqlNow = "CAST(unixepoch('subsec')*1000 AS INTEGER)";
const headers = {"cache-control":"no-store","referrer-policy":"no-referrer","x-content-type-options":"nosniff"};
interface NativeKey {
 key_spki:string; original_request:string; apple_key_id_b64:string; apple_public_key_spki_b64:string;
 apple_assertion_policy_json:string; apple_counter:number; apple_evidence_expires_at_ms:number;
 apple_status_expires_at_ms:number; request_expires_at_ms:number; consent_revision:number;
}
interface ChallengeRow {id:string;request_json:string;challenge_json:string;claim_id:string;outcome:string;expires_at_ms:number}
export function reauthorizationSigningBytes(action:"challenge"|"register", native:unknown, publication:unknown,
 delegation:unknown):Uint8Array<ArrayBuffer> {
 return Uint8Array.from(new TextEncoder().encode(canonical([reauthorizationVersion,"POST",reauthorizationPrefix+action,
  ...(action === "challenge" ? [native,publication,delegation] : [publication,native,delegation])])));
}
function signatureKey(spki:string) {
 return crypto.subtle.importKey("spki",Uint8Array.from(atob(spki),c=>c.charCodeAt(0)),{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
}
function widget(delegation:Enrolment, env:AppEnv) {
 const p=delegation.policy;
 need(p.token_role==="widget"&&p.platform==="ios"&&p.activity_profile===null&&!p.external_content_allowed&&
  p.apns_environment===env.APNS_ENVIRONMENT&&p.target.app_bundle_id==="dev.djconnect.ios"&&
  p.target.extension_bundle_id==="dev.djconnect.ios.track-insight-widget"&&p.target.widget_kind==="DJConnectSessionWidget"&&
  p.original_grant_expires_at_ms<=installationNativePolicy.expiresAt,"native_role_scope_mismatch",403);
}
/** Only this principal's genuine saved Apple key and a newer exact publication qualify. */
export function createInstallationReauthorization(env:AppEnv,current:()=>boolean) {
 return async(request:Request)=>{
  let window:RequestWindow|undefined, claimed:ChallengeRow|undefined;
  try {
   const path=new URL(request.url).pathname, action=path.slice(reauthorizationPrefix.length);
   need(request.method==="POST"&&(action==="challenge"||action==="register")&&
    request.url==="https://api.djconnect.dev"+reauthorizationPrefix+action&&
    !request.headers.has("origin")&&!request.headers.has("cookie"),"native_role_route_unavailable",404);
   const db=env.DB, selected=installationNativePolicy;
   const live=()=>current()&&env.DB===db&&!request.signal.aborted&&Date.now()<selected.expiresAt;
   const credential=await authenticateInstallation(request,db,live);
   const input=await readFirstKeyBody(request,action==="challenge"?8192:24576,true);
   closed(input,action==="challenge"?["contract_version","first_key_receipt","publication_operation_id","delegation","signature"]:
    ["contract_version","challenge","first_key_receipt","delegation","apple_proof"]);
   need(input.contract_version===1&&input.first_key_receipt!==null&&typeof input.first_key_receipt==="object"&&!Array.isArray(input.first_key_receipt));
   const native=input.first_key_receipt as Record<string,unknown>, nativeJSON=canonical(native);
   need(native.install_credential_id===credential.id&&native.state==="registered"&&native.key_revision===1,"native_role_first_key_required",403);
   const delegation=enrolment(input.delegation,Date.now(),[]);widget(delegation,env);
   need(delegation.install_id===native.api_installation_id&&delegation.approval_reference===native.registry_generation,"native_role_scope_mismatch",403);
   let challenge:Record<string,unknown>|undefined;
   if(action==="register") {
    need(input.challenge!==null&&typeof input.challenge==="object"&&!Array.isArray(input.challenge));
    challenge=input.challenge as Record<string,unknown>;
    closed(challenge,["contract_version","api_audience","challenge_id","challenge_nonce","expires_at_ms",
     "publication_operation_id","first_key_receipt_sha256","delegation_sha256"]);
    need(challenge.contract_version===1&&challenge.api_audience==="djc-native-push/1");
   }
   const publication=action==="challenge"?input.publication_operation_id:challenge!.publication_operation_id;
   need(typeof publication==="string"&&/^[A-Za-z0-9_-]{1,128}$/.test(publication));
   let guardSQL=`EXISTS(SELECT 1 FROM native_installation_first_key k
    JOIN install_tokens i ON i.id=k.credential_id AND i.token_hash=? AND i.ha_install_id=? AND i.disabled=0
    JOIN native_installation_pair_publications original ON original.credential_id=k.credential_id AND original.operation_id=k.operation_id
    JOIN native_installation_pair_publications p ON p.credential_id=k.credential_id AND p.operation_id=?
    WHERE k.credential_id=? AND k.operation_id=? AND k.receipt=? AND k.policy_id=? AND k.retired=0
    AND k.apple_key_id_b64 IS NOT NULL AND k.apple_public_key_spki_b64 IS NOT NULL AND k.apple_assertion_policy_json IS NOT NULL
    AND typeof(k.apple_counter)='integer' AND k.apple_counter>=0 AND k.apple_counter<=4294967295
    AND k.apple_evidence_expires_at_ms>${sqlNow} AND k.apple_status_expires_at_ms>${sqlNow}
    AND p.request_expires_at_ms>${sqlNow} AND p.consent_revision>original.consent_revision
    AND json_extract(k.original_request,'$.pairing_generation')=p.pairing_generation
    AND json_extract(k.original_request,'$.pair_binding')=p.pair_binding
    AND json_extract(k.original_request,'$.owner_binding')=p.owner_binding
    AND json_extract(k.original_request,'$.device_binding')=p.device_binding
    AND json_extract(k.original_request,'$.core_key_thumbprint')=p.core_key_thumbprint
    AND NOT EXISTS(SELECT 1 FROM native_installation_key_retirements r WHERE r.credential_id=k.credential_id AND r.pair_binding=p.pair_binding)
    AND NOT EXISTS(SELECT 1 FROM native_installation_consent_withdrawals w WHERE w.credential_id=k.credential_id
     AND w.pair_binding=p.pair_binding AND w.through_revision>=p.consent_revision)) AND ?>${sqlNow}`;
   const guardValues=[credential.token_hash,credential.ha_install_id,publication,credential.id,native.operation_id,nativeJSON,selected.id,selected.expiresAt];
   const key=await db.prepare(`SELECT k.*,p.request_expires_at_ms,p.consent_revision FROM native_installation_first_key k
    JOIN native_installation_pair_publications p ON p.credential_id=k.credential_id AND p.operation_id=?
    WHERE k.credential_id=? AND k.operation_id=? AND ${guardSQL}`)
    .bind(publication,credential.id,native.operation_id,...guardValues).first<NativeKey>();
   need(key&&live(),"native_role_current_publication_required",403);
   need(Number.isSafeInteger(key.apple_counter)&&key.apple_counter>=0&&key.apple_counter<=0xffffffff,
    "native_role_saved_counter_invalid",503);
   // Capture the genuine stored key metadata before any further await. Its
   // original identity/deadlines must still match at every SQL commit; a later
   // assertion counter is separately serialized by the actual counter CAS.
   guardSQL += ` AND EXISTS(SELECT 1 FROM native_installation_first_key WHERE credential_id=? AND operation_id=?
    AND key_spki=? AND apple_key_id_b64=? AND apple_public_key_spki_b64=? AND apple_assertion_policy_json=?
    AND apple_evidence_expires_at_ms=? AND apple_status_expires_at_ms=?)`;
   guardValues.push(credential.id,native.operation_id,key.key_spki,key.apple_key_id_b64,key.apple_public_key_spki_b64,
    key.apple_assertion_policy_json,key.apple_evidence_expires_at_ms,key.apple_status_expires_at_ms);
   const policy=JSON.parse(key.apple_assertion_policy_json) as Record<string,unknown>;
   closed(policy,["profile","app_identifier","bundle_version","launch_validation_category_b64"]);
   need(policy.profile==="host_wake_apple_assertion_properties_v2"&&policy.app_identifier===selected.apple.app_identifier&&
    policy.bundle_version===selected.apple.bundle_version&&policy.launch_validation_category_b64===selected.apple.launch_validation_category_b64,
    "native_role_saved_apple_policy_required",403);
   const publicKey=await signatureKey(key.key_spki);
   const exported=await crypto.subtle.exportKey("jwk",await crypto.subtle.importKey("spki",
    Uint8Array.from(atob(key.key_spki),c=>c.charCodeAt(0)),{name:"ECDSA",namedCurve:"P-256"},true,["verify"])) as JsonWebKey;
   need(exported.x===delegation.public_key.x&&exported.y===delegation.public_key.y,"native_role_key_mismatch",403);
   const original={contract_version:1,first_key_receipt:native,publication_operation_id:publication,delegation};
   const originalJSON=canonical(original);
   const deadline=Math.min(key.request_expires_at_ms,key.apple_evidence_expires_at_ms,key.apple_status_expires_at_ms,selected.expiresAt);
   need(Date.now()<deadline&&delegation.policy.original_grant_expires_at_ms<=Math.min(key.apple_evidence_expires_at_ms,
    key.apple_status_expires_at_ms,selected.expiresAt),"native_role_evidence_expired",403);
   if(action==="challenge") {
    need(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},publicKey,bytes(input.signature as string,64),
     reauthorizationSigningBytes("challenge",native,publication,delegation))&&live(),"native_role_signature_required",403);
    const id=crypto.randomUUID(),claim=crypto.randomUUID(),nonce=base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const challenge={contract_version:1,api_audience:"djc-native-push/1",challenge_id:id,challenge_nonce:nonce,
     expires_at_ms:Math.min(Date.now()+120000,deadline),publication_operation_id:publication,
     first_key_receipt_sha256:await sha256Hex(nativeJSON),delegation_sha256:await sha256Hex(canonical(delegation))};
    const saved=await db.prepare(`INSERT OR IGNORE INTO native_installation_role_challenges
     (id,credential_id,credential_hash,ha_install_id,native_operation_id,native_receipt_json,publication_operation_id,
      consent_revision,request_json,challenge_json,expires_at_ms,claim_id,outcome)
     SELECT ?,?,?,?,?,?,?,?,?,?,?,?,'pending' WHERE ${guardSQL}
     AND NOT EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=?) RETURNING id`)
     .bind(id,credential.id,credential.token_hash,credential.ha_install_id,native.operation_id,nativeJSON,publication,key.consent_revision,
      originalJSON,canonical(challenge),challenge.expires_at_ms,claim,...guardValues,delegation.delegation_id).first();
    need(saved&&live(),"native_role_challenge_consumed",409);
    return Response.json(challenge,{headers});
   }
   closed(input.apple_proof,["kind","key_id_b64","proof_b64"]);
   const proof=input.apple_proof as Record<string,unknown>;
   need(proof.kind==="assertion"&&proof.key_id_b64===key.apple_key_id_b64&&typeof proof.proof_b64==="string"&&
    proof.proof_b64.length>0&&proof.proof_b64.length<=12288&&/^[A-Za-z0-9+/]+={0,2}$/.test(proof.proof_b64)&&
    btoa(atob(proof.proof_b64))===proof.proof_b64,"native_role_assertion_required",403);
   const claim=crypto.randomUUID();
   claimed=await db.prepare(`UPDATE native_installation_role_challenges SET outcome='verifying',claim_id=?
    WHERE id=? AND credential_id=? AND credential_hash=? AND ha_install_id=? AND native_operation_id=? AND native_receipt_json=?
     AND publication_operation_id=? AND consent_revision=? AND request_json=? AND challenge_json=? AND outcome='pending'
     AND expires_at_ms>${sqlNow} AND ${guardSQL} RETURNING *`)
    .bind(claim,challenge!.challenge_id,credential.id,credential.token_hash,credential.ha_install_id,native.operation_id,nativeJSON,
     publication,key.consent_revision,originalJSON,canonical(challenge),...guardValues).first<ChallengeRow>()??undefined;
   need(claimed&&live(),"native_role_challenge_consumed",409);
   const remaining=claimed.expires_at_ms-Date.now();need(remaining>0,"native_role_challenge_consumed",409);
   window=new RequestWindow(Date.now,AbortSignal.any([request.signal,AbortSignal.timeout(remaining)]));
   const counter=await verifyNativeAssertionCrypto(Uint8Array.from(atob(proof.proof_b64),c=>c.charCodeAt(0)),
    reauthorizationSigningBytes("register",native,challenge,delegation),
    {public_key_spki_b64:key.apple_public_key_spki_b64,native_key_id_b64:key.apple_key_id_b64,counter:key.apple_counter},
    policy as {profile:string;app_identifier:string;bundle_version:string;launch_validation_category_b64:string},window);
   need(counter!==null&&live(),"native_role_assertion_rejected",403);window.check();
   const keyHash=await thumbprint(delegation.public_key),requestHash=await sha256Hex(new TextDecoder().decode(
    reauthorizationSigningBytes("challenge",native,publication,delegation)));
   const scope=await sha256Hex(canonical([ISSUER_VERSION,"delegation",delegation.delegation_id,1,delegation.install_id,
    delegation.device_binding,delegation.owner_binding,delegation.grant_binding,delegation.source_binding,delegation.binding_id,keyHash,delegation.policy]));
   const originalPair=(JSON.parse(key.original_request) as {pair_binding:string}).pair_binding;
   const claimGuard=`EXISTS(SELECT 1 FROM native_installation_role_challenges WHERE id=? AND claim_id=? AND outcome='verifying'
    AND expires_at_ms>${sqlNow} AND request_json=?)`;
   const claimValues=[claimed.id,claim,originalJSON];
   const roleGuard=`${guardSQL} AND ${claimGuard} AND EXISTS(SELECT 1 FROM native_installation_first_key WHERE credential_id=?
    AND operation_id=? AND apple_counter=? AND apple_counter_claim=? AND apple_key_id_b64=? AND apple_public_key_spki_b64=?
    AND apple_assertion_policy_json=?)`;
   const roleValues=[...guardValues,...claimValues,credential.id,native.operation_id,counter,claim,
    key.apple_key_id_b64,key.apple_public_key_spki_b64,key.apple_assertion_policy_json];
   const ack={contract_version:1,success:true,state:"enrolled",replayed:false,delegation_id:delegation.delegation_id,
    delegation_revision:1,key_thumbprint:keyHash,scope_digest:scope,expires_at_ms:delegation.policy.original_grant_expires_at_ms,
    enrol_operation_id:delegation.operation_id,install_credential_id:credential.id,native_operation_id:native.operation_id,
    native_api_installation_id:native.api_installation_id,native_registry_generation:native.registry_generation,
    enrolment_sha256:requestHash,publication_operation_id:publication,reauthorization_challenge_id:claimed.id};
   await window.run(()=>db.batch([
    db.prepare(`UPDATE native_installation_first_key SET apple_counter=?,apple_counter_claim=?
     WHERE credential_id=? AND operation_id=? AND typeof(apple_counter)='integer' AND apple_counter=? AND apple_key_id_b64=? AND apple_public_key_spki_b64=?
      AND apple_assertion_policy_json=? AND ${guardSQL} AND ${claimGuard}`)
     .bind(counter,claim,credential.id,native.operation_id,key.apple_counter,key.apple_key_id_b64,key.apple_public_key_spki_b64,
      key.apple_assertion_policy_json,...guardValues,...claimValues),
    db.prepare(`INSERT OR IGNORE INTO surface_push_delegations
     (id,revision,enrol_operation_id,approval_reference,install_id,device_binding,owner_binding,grant_binding,source_binding,
      binding_id,public_key_json,key_thumbprint,policy_json,scope_digest,expires_at,created_at,revoked_at)
     SELECT ?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL WHERE ${roleGuard}`)
     .bind(delegation.delegation_id,delegation.operation_id,delegation.approval_reference,delegation.install_id,
      delegation.device_binding,delegation.owner_binding,delegation.grant_binding,delegation.source_binding,delegation.binding_id,
      canonical(delegation.public_key),keyHash,canonical(delegation.policy),scope,delegation.policy.original_grant_expires_at_ms,
      Date.now(),...roleValues),
    db.prepare(`INSERT OR IGNORE INTO native_installation_surface_bindings
     (delegation_id,credential_id,credential_hash,ha_install_id,native_operation_id,publication_operation_id,native_receipt_json,
      pair_binding,consent_revision,enrolment_sha256,scope_digest,admission_kind)
     SELECT ?,?,?,?,?,?,?,?,?,?,?,'reauthorization' WHERE ${roleGuard}
     AND EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND enrol_operation_id=? AND scope_digest=? AND revoked_at IS NULL)`)
     .bind(delegation.delegation_id,credential.id,credential.token_hash,credential.ha_install_id,native.operation_id,publication,
      nativeJSON,originalPair,key.consent_revision,requestHash,scope,...roleValues,delegation.delegation_id,delegation.operation_id,scope),
    db.prepare(`UPDATE native_installation_role_challenges SET outcome='enrolled',ack_json=? WHERE id=? AND claim_id=?
     AND outcome='verifying' AND ${roleGuard} AND EXISTS(SELECT 1 FROM native_installation_live_delegations WHERE id=?
      AND scope_digest=? AND enrol_operation_id=?)`)
     .bind(canonical(ack),claimed!.id,claim,...roleValues,delegation.delegation_id,scope,delegation.operation_id),
   ]));
   const winner=await window.run(()=>db.prepare(`SELECT 1 FROM native_installation_role_challenges c
    JOIN native_installation_live_delegations d ON d.id=? WHERE c.id=? AND c.claim_id=? AND c.outcome='enrolled' AND c.ack_json=?`)
    .bind(delegation.delegation_id,claimed!.id,claim,canonical(ack)).first());
   need(winner&&live(),"native_role_reauthorization_unknown",409);
   return Response.json(ack,{headers});
  }catch(error){
   if(claimed) await env.DB.prepare("UPDATE native_installation_role_challenges SET outcome='unknown' WHERE id=? AND claim_id=? AND outcome='verifying'")
    .bind(claimed.id,claimed.claim_id).run();
   return Response.json({contract_version:1,success:false,error:error instanceof SurfaceError?error.code:"native_role_unavailable"},
    {status:error instanceof SurfaceError?error.status:503,headers});
  }finally{window?.close();}
 };
}
