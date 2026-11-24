/** Real Worker/D1/P256 role tests. Native registered-key rows below are declared
 * synthetic storage-boundary fixtures, not Apple evidence or device admission. */
import cbor from "cbor";
import * as pki from "pkijs";
import { env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, expect, it, vi } from "vitest";
import m1 from "../migrations/0001_initial.sql?raw";
import m2 from "../migrations/0002_install_tokens.sql?raw";
import m3 from "../migrations/0003_encrypt_apns_tokens.sql?raw";
import m4 from "../migrations/0004_bootstrap_proofs.sql?raw";
import m5 from "../migrations/0005_install_token_revoke.sql?raw";
import m6 from "../migrations/0006_privacy_safe_diagnostics.sql?raw";
import m7 from "../migrations/0007_restrict_apns_push_contract.sql?raw";
import m8 from "../migrations/0008_restore_bootstrap_proof_metadata.sql?raw";
import m9 from "../migrations/0009_surface_push.sql?raw";
import m10 from "../migrations/0010_surface_delegations.sql?raw";
import m11 from "../migrations/0011_surface_enrollment_authorizations.sql?raw";
import m12 from "../migrations/0012_watch_lifecycle.sql?raw";
import m13 from "../migrations/0013_push_registration_erasure.sql?raw";
import m14 from "../migrations/0014_native_installation_publisher.sql?raw";
import m15 from "../migrations/0015_native_installation_surface_roles.sql?raw";
import m16 from "../migrations/0016_native_installation_apple_key.sql?raw";
import m17 from "../migrations/0017_native_installation_role_challenges.sql?raw";
import {createInstallationReauthorization,reauthorizationPrefix,reauthorizationSigningBytes} from "../src/native-push/installation-reauthorization";
import { issueInstallToken } from "../src/repositories/installTokens";
import { base64Encode, base64Url } from "../src/crypto";
import { canonical } from "../src/surface-push/wire";
import { ISSUER_PREFIX, signingBytes, type Enrolment, type Statement } from "../src/surface-push/issuer-wire";
import { createInstallationPublisher } from "../src/native-push/installation-publisher";
import { createInstallationSurfaceEnrol, installationEnrolPath, installationEnrolSigningBytes } from "../src/native-push/installation-surface-enrol";
import { createInstallationSurfaceService } from "../src/native-push/installation-surface-dispatch";
import { installationNativePolicy } from "../src/native-push/installation-policy";
import type { AppEnv } from "../src/types";

const db = env.DB, origin = "https://api.djconnect.dev";
const config = { ...env, APNS_ENVIRONMENT: "sandbox", APNS_PRIVATE_KEY: "", DJCONNECT_RELAY_SECRET: "fixture-not-operator",
 APNS_TOKEN_ENCRYPTION_KEY: btoa("0123456789abcdef0123456789abcdef") } as AppEnv;
let credential: Awaited<ReturnType<typeof issueInstallToken>>, other: typeof credential;
let key: CryptoKeyPair, receipt: Record<string, unknown>, declaration: Enrolment;
let original: Record<string, unknown>, spki: ArrayBuffer;
const op = () => {
 const time = Date.now().toString(16).padStart(12, "0");
 return `${time.slice(0, 8)}-${time.slice(8)}-7000-8000-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
};
const bytesHash = async (value: ArrayBuffer) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", value)),
 value => value.toString(16).padStart(2, "0")).join("");
const post = (path: string, body: unknown, bearer?: string) => new Request(origin + path, { method: "POST", headers: {
 "content-type": "application/json", ...(bearer ? { authorization: "Bearer " + bearer } : {}) }, body: canonical(body) });
async function enrolBody(value = declaration, native = receipt) {
 return { contract_version: 1, first_key_receipt: native, delegation: value,
  signature: base64Url(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey,
   installationEnrolSigningBytes(native, value))) };
}
async function enrolled() {
 const reply = await createInstallationSurfaceEnrol(config, () => true)(post(installationEnrolPath, await enrolBody(), credential.token));
 expect(reply.status).toBe(200);
 return await reply.json() as Record<string, unknown>;
}
async function signed(action: "challenge" | "issue" | "status" | "withdraw", extra: object = {}) {
 const payload = { contract_version: 1, purpose: "surface_push", action, operation_id: op(), delegation_id: declaration.delegation_id,
  delegation_revision: 1, key_thumbprint: (await enrolledHash()), ...extra } as Statement;
 return post(ISSUER_PREFIX + action, { payload, signature: base64Url(await crypto.subtle.sign(
  { name: "ECDSA", hash: "SHA-256" }, key.privateKey, signingBytes(ISSUER_PREFIX + action, payload))) });
}
async function enrolledHash() {
 const { thumbprint } = await import("../src/surface-push/issuer-wire");
 return thumbprint(declaration.public_key);
}
async function issued(service: ReturnType<typeof createInstallationSurfaceService>) {
 await enrolled();
 const challengeRequest = await signed("challenge");
 const original = (await challengeRequest.clone().json() as { payload: Statement }).payload;
 const response = await service(challengeRequest);
 const challenge = await response.json() as {challenge_id: string; nonce: string; scope_digest: string};
 expect(response.status).toBe(200);
 const issue = { ...original, action: "issue", challenge_id: challenge.challenge_id,
  nonce: challenge.nonce, scope_digest: challenge.scope_digest } as Statement;
 const result = await service(post(ISSUER_PREFIX + "issue", { payload: issue, signature: base64Url(
  await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, signingBytes(ISSUER_PREFIX + "issue", issue))) }));
 const body = await result.json() as {credential: string};
 expect(result.status).toBe(200);
 expect(body.credential).toMatch(/^djcs_/);
 return body.credential;
}
function registration() {
 return { contract_version: 1, registration_id: "native-widget", generation: "original-widget-generation", revision: 1,
  operation_id: op(), binding_id: declaration.binding_id, device_binding: declaration.device_binding,
  owner_binding: declaration.owner_binding, expires_at_ms: declaration.policy.original_grant_expires_at_ms,
  token_role: "widget", platform: "ios", apns_environment: "sandbox",
  target: { ...declaration.policy.target, instance_id: "native-widget-instance" }, apns_token: "01".repeat(32) };
}
function coordinate(value: ReturnType<typeof registration>) {
 const { contract_version, registration_id, generation, revision, binding_id, device_binding, owner_binding } = value;
 return { contract_version, registration_id, generation, revision, binding_id, device_binding, owner_binding, operation_id: op() };
}
beforeAll(async () => {
 for (const schema of [m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17]) {
  const triggers = schema.match(/CREATE TRIGGER[\s\S]*?END;/g) ?? [];
  const plain = schema.replace(/CREATE TRIGGER[\s\S]*?END;/g, "").replace(/^--.*$/gm, "");
  for (const sql of plain.split(";").map(s => s.trim()).filter(Boolean)) await db.prepare(sql).run();
  for (const sql of triggers) await db.prepare(sql).run();
 }
 const provider = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign","verify"]) as CryptoKeyPair;
 const pem = base64Encode(new Uint8Array(await crypto.subtle.exportKey("pkcs8", provider.privateKey)));
 config.APNS_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" + pem + "\n-----END PRIVATE KEY-----";
 config.APNS_TEAM_ID = "TEAM123456";
 config.APNS_KEY_ID = "KEY1234567";
});
afterEach(() => vi.restoreAllMocks());
beforeEach(async () => {
 for (const table of ["native_installation_role_challenges","native_installation_surface_bindings","surface_push_targets","surface_push_operations",
 "surface_push_issuer_operations","surface_push_capabilities","surface_push_delegations","surface_push_operator_operations",
 "native_installation_first_key","native_installation_pair_publications","native_installation_consent_withdrawals",
 "native_installation_key_retirements","native_installation_key_decisions","install_tokens"]) await db.prepare("DELETE FROM " + table).run();
 credential = await issueInstallToken(db, { ha_install_id: "same-ha-fixture" });
 other = await issueInstallToken(db, { ha_install_id: "same-ha-fixture" });
 key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign","verify"]) as CryptoKeyPair;
 spki = await crypto.subtle.exportKey("spki", key.publicKey) as ArrayBuffer;
 const pub = { contract_version: 1, install_credential_id: credential.id, operation_id: "synthetic-native-operation",
  pairing_generation: "native-generation", pair_binding: "1".repeat(64), owner_binding: "2".repeat(64),
  device_binding: "3".repeat(64), core_key_thumbprint: await bytesHash(spki),
  request_expires_at_ms: Date.now() + 60_000, consent_revision: 1 };
 expect((await createInstallationPublisher(db, origin, () => true)(post("/v1/push/native/installation/publisher/operation", pub, credential.token))).status).toBe(200);
 original = Object.fromEntries(["contract_version","operation_id","pairing_generation","pair_binding","owner_binding","device_binding","core_key_thumbprint"].map(k => [k, pub[k as keyof typeof pub]]));
 receipt = { contract_version: 1, operation_id: pub.operation_id, api_installation_id: "synthetic-native-installation",
  install_credential_id: credential.id, pairing_generation: pub.pairing_generation, registry_generation: "synthetic-native-registry",
  key_revision: 1, core_key_thumbprint: pub.core_key_thumbprint, transcript_sha256: "4".repeat(64),
  expires_at_ms: pub.request_expires_at_ms, state: "registered" };
 // Explicit synthetic enrolled-native storage boundary. No fixture is used as
 // an actual first-key/verifier/provider/SDK qualification outside this worker.
 await db.prepare(`INSERT INTO native_installation_first_key
  (credential_id,operation_id,installation_id,policy_id,pair_binding,original_request,challenge,expires_at_ms,
   key_spki,transcript_sha256,receipt) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(credential.id, pub.operation_id,
  receipt.api_installation_id, installationNativePolicy.id, pub.pair_binding, canonical(original), "{}", pub.request_expires_at_ms,
  base64Encode(new Uint8Array(spki)), receipt.transcript_sha256, canonical(receipt)).run();
 // Explicit synthetic saved-verifier metadata for the initial-role boundary.
 await db.prepare(`UPDATE native_installation_first_key SET apple_key_id_b64=?,apple_public_key_spki_b64=?,
  apple_assertion_policy_json=?,apple_counter=0,apple_evidence_expires_at_ms=?,apple_status_expires_at_ms=?`)
  .bind(base64Encode(new Uint8Array(32)),base64Encode(new Uint8Array(spki)),
   canonical({profile:"host_wake_apple_assertion_properties_v2",app_identifier:installationNativePolicy.apple.app_identifier,
    bundle_version:installationNativePolicy.apple.bundle_version,launch_validation_category_b64:"AwAAAA=="}),
   Date.now()+240000,Date.now()+240000).run();
 const jwk = await crypto.subtle.exportKey("jwk", key.publicKey) as JsonWebKey;
 declaration = { contract_version: 1, purpose: "surface_push", action: "enrol", operation_id: op(),
  delegation_id: "fixture-delegation", expected_revision: 0, approval_reference: String(receipt.registry_generation),
  install_id: String(receipt.api_installation_id), device_binding: "5".repeat(64), owner_binding: "6".repeat(64),
  grant_binding: "7".repeat(64), source_binding: "8".repeat(64), binding_id: "9".repeat(64),
  public_key: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, policy: {
   token_role: "widget", platform: "ios", apns_environment: "sandbox", target: { app_bundle_id: "dev.djconnect.ios",
    extension_bundle_id: "dev.djconnect.ios.track-insight-widget", widget_kind: "DJConnectSessionWidget" },
   activity_profile: null, external_content_allowed: false, original_grant_expires_at_ms: Date.now() + 180_000,
   max_operations: 10, max_events: 5, max_challenges: 4 } };
});
it("binds a real P256 signed role acknowledgement to exact original native/policy fields and forbids replay transfer", async () => {
 const ack = await enrolled();
 expect(ack).toMatchObject({ contract_version: 1, success: true, state: "enrolled", replayed: false,
  delegation_id: declaration.delegation_id, enrol_operation_id: declaration.operation_id,
  install_credential_id: credential.id, native_operation_id: receipt.operation_id,
  native_api_installation_id: receipt.api_installation_id, native_registry_generation: receipt.registry_generation,
  expires_at_ms: declaration.policy.original_grant_expires_at_ms });
 expect(ack.enrolment_sha256).toBe(await bytesHash(installationEnrolSigningBytes(receipt, declaration).buffer));
 expect((await createInstallationSurfaceEnrol(config, () => true)(post(installationEnrolPath,
  await enrolBody(), credential.token))).status).toBe(202);
});
it("does not equate first-key SPKI digest with Surface key/pair binding dialects", async () => {
 const ack = await enrolled();
 expect(ack.key_thumbprint).not.toBe(receipt.core_key_thumbprint);
 expect(declaration.device_binding).not.toBe(original.device_binding);
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_live_delegations").first("n")).toBe(1);
});
it("one actual native first-key winner cannot multiply initial role grants with new operation/delegation IDs", async () => {
 await enrolled();
 const extra = {...declaration, operation_id: op(), delegation_id: "second-initial-role"};
 expect((await createInstallationSurfaceEnrol(config, () => true)(post(installationEnrolPath,
  await enrolBody(extra), credential.token))).status).toBe(409);
 expect(await db.prepare("SELECT count(*) FROM native_installation_surface_bindings").first("count(*)")).toBe(1);
 expect(await db.prepare("SELECT count(*) FROM surface_push_delegations").first("count(*)")).toBe(1);
 expect(await db.prepare("SELECT count(*) FROM surface_push_capabilities").first("count(*)")).toBe(0);
});
it("rejects another credential with the same HA ID, modified receipt, wrong signature and substituted native target", async () => {
 const handler = createInstallationSurfaceEnrol(config, () => true);
 expect((await handler(post(installationEnrolPath, await enrolBody(), other.token))).status).toBe(403);
 expect((await handler(post(installationEnrolPath, await enrolBody(declaration, { ...receipt, registry_generation: "forged" }), credential.token))).status).toBe(403);
 const body = await enrolBody(); body.signature = "A".repeat(86);
 expect((await handler(post(installationEnrolPath, body, credential.token))).status).toBe(403);
 const wrong = { ...declaration, policy: { ...declaration.policy,
  target: { ...declaration.policy.target, widget_kind: "OtherKind" } } };
 expect((await handler(post(installationEnrolPath, await enrolBody(wrong), credential.token))).status).toBe(403);
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_surface_bindings").first("n")).toBe(0);
});
it("distinguishes initial native challenge expiry from the genuinely acknowledged original role expiry", async () => {
 await enrolled();
 await db.prepare("UPDATE native_installation_first_key SET expires_at_ms=1 WHERE credential_id=?").bind(credential.id).run();
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_live_delegations").first("n")).toBe(1);
 const fresh = { ...declaration, operation_id: op(), delegation_id: "cannot-new-enrol-from-expired-first-win" };
 expect((await createInstallationSurfaceEnrol(config, () => true)(post(installationEnrolPath,
  await enrolBody(fresh), credential.token))).status).toBe(403);
});
it("credential revocation closes issued native role provenance and preserves scoped negative issuer management", async () => {
 await enrolled();
 const service = createInstallationSurfaceService({ env: config });
 expect((await service(await signed("challenge"))).status).toBe(200);
 await db.prepare("UPDATE install_tokens SET disabled=1 WHERE id=?").bind(credential.id).run();
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_live_delegations").first("n")).toBe(0);
 expect((await service(await signed("challenge"))).status).toBe(403);
 expect((await service(await signed("withdraw"))).status).toBe(200);
});
it("composes native role, purpose credential, encrypted widget registration and content-free provider send", async () => {
 const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, {status: 200}));
 const service = createInstallationSurfaceService({env: config, fetcher});
 const bearer = await issued(service), value = registration();
 expect((await service(post("/v1/push/surface/register", value, bearer))).status).toBe(200);
 const target = await db.prepare("SELECT ciphertext,nonce FROM surface_push_targets").first<Record<string, unknown>>();
 expect(target?.ciphertext).toBeTypeOf("string");
 expect(JSON.stringify(target)).not.toContain(value.apns_token);
 expect((await service(post("/v1/push/surface/event", {...coordinate(value), event: "widget_reload"}, bearer))).status).toBe(200);
 expect(fetcher).toHaveBeenCalledTimes(1);
 const [, init] = fetcher.mock.calls[0]!;
 expect(init?.headers).toMatchObject({"apns-topic": "dev.djconnect.ios.push-type.widgets", "apns-push-type": "widgets"});
 expect(JSON.parse(String(init?.body))).toEqual({aps: {"content-changed": true}});
});
it.each(["withdraw", "retire", "rotate"])("actual %s provenance closes an already issued credential and scrubs its token", async closure => {
 const fetcher = vi.fn<typeof fetch>();
 const service = createInstallationSurfaceService({env: config, fetcher});
 const bearer = await issued(service), value = registration();
 expect((await service(post("/v1/push/surface/register", value, bearer))).status).toBe(200);
 if (closure === "withdraw") {
  expect((await createInstallationPublisher(db, origin, () => true)(post("/v1/push/native/installation/publisher/withdraw",
   {contract_version: 1, pair_binding: original.pair_binding, consent_revision: 1}, credential.token))).status).toBe(200);
 } else if (closure === "retire") {
  const {createInstallationFirstKey} = await import("../src/native-push/installation-first-key");
  const event = {...original, install_credential_id: credential.id, request_expires_at_ms: receipt.expires_at_ms,
   api_audience: "djc-native-push/1", event_id: receipt.operation_id};
  expect((await createInstallationFirstKey(db, origin, () => true, installationNativePolicy)(
   post("/v1/push/native/key/retire", event, credential.token))).status).toBe(200);
 } else await db.prepare("UPDATE install_tokens SET token_hash=? WHERE id=?").bind("a".repeat(64), credential.id).run();
 expect((await service(post("/v1/push/surface/event", {...coordinate(value), event: "widget_reload"}, bearer))).status).toBe(403);
 expect(fetcher).not.toHaveBeenCalled();
 expect(await db.prepare("SELECT ciphertext FROM surface_push_targets").first("ciphertext")).toBeNull();
 expect((await service(post("/v1/push/surface/revoke", coordinate(value), bearer))).status).toBe(200);
});
it("credential rotation during provider authorization prevents the actual outbound call", async () => {
 const fetcher = vi.fn<typeof fetch>();
 const service = createInstallationSurfaceService({env: config, fetcher});
 const bearer = await issued(service), value = registration();
 expect((await service(post("/v1/push/surface/register", value, bearer))).status).toBe(200);
 const originalSign = crypto.subtle.sign.bind(crypto.subtle);
 vi.spyOn(crypto.subtle, "sign").mockImplementation(async (...args) => {
  await db.prepare("UPDATE install_tokens SET disabled=1 WHERE id=?").bind(credential.id).run();
  return originalSign(...args);
 });
 const result = await service(post("/v1/push/surface/event", {...coordinate(value), event: "widget_reload"}, bearer));
 expect(result.status).toBeGreaterThanOrEqual(400);
 expect(fetcher).not.toHaveBeenCalled();
 expect(await db.prepare("SELECT outcome FROM surface_push_operations WHERE kind='event'").first("outcome")).toBe("not_sent");
});
it("a Surface delegation without native provenance cannot fall back to operator or install bearer admission", async () => {
 await enrolled();
 await db.prepare("DELETE FROM native_installation_surface_bindings").run();
 const service = createInstallationSurfaceService({env: config});
 expect((await service(await signed("challenge"))).status).toBe(403);
 expect((await service(post("/v1/push/surface/register", registration(), credential.token))).status).toBe(401);
 expect(await db.prepare("SELECT count(*) FROM surface_push_capabilities").first("count(*)")).toBe(0);
});
it("credential withdrawal during native role signature verification cannot publish a winning ACK", async () => {
 const body = await enrolBody();
 const verify = crypto.subtle.verify.bind(crypto.subtle);
 vi.spyOn(crypto.subtle, "verify").mockImplementation(async (...args) => {
  await db.prepare("UPDATE install_tokens SET disabled=1 WHERE id=?").bind(credential.id).run();
  return verify(...args);
 });
 const result = await createInstallationSurfaceEnrol(config, () => true)(post(installationEnrolPath, body, credential.token));
 expect(result.status).toBeGreaterThanOrEqual(400);
 expect(await db.prepare("SELECT count(*) FROM native_installation_surface_bindings").first("count(*)")).toBe(0);
 expect(await db.prepare("SELECT count(*) FROM native_installation_live_delegations").first("count(*)")).toBe(0);
});

async function reauthorizationPrepared() {
 await enrolled();
 const apple = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair;
 const applePoint = await crypto.subtle.exportKey("raw",apple.publicKey);
 const appleID = base64Encode(new Uint8Array(await crypto.subtle.digest("SHA-256",applePoint)));
 // Explicit synthetic saved-verifier metadata boundary. This test produces
 // actual ECDSA assertions and SQL counters, never actual Apple enrollment.
 await db.prepare(`UPDATE native_installation_first_key SET apple_key_id_b64=?,apple_public_key_spki_b64=?,
  apple_assertion_policy_json=?,apple_counter=0,apple_evidence_expires_at_ms=?,apple_status_expires_at_ms=?`)
  .bind(appleID,base64Encode(new Uint8Array(await crypto.subtle.exportKey("spki",apple.publicKey))),
   canonical({profile:"host_wake_apple_assertion_properties_v2",app_identifier:installationNativePolicy.apple.app_identifier,
    bundle_version:installationNativePolicy.apple.bundle_version,launch_validation_category_b64:"AwAAAA=="}),
   Date.now()+240000,Date.now()+240000).run();
 const publisher=createInstallationPublisher(db,origin,()=>true);
 expect((await publisher(post("/v1/push/native/installation/publisher/withdraw",
  {contract_version:1,pair_binding:original.pair_binding,consent_revision:2},credential.token))).status).toBe(200);
 const publication={...original,install_credential_id:credential.id,operation_id:"new-consent-original",
  request_expires_at_ms:Date.now()+120000,consent_revision:3};
 expect((await publisher(post("/v1/push/native/installation/publisher/operation",publication,credential.token))).status).toBe(200);
 const next={...declaration,operation_id:op(),delegation_id:"reauthorized-widget-role"};
 const signature=base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key.privateKey,
  reauthorizationSigningBytes("challenge",receipt,publication.operation_id,next)));
 const handler=createInstallationReauthorization(config,()=>true);
 const challengeResponse=await handler(post(reauthorizationPrefix+"challenge",{contract_version:1,first_key_receipt:receipt,
  publication_operation_id:publication.operation_id,delegation:next,signature},credential.token));
 const challenge=await challengeResponse.json() as Record<string,unknown>;
 expect(challengeResponse.status,JSON.stringify(challenge)).toBe(200);
 async function assertion(counter=1,selectedChallenge=challenge,selectedDelegation=next) {
  const props=cbor.encode(new Map<string,unknown>([["apple_bundle_version_01",installationNativePolicy.apple.bundle_version],
   ["apple_validation_category_01",Buffer.from([3,0,0,0])]]));
  const auth=new Uint8Array(37+props.length);
  auth.set(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(installationNativePolicy.apple.app_identifier))));
  auth[32]=0xc0;new DataView(auth.buffer).setUint32(33,counter,false);auth.set(props,37);
  const clientHash=new Uint8Array(await crypto.subtle.digest("SHA-256",reauthorizationSigningBytes("register",receipt,selectedChallenge,selectedDelegation)));
  const combined=new Uint8Array(auth.length+clientHash.length);combined.set(auth);combined.set(clientHash,auth.length);
  const nonce=await crypto.subtle.digest("SHA-256",combined);
  const raw=await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},apple.privateKey,nonce);
  const proof=base64Encode(new Uint8Array(cbor.encode(new Map([["signature",Buffer.from(pki.createCMSECDSASignature(raw))],
   ["authenticatorData",Buffer.from(auth)]]))));
  return {contract_version:1,challenge:selectedChallenge,first_key_receipt:receipt,delegation:selectedDelegation,
   apple_proof:{kind:"assertion",key_id_b64:appleID,proof_b64:proof}};
 }
 return {handler,challenge,next,assertion,publication};
}
it("ON/OFF/ON uses one real saved-key signature and counter CAS for a separate role without reopening first trust",async()=>{
 const x=await reauthorizationPrepared(),body=await x.assertion();
 const response=await x.handler(post(reauthorizationPrefix+"register",body,credential.token));
 const ack=await response.json();
 expect(response.status,JSON.stringify(ack)).toBe(200);
 expect(ack).toMatchObject({success:true,replayed:false,native_operation_id:receipt.operation_id,
  publication_operation_id:x.publication.operation_id,reauthorization_challenge_id:x.challenge.challenge_id,
  delegation_id:x.next.delegation_id});
 expect((ack as {enrolment_sha256:string}).enrolment_sha256).toBe(await bytesHash(
  reauthorizationSigningBytes("challenge",receipt,x.publication.operation_id,x.next).buffer));
 expect(await db.prepare("SELECT count(*) FROM native_installation_first_key").first("count(*)")).toBe(1);
 expect(await db.prepare("SELECT apple_counter FROM native_installation_first_key").first("apple_counter")).toBe(1);
 expect(await db.prepare("SELECT count(*) FROM native_installation_live_delegations").first("count(*)")).toBe(1);
 expect(await db.prepare("SELECT revoked_at FROM surface_push_delegations WHERE id=?").bind(declaration.delegation_id).first("revoked_at")).not.toBeNull();
 expect((await x.handler(post(reauthorizationPrefix+"register",body,credential.token))).status).toBe(409);
 const fetcher=vi.fn<typeof fetch>().mockResolvedValue(new Response(null,{status:200}));
 const service=createInstallationSurfaceService({env:config,fetcher});
 const challengeRequest=await signed("challenge",{delegation_id:x.next.delegation_id});
 const payload=(await challengeRequest.clone().json() as {payload:Statement}).payload;
 const issuedChallenge=await service(challengeRequest);
 expect(issuedChallenge.status).toBe(200);
 const c=await issuedChallenge.json() as {challenge_id:string;nonce:string;scope_digest:string};
 const statement={...payload,action:"issue",challenge_id:c.challenge_id,nonce:c.nonce,scope_digest:c.scope_digest} as Statement;
 const purpose=await service(post(ISSUER_PREFIX+"issue",{payload:statement,signature:base64Url(await crypto.subtle.sign(
  {name:"ECDSA",hash:"SHA-256"},key.privateKey,signingBytes(ISSUER_PREFIX+"issue",statement)))}));
 expect(purpose.status).toBe(200);
 const {credential:bearer}=await purpose.json() as {credential:string},value=registration();
 expect((await service(post("/v1/push/surface/register",value,bearer))).status).toBe(200);
 expect((await service(post("/v1/push/surface/event",{...coordinate(value),event:"widget_reload"},bearer))).status).toBe(200);
 expect(fetcher).toHaveBeenCalledTimes(1);
});
it.each(["withdraw","rotate","retire"])("reauthorization cannot win after actual %s during assertion verification",async closure=>{
 const x=await reauthorizationPrepared(),body=await x.assertion();
 const verify=crypto.subtle.verify.bind(crypto.subtle);
 vi.spyOn(crypto.subtle,"verify").mockImplementation(async(...args)=>{
  if(closure==="withdraw") await createInstallationPublisher(db,origin,()=>true)(post("/v1/push/native/installation/publisher/withdraw",
   {contract_version:1,pair_binding:original.pair_binding,consent_revision:4},credential.token));
  else if(closure==="rotate") await db.prepare("UPDATE install_tokens SET disabled=1 WHERE id=?").bind(credential.id).run();
  else await db.prepare("INSERT INTO native_installation_key_retirements(credential_id,pair_binding) VALUES(?,?)")
   .bind(credential.id,original.pair_binding).run(); // Explicit same storage-boundary retired-pair fixture.
  return verify(...args);
 });
 const result=await x.handler(post(reauthorizationPrefix+"register",body,credential.token));
 expect(result.status).toBeGreaterThanOrEqual(400);
 expect(await db.prepare("SELECT count(*) FROM native_installation_live_delegations").first("count(*)")).toBe(0);
 expect(await db.prepare("SELECT apple_counter FROM native_installation_first_key").first("apple_counter")).toBe(0);
 expect(await db.prepare("SELECT outcome FROM native_installation_role_challenges").first("outcome")).toBe("unknown");
});
it("stale assertion counters consume no native key and never reopen their claimed role challenge",async()=>{
 const x=await reauthorizationPrepared();
 expect((await x.handler(post(reauthorizationPrefix+"register",await x.assertion(0),credential.token))).status).toBe(403);
 expect((await x.handler(post(reauthorizationPrefix+"register",await x.assertion(1),credential.token))).status).toBe(409);
 expect(await db.prepare("SELECT apple_counter FROM native_installation_first_key").first("apple_counter")).toBe(0);
});
it("an original receipt without actual saved verifier metadata cannot reauthorize",async()=>{
 const x=await reauthorizationPrepared();
 await db.prepare("UPDATE native_installation_first_key SET apple_key_id_b64=NULL").run();
 expect((await x.handler(post(reauthorizationPrefix+"register",await x.assertion(),credential.token))).status).toBe(403);
 expect(await db.prepare("SELECT apple_counter FROM native_installation_first_key").first("apple_counter")).toBe(0);
});
it("two distinct actual role challenges sharing one native key serialize at its global actual counter CAS",async()=>{
 const x=await reauthorizationPrepared();
 const publication={...x.publication,operation_id:"second-consent-original",consent_revision:4};
 expect((await createInstallationPublisher(db,origin,()=>true)(post("/v1/push/native/installation/publisher/operation",publication,credential.token))).status).toBe(200);
 const next={...x.next,operation_id:op(),delegation_id:"competing-reauthorization"};
 const signature=base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key.privateKey,
  reauthorizationSigningBytes("challenge",receipt,publication.operation_id,next)));
 const response=await x.handler(post(reauthorizationPrefix+"challenge",{contract_version:1,first_key_receipt:receipt,
  publication_operation_id:publication.operation_id,delegation:next,signature},credential.token));
 expect(response.status).toBe(200);
 const challenge=await response.json() as Record<string,unknown>;
 const one=await x.assertion(1),two=await x.assertion(1,challenge,next);
 const results=await Promise.all([x.handler(post(reauthorizationPrefix+"register",one,credential.token)),
  x.handler(post(reauthorizationPrefix+"register",two,credential.token))]);
 expect(results.map(result=>result.status).sort()).toEqual([200,409]);
 expect(await db.prepare("SELECT apple_counter FROM native_installation_first_key").first("apple_counter")).toBe(1);
 expect(await db.prepare("SELECT count(*) FROM native_installation_surface_bindings WHERE admission_kind='reauthorization'").first("count(*)")).toBe(1);
});
it("another genuine credential sharing an HA ID cannot consume or authorize the original native challenge",async()=>{
 const x=await reauthorizationPrepared(),body=await x.assertion();
 expect((await x.handler(post(reauthorizationPrefix+"register",body,other.token))).status).toBe(403);
 expect(await db.prepare("SELECT outcome FROM native_installation_role_challenges").first("outcome")).toBe("pending");
 expect((await x.handler(post(reauthorizationPrefix+"register",body,credential.token))).status).toBe(200);
});
it("a changed original declaration cannot consume the saved role challenge or substitute its target",async()=>{
 const x=await reauthorizationPrepared(),body=await x.assertion();
 const forged={...body,delegation:{...body.delegation,source_binding:"a".repeat(64)}};
 expect((await x.handler(post(reauthorizationPrefix+"register",forged,credential.token))).status).toBe(409);
 expect(await db.prepare("SELECT outcome FROM native_installation_role_challenges").first("outcome")).toBe("pending");
 expect((await x.handler(post(reauthorizationPrefix+"register",body,credential.token))).status).toBe(200);
});
it("initial role cannot promote an old receipt missing genuine native metadata or overrun its actual evidence deadline",async()=>{
 await db.prepare("UPDATE native_installation_first_key SET apple_status_expires_at_ms=?").bind(Date.now()+30000).run();
 expect((await createInstallationSurfaceEnrol(config,()=>true)(post(installationEnrolPath,await enrolBody(),credential.token))).status).toBe(403);
 await db.prepare("UPDATE native_installation_first_key SET apple_status_expires_at_ms=?,apple_key_id_b64=NULL").bind(Date.now()+240000).run();
 expect((await createInstallationSurfaceEnrol(config,()=>true)(post(installationEnrolPath,await enrolBody(),credential.token))).status).toBe(403);
 expect(await db.prepare("SELECT count(*) FROM native_installation_surface_bindings").first("count(*)")).toBe(0);
});
it.each([0.5,-1,4294967296,"invalid-counter"])("corrupt saved counter %s remains unavailable and is never normalized by a genuine assertion",async corrupted=>{
 const x=await reauthorizationPrepared(),body=await x.assertion(1);
 await db.prepare("UPDATE native_installation_first_key SET apple_counter=?").bind(corrupted).run();
 expect((await x.handler(post(reauthorizationPrefix+"register",body,credential.token))).status).toBeGreaterThanOrEqual(400);
 expect(await db.prepare("SELECT apple_counter FROM native_installation_first_key").first("apple_counter")).toBe(corrupted);
 expect(await db.prepare("SELECT count(*) FROM native_installation_surface_bindings WHERE admission_kind='reauthorization'").first("count(*)")).toBe(0);
});
