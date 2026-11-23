import { env } from "cloudflare:test";
import { beforeAll, beforeEach, expect, it } from "vitest";
import credentials from "../migrations/0002_install_tokens.sql?raw";
import publisher from "../migrations/0014_native_installation_publisher.sql?raw";
import { issueInstallToken } from "../src/repositories/installTokens";
import { createInstallationPublisher, installationPrefix } from "../src/native-push/installation-publisher";
import { canonical } from "../src/surface-push/wire";
const origin = "https://api.djconnect.dev";
const db = env.DB;
let a: Awaited<ReturnType<typeof issueInstallToken>>, b: typeof a;
const handler = () => createInstallationPublisher(db, origin, () => true);
const publication = (credential = a) => ({ contract_version: 1, install_credential_id: credential.id,
 operation_id: "operation-1", pairing_generation: "pair-generation", pair_binding: "1".repeat(64),
 owner_binding: "2".repeat(64), device_binding: "3".repeat(64), core_key_thumbprint: "4".repeat(64),
 request_expires_at_ms: Date.now() + 60_000, consent_revision: 1 });
const request = (action: string, body: unknown, token = a.token) => new Request(origin + installationPrefix + action, {
 method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + token }, body: canonical(body),
});
beforeAll(async () => {
 for (const sql of (credentials + publisher).replace(/^--.*$/gm, "").split(";").map(s => s.trim()).filter(Boolean)) await db.prepare(sql).run();
});
beforeEach(async () => {
 for (const table of ["native_installation_pair_publications", "native_installation_consent_withdrawals",
 "native_installation_key_retirements", "native_installation_key_decisions", "native_installation_first_key", "install_tokens"])
  await db.prepare("DELETE FROM " + table).run();
 a = await issueInstallToken(db, { ha_install_id: "same-claimed-ha-id" });
 b = await issueInstallToken(db, { ha_install_id: "same-claimed-ha-id" });
});
it("resolves only an existing credential and creates no enrolled principal or key", async () => {
 const response = await handler()(request("resolve", { contract_version: 1 }));
 expect(response.status).toBe(200);
 expect(await response.json()).toEqual({ contract_version: 1, install_credential_id: a.id, ha_install_id: "same-claimed-ha-id" });
 for (const table of ["native_installation_pair_publications", "native_installation_first_key", "native_installation_key_decisions"])
  expect(await db.prepare("SELECT count(*) AS n FROM " + table).first("n")).toBe(0);
 expect((await handler()(request("resolve", { contract_version: 1, ha_install_id: "other" }))).status).toBe(400);
 expect((await handler()(request("resolve", { contract_version: 1 }, "djci_" + "A".repeat(43)))).status).toBe(401);
});
it("isolates two genuine credentials sharing a caller HA ID and pair hash", async () => {
 const first = publication(a), second = { ...first, install_credential_id: b.id };
 expect((await handler()(request("publisher/operation", first))).status).toBe(200);
 expect((await handler()(request("publisher/operation", second, b.token))).status).toBe(200);
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_pair_publications").first("n")).toBe(2);
 expect((await handler()(request("publisher/operation", first, b.token))).status).toBe(400);
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_first_key").first("n")).toBe(0);
});
it("retains own withdrawal without suppressing another credential's same pair", async () => {
 const first = publication(a), second = { ...first, install_credential_id: b.id };
 expect((await handler()(request("publisher/withdraw", { contract_version: 1, pair_binding: first.pair_binding, consent_revision: 2 }))).status).toBe(200);
 expect((await handler()(request("publisher/operation", first))).status).toBe(409);
 expect((await handler()(request("publisher/operation", second, b.token))).status).toBe(200);
 expect((await handler()(request("publisher/operation", { ...first, consent_revision: 3 }))).status).toBe(200);
});
it("replay preserves exact publication instead of replacing another pair or key", async () => {
 const first = publication();
 expect((await handler()(request("publisher/operation", first))).status).toBe(200);
 expect((await handler()(request("publisher/operation", first))).status).toBe(200);
 for (const changed of [{ pair_binding: "5".repeat(64) }, { owner_binding: "6".repeat(64) },
 { core_key_thumbprint: "7".repeat(64) }, { consent_revision: 2 }])
  expect((await handler()(request("publisher/operation", { ...first, ...changed }))).status).toBe(409);
});
it("revoked and rotated credentials cannot resolve or publish", async () => {
 await db.prepare("UPDATE install_tokens SET disabled=1 WHERE id=?").bind(a.id).run();
 for (const action of ["resolve", "publisher/operation", "publisher/withdraw"])
  expect((await handler()(request(action, action === "resolve" ? { contract_version: 1 } : publication()))).status).toBe(401);
 const newToken = await issueInstallToken(db, { ha_install_id: "same-claimed-ha-id" });
 expect((await handler()(request("publisher/operation", publication(), newToken.token))).status).toBe(400);
});
function afterAuthentication(effect: () => Promise<void>): D1Database {
 return { prepare(sql: string) {
  const statement = db.prepare(sql);
  return { bind(...args: unknown[]) {
   const bound = statement.bind(...args);
   return { async first() {
    const row = await bound.first();
    if (/SELECT \* FROM install_tokens/.test(sql)) await effect();
    return row;
   } };
  } };
 } } as unknown as D1Database;
}
it("same-statement original credential guards close rotation after authenticated await", async () => {
 const wrapped = afterAuthentication(async () => {
  await db.prepare("UPDATE install_tokens SET disabled=1 WHERE id=?").bind(a.id).run();
 });
 const dispatch = createInstallationPublisher(wrapped, origin, () => true);
 expect((await dispatch(request("publisher/operation", publication()))).status).toBe(409);
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_pair_publications").first("n")).toBe(0);
});
it("withdrawal committed during authenticated await closes the exact pending revision", async () => {
 const first = publication();
 const wrapped = afterAuthentication(async () => {
  expect((await handler()(request("publisher/withdraw", { contract_version: 1,
   pair_binding: first.pair_binding, consent_revision: first.consent_revision }))).status).toBe(200);
 });
 const dispatch = createInstallationPublisher(wrapped, origin, () => true);
 expect((await dispatch(request("publisher/operation", first))).status).toBe(409);
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_pair_publications").first("n")).toBe(0);
});
it("current owner retirement and noncanonical or foreign-origin input are closed", async () => {
 expect((await createInstallationPublisher(db, origin, () => false)(request("resolve", { contract_version: 1 }))).status).toBe(503);
 const spaced = new Request(origin + installationPrefix + "resolve", { method: "POST", headers: {
  "content-type": "application/json", authorization: "Bearer " + a.token }, body: '{ "contract_version":1}' });
 expect((await handler()(spaced)).status).toBe(400);
 const foreign = new Request("https://other.invalid" + installationPrefix + "resolve", request("resolve", { contract_version: 1 }));
 expect((await handler()(foreign)).status).toBe(404);
});

it("production native first trust uses selected signed policy and rejects malformed Apple proof without ACK", async () => {
 const { createInstallationFirstKey } = await import("../src/native-push/installation-first-key");
 const { installationNativePolicy } = await import("../src/native-push/installation-policy");
 const { installationFirstKeyAudience, firstKeyRegisterBytes } = await import("../src/native-push/first-key-wire");
 const { sha256Hex, base64Encode, base64Url } = await import("../src/crypto");
 const { vi } = await import("vitest");
 const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
 const spki = await crypto.subtle.exportKey("spki", key.publicKey) as ArrayBuffer;
 const published = { ...publication(), core_key_thumbprint: Array.from(
  new Uint8Array(await crypto.subtle.digest("SHA-256", spki)), value => value.toString(16).padStart(2, "0")).join("") };
 expect((await handler()(request("publisher/operation", published))).status).toBe(200);
 const original = { contract_version: 1 as const, operation_id: published.operation_id,
  pairing_generation: published.pairing_generation, pair_binding: published.pair_binding,
  owner_binding: published.owner_binding, device_binding: published.device_binding,
  core_key_thumbprint: published.core_key_thumbprint };
 const send = async (action: string, body: object, expiry: number | null) => {
  const now = Date.now();
  const currentness = { ...original, api_audience: installationFirstKeyAudience, action,
   decision_id: crypto.randomUUID(), install_credential_id: a.id,
   request_sha256: await sha256Hex(canonical(body)), issued_at_ms: now,
   expires_at_ms: Math.min(now + 9000, expiry ?? Infinity), operation_expires_at_ms: expiry };
  return new Request(origin + "/v1/push/native/key/" + action, { method: "POST", headers: {
   "content-type": "application/json", authorization: "Bearer " + a.token,
   "x-djc-first-key-currentness": canonical(currentness) }, body: canonical(body) });
 };
 const dispatch = createInstallationFirstKey(db, origin, () => true, installationNativePolicy);
 const challengeResponse = await dispatch(await send("challenge", original, null));
 expect(challengeResponse.status).toBe(200);
 const challenge = await challengeResponse.json() as import("../src/native-push/first-key-wire").FirstKeyChallenge;
 expect(challenge.api_audience).toBe(installationFirstKeyAudience);
 expect(challenge.install_credential_id).toBe(a.id);
 const transcript = firstKeyRegisterBytes(challenge, original, installationFirstKeyAudience);
 const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, transcript);
 const registration = { ...challenge, ...original, core_public_key_spki_b64: base64Encode(new Uint8Array(spki)),
  core_signature_b64url: base64Url(signature), apple_proof: { kind: "attestation",
   key_id_b64: base64Encode(new Uint8Array(32)), proof_b64: btoa("synthetic malformed Apple CBOR") } };
 const external = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("No external fixture calls"));
 try {
  const rejected = await dispatch(await send("register", registration, challenge.expires_at_ms));
  expect(rejected.status).toBe(403);
  // The register decision is claimed only AFTER genuine Core P256 verification;
  // this therefore reaches the real Apple verifier instead of a wrong key hash.
  expect(await db.prepare("SELECT count(*) AS n FROM native_installation_key_decisions").first("n")).toBe(2);
  expect(await db.prepare("SELECT count(*) AS n FROM native_installation_first_key WHERE receipt IS NOT NULL").first("n")).toBe(0);
  expect(external).not.toHaveBeenCalled();
  const noPolicy = createInstallationFirstKey(db, origin, () => true);
  expect((await noPolicy(await send("challenge", original, null))).status).toBe(503);
  expect(external).not.toHaveBeenCalled();
 } finally { external.mockRestore(); }
});

it("production retirement affects only its original credential even with identical pair and HA IDs", async () => {
 const { createInstallationFirstKey } = await import("../src/native-push/installation-first-key");
 const { installationNativePolicy } = await import("../src/native-push/installation-policy");
 const { installationFirstKeyAudience } = await import("../src/native-push/first-key-wire");
 const { sha256Hex } = await import("../src/crypto");
 const first = publication(), second = { ...first, install_credential_id: b.id };
 expect((await handler()(request("publisher/operation", first))).status).toBe(200);
 expect((await handler()(request("publisher/operation", second, b.token))).status).toBe(200);
 const dispatch = createInstallationFirstKey(db, origin, () => true, installationNativePolicy);
 const original = { contract_version: 1 as const, operation_id: first.operation_id, pairing_generation: first.pairing_generation,
  pair_binding: first.pair_binding, owner_binding: first.owner_binding, device_binding: first.device_binding,
  core_key_thumbprint: first.core_key_thumbprint };
 const event = { ...original, api_audience: installationFirstKeyAudience, event_id: original.operation_id,
  install_credential_id: a.id, request_expires_at_ms: first.request_expires_at_ms };
 const retirement = (token: string) => new Request(origin + "/v1/push/native/key/retire", { method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer " + token }, body: canonical(event) });
 expect((await dispatch(retirement(b.token))).status).toBe(403);
 expect((await dispatch(retirement(a.token))).status).toBe(200);
 expect(await db.prepare("SELECT credential_id FROM native_installation_key_retirements").all()).toMatchObject({ results: [{ credential_id: a.id }] });
 const challenge = async (credential: typeof a) => {
  const now = Date.now();
  return dispatch(new Request(origin + "/v1/push/native/key/challenge", { method: "POST", headers: {
   "content-type": "application/json", authorization: "Bearer " + credential.token,
   "x-djc-first-key-currentness": canonical({ ...original, api_audience: installationFirstKeyAudience, action: "challenge",
    decision_id: crypto.randomUUID(), install_credential_id: credential.id,
    request_sha256: await sha256Hex(canonical(original)), issued_at_ms: now, expires_at_ms: now + 9000,
    operation_expires_at_ms: null }) }, body: canonical(original) }));
 };
 expect((await challenge(a)).status).toBe(403);
 expect((await challenge(b)).status).toBe(200);
 expect(await db.prepare("SELECT count(*) AS n FROM native_installation_first_key WHERE receipt IS NOT NULL").first("n")).toBe(0);
});

it("shipping dispatcher mounts only authenticated own publication and preserves closed surface roles", async () => {
 const { default: worker } = await import("../src/index");
 const { createExecutionContext } = await import("cloudflare:test");
 const { vi } = await import("vitest");
 const external = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("No external fixture calls"));
 try {
  const ctx = createExecutionContext();
  const resolved = await worker.fetch(request("resolve", { contract_version: 1 }), env, ctx);
  expect(resolved.status).toBe(200);
  expect(await resolved.json()).toEqual({ contract_version: 1, install_credential_id: a.id, ha_install_id: "same-claimed-ha-id" });
  const native = new Request(origin + "/v1/push/native/key/challenge", { method: "POST",
   headers: { "content-type": "application/json" }, body: "{}" });
  expect((await worker.fetch(native, env, ctx)).status).toBe(401);
  expect((await worker.fetch(new Request(origin + "/v1/push/surface/status"), env, ctx)).status).toBe(503);
  expect(external).not.toHaveBeenCalled();
  expect(await db.prepare("SELECT count(*) AS n FROM native_installation_first_key WHERE receipt IS NOT NULL").first("n")).toBe(0);
 } finally { external.mockRestore(); }
});
