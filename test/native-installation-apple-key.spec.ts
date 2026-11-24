/** Actual P256 and D1 rejection tests. No fixture is an Apple verifier witness. */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, expect, it, vi } from "vitest";
import credentials from "../migrations/0002_install_tokens.sql?raw";
import native from "../migrations/0014_native_installation_publisher.sql?raw";
import apple from "../migrations/0016_native_installation_apple_key.sql?raw";
import { issueInstallToken } from "../src/repositories/installTokens";
import { base64Encode, base64Url } from "../src/crypto";
import { canonical } from "../src/surface-push/wire";
import { consumeFirstKeyApple, type VerifiedFirstKeyApple } from "../src/native-push/first-key-apple";
import { createWidgetFirstKeyHandler } from "../src/native-push/first-key-service";
import { firstKeyRegisterBytes, installationFirstKeyAudience, type FirstKeyChallenge } from "../src/native-push/first-key-wire";
const db = env.DB, origin = "https://api.djconnect.dev", prefix = "/v1/push/native/key/";
beforeAll(async () => {
 for (const sql of (credentials + native + apple).replace(/^--.*$/gm, "").split(";").map(s => s.trim()).filter(Boolean))
  await db.prepare(sql).run();
});
beforeEach(async () => {
 for (const table of ["native_installation_first_key", "native_installation_key_retirements", "install_tokens"])
  await db.prepare("DELETE FROM " + table).run();
});
it.each([true, {kind: "native_first_key_apple_crypto_only"}])("a positive model verifier value %j cannot populate a genuine production Apple key or ACK", async model => {
 const credential = await issueInstallToken(db, {ha_install_id: "synthetic-rejection-owner"});
 const key = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign","verify"]) as CryptoKeyPair;
 const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
 const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)), value => value.toString(16).padStart(2,"0")).join("");
 const original = {contract_version: 1 as const, operation_id: "synthetic-operation", pairing_generation: "original-generation",
  pair_binding: "1".repeat(64), owner_binding: "2".repeat(64), device_binding: "3".repeat(64), core_key_thumbprint: digest};
 const verifyApple = vi.fn(async () => model as boolean | VerifiedFirstKeyApple);
 // Explicit trusted-policy model only proves the production writer still
 // rejects its affirmative boolean/object after actual Core P256 verification.
 const handler = createWidgetFirstKeyHandler(db, origin, () => true, {
  id: "model-policy", expiresAt: Date.now()+120_000, isCurrent: () => true,
  isPairCurrent: async () => true, verifyApple,
 }, undefined, "installation");
 const request = (path: string, body: unknown) => new Request(origin+prefix+path, {method: "POST", headers: {
  "content-type": "application/json", authorization: "Bearer "+credential.token}, body: canonical(body)});
 const challengeResponse = await handler(request("challenge", original));
 expect(challengeResponse.status).toBe(200);
 const challenge = await challengeResponse.json() as FirstKeyChallenge;
 expect(challenge.api_audience).toBe(installationFirstKeyAudience);
 const transcript = firstKeyRegisterBytes(challenge, original, installationFirstKeyAudience);
 const input = {...original, ...challenge, core_public_key_spki_b64: base64Encode(spki),
  core_signature_b64url: base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"}, key.privateKey, transcript)),
  apple_proof: {kind:"attestation",key_id_b64:btoa("0".repeat(32)),proof_b64:"AA=="}};
 expect((await handler(request("register", input))).status).toBe(403);
 expect(verifyApple).toHaveBeenCalledOnce();
 const row = await db.prepare("SELECT receipt,apple_key_id_b64,apple_public_key_spki_b64,apple_counter FROM native_installation_first_key")
  .first<Record<string,unknown>>();
 expect(row).toEqual({receipt:null,apple_key_id_b64:null,apple_public_key_spki_b64:null,apple_counter:null});
});
it("JSON, copies, booleans and malformed objects cannot reconstruct original verifier custody", () => {
 for (const value of [true,false,null,{}, {kind:"native_first_key_apple_crypto_only"}, Object.freeze({kind:"native_first_key_apple_crypto_only"})])
  expect(consumeFirstKeyApple(value, new Uint8Array([1]), btoa("0".repeat(32)))).toBeNull();
});
