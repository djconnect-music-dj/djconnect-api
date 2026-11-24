/** MODEL APPLE-KERNEL BOUNDARY ONLY. Actual Core P256/D1 and production receipt
 * writer execute; synthetic kernel results never qualify Apple/native/device
 * acceptance. No witness constructor or positive production override is added. */
import {env} from "cloudflare:test";
import {beforeAll,beforeEach,expect,it,vi} from "vitest";
import credentials from "../migrations/0002_install_tokens.sql?raw";
import surface from "../migrations/0009_surface_push.sql?raw";
import delegations from "../migrations/0010_surface_delegations.sql?raw";
import native from "../migrations/0014_native_installation_publisher.sql?raw";
import roles from "../migrations/0015_native_installation_surface_roles.sql?raw";
import apple from "../migrations/0016_native_installation_apple_key.sql?raw";
import {issueInstallToken} from "../src/repositories/installTokens";
import {base64Encode,base64Url} from "../src/crypto";
import {canonical} from "../src/surface-push/wire";
import {createWidgetFirstKeyHandler} from "../src/native-push/first-key-service";
import {createWidgetFirstKeyAppleVerifier} from "../src/native-push/first-key-apple";
import {installationNativePolicy} from "../src/native-push/installation-policy";
import {firstKeyRegisterBytes,installationFirstKeyAudience,type FirstKeyChallenge} from "../src/native-push/first-key-wire";
const kernel=vi.hoisted(()=>({expires:0,status:0,calls:0,after:undefined as undefined|(()=>Promise<void>)}));
vi.mock("../coordinator/host-app-wake-receiving/native-apple-evidence.mjs",()=>({
 verifyAppleAttestationEvidence:async()=>{
  kernel.calls++;await kernel.after?.();
  return {scope:"APPLE_ATTESTATION_AND_RECEIPT_CRYPTO_STATUS_ONLY_NO_ENROLLMENT",public_key_spki_b64:"MODEL_ONLY_NOT_AN_APPLE_KEY",
   launch_validation_category_b64:"AwAAAA==",expires:kernel.expires,statusExpiresAt:kernel.status};
 }
}));
const db=env.DB,origin="https://api.djconnect.dev",prefix="/v1/push/native/key/";
beforeAll(async()=>{
 const schema=[credentials,surface,delegations,native,roles,apple].join("\n");
 const triggers=schema.match(/CREATE TRIGGER[\s\S]*?END;/g)??[];
 for(const sql of schema.replace(/CREATE TRIGGER[\s\S]*?END;/g,"").replace(/^--.*$/gm,"").split(";").map(s=>s.trim()).filter(Boolean))await db.prepare(sql).run();
 for(const sql of triggers)await db.prepare(sql).run();
});
beforeEach(async()=>{
 for(const table of ["native_installation_first_key","native_installation_key_retirements","install_tokens"])await db.prepare("DELETE FROM "+table).run();
 kernel.expires=Date.now()+7_200_000;kernel.status=Date.now()+900_000;kernel.calls=0;kernel.after=undefined;
});
async function prepared(afterPair?:()=>Promise<void>){
 const credential=await issueInstallToken(db,{ha_install_id:"MODEL_ACK_STORAGE_BOUNDARY"});
 const key=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair;
 const spki=new Uint8Array(await crypto.subtle.exportKey("spki",key.publicKey));
 const hash=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",spki)),b=>b.toString(16).padStart(2,"0")).join("");
 const original={contract_version:1 as const,operation_id:"model-native-operation",pairing_generation:"model-original-pair",
  pair_binding:"1".repeat(64),owner_binding:"2".repeat(64),device_binding:"3".repeat(64),core_key_thumbprint:hash};
 const handler=createWidgetFirstKeyHandler(db,origin,()=>true,{
  id:installationNativePolicy.id,expiresAt:installationNativePolicy.expiresAt,isCurrent:()=>true,
  isPairCurrent:async()=>{await afterPair?.();return true;},verifyApple:createWidgetFirstKeyAppleVerifier(installationNativePolicy.apple)
 },undefined,"installation");
 const request=(action:string,body:unknown)=>new Request(origin+prefix+action,{method:"POST",headers:{
  "content-type":"application/json",authorization:"Bearer "+credential.token},body:canonical(body)});
 const response=await handler(request("challenge",original));expect(response.status).toBe(200);
 const challenge=await response.json() as FirstKeyChallenge;
 const transcript=firstKeyRegisterBytes(challenge,original,installationFirstKeyAudience);
 const body={...original,...challenge,core_public_key_spki_b64:base64Encode(spki),
  core_signature_b64url:base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key.privateKey,transcript)),
  apple_proof:{kind:"attestation",key_id_b64:btoa("0".repeat(32)),proof_b64:"AA=="}};
 return {credential,handler,request,body,challenge};
}
it("MODEL kernel boundary: copies exact original evidence bounds into the same winning receipt and native-key row",async()=>{
 const x=await prepared(),response=await x.handler(x.request("register",x.body));
 expect(response.status).toBe(200);
 const receipt=await response.json() as Record<string,unknown>;
 expect(receipt).toMatchObject({state:"registered",expires_at_ms:x.challenge.expires_at_ms,
  apple_evidence_expires_at_ms:kernel.expires,apple_status_expires_at_ms:kernel.status});
 expect(Object.keys(receipt).sort()).toEqual(["contract_version","operation_id","api_installation_id","install_credential_id",
  "pairing_generation","registry_generation","key_revision","core_key_thumbprint","transcript_sha256","expires_at_ms","state",
  "apple_evidence_expires_at_ms","apple_status_expires_at_ms"].sort());
 const row=await db.prepare("SELECT receipt,apple_evidence_expires_at_ms,apple_status_expires_at_ms FROM native_installation_first_key")
  .first<{receipt:string;apple_evidence_expires_at_ms:number;apple_status_expires_at_ms:number}>();
 expect(JSON.parse(row!.receipt)).toEqual(receipt);
 expect(row!.apple_evidence_expires_at_ms).toBe(kernel.expires);expect(row!.apple_status_expires_at_ms).toBe(kernel.status);
});
it("caller-supplied evidence deadlines cannot enter the registered receipt",async()=>{
 const x=await prepared();
 expect((await x.handler(x.request("register",{...x.body,apple_evidence_expires_at_ms:kernel.expires,
  apple_status_expires_at_ms:kernel.status}))).status).toBe(400);
 expect(kernel.calls).toBe(0);expect(await db.prepare("SELECT receipt FROM native_installation_first_key").first("receipt")).toBeNull();
});
it.each(["expired-evidence","expired-status","fractional-status"])("MODEL kernel boundary: %s cannot produce key metadata or ACK",async changed=>{
 const x=await prepared();
 if(changed==="expired-evidence")kernel.expires=Date.now()-1;
 if(changed==="expired-status")kernel.status=Date.now()-1;
 if(changed==="fractional-status")kernel.status+=0.5;
 expect((await x.handler(x.request("register",x.body))).status).toBe(403);
 expect(kernel.calls).toBe(1);
 expect(await db.prepare("SELECT receipt FROM native_installation_first_key").first("receipt")).toBeNull();
});
it("MODEL kernel boundary: actual expiry during the final authority await prevents the atomic winning receipt",async()=>{
 let waited=false;
 const x=await prepared(async()=>{if(kernel.calls&&!waited){waited=true;await new Promise(resolve=>setTimeout(resolve,600));}});
 kernel.status=Date.now()+400;
 const response=await x.handler(x.request("register",x.body));
 expect(kernel.calls).toBe(1);expect(waited).toBe(true);expect(response.status).toBe(409);
 expect(await db.prepare("SELECT receipt FROM native_installation_first_key").first("receipt")).toBeNull();
});
