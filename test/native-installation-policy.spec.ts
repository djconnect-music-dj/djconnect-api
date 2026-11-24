/** Actual selected configuration/HTTP guard, not Apple proof acceptance. */
import {env} from "cloudflare:test";
import {expect,it} from "vitest";
import evidence from "../docs/native-push/signed-ios-40533-policy-evidence.json";
import {installationNativePolicy} from "../src/native-push/installation-policy";
import {createInstallationFirstKey} from "../src/native-push/installation-first-key";
import {createWidgetFirstKeyHandler} from "../src/native-push/first-key-service";
const origin="https://api.djconnect.dev";
const request=()=>new Request(origin+"/v1/push/native/key/challenge",{method:"POST",
 headers:{"content-type":"application/json"},body:"{}"});
it("pins the NEW selected40533 policy to actual signed artifact data without claiming Apple/category/clock acceptance",()=>{
 expect(installationNativePolicy).toEqual({id:"ios-native-push-development-40533/1",
  expiresAt:Date.parse("2026-12-23T10:00:00Z"),apple:{profile:"host_wake_apple_properties_attestation_v2",
   app_identifier:"ZEML4LPXH4.dev.djconnect.ios",app_attest_environment:"development",bundle_version:"40533",
   launch_validation_category_b64:"AwAAAA=="}});
 expect(evidence.application.build).toBe("40533");expect(evidence.apple_source).toBe("60fd1157207dfb0f8cc7fe5fbf3acfd26fd3ef58");
 expect(evidence.signed_manifest_sha256).toBe("1d83d30268176f56f4a6f398bee2e38f50df292f67f76b90d55b928cd4611741");
 expect(evidence.application.executable_sha256).toBe("b455a8ad75e7b8214b4e2feefb85fdffdbf71b1e66a2ad7323ba5efd2ca9450d");
 expect(evidence.category_observed_in_actual_apple_proof).toBe(false);
 expect(evidence.installation_or_native_clock_admission_from_metadata).toBe(false);
});
it("selected configuration still requires original installation authentication before any native decision",async()=>{
 expect((await createInstallationFirstKey(env.DB,origin,()=>true,installationNativePolicy)(request())).status).toBe(401);
});
const variants=[
 {name:"old40532 policy ID",id:"ios-native-push-development-40532/1"},
 {name:"old40532 bundle",apple:{bundle_version:"40532"}},
 {name:"other unqualified bundle",apple:{bundle_version:"40534"}},
 {name:"other category",apple:{launch_validation_category_b64:"BAAAAA=="}},
 {name:"production environment",apple:{app_attest_environment:"production" as const}},
 {name:"other AppID",apple:{app_identifier:"ZEML4LPXH4.dev.other"}},
];
it.each(variants)("rejects trusted-composition miswire: $name before auth/verifier/network",async variant=>{
 const selected={...installationNativePolicy,id:variant.id??installationNativePolicy.id,
  apple:{...installationNativePolicy.apple,...variant.apple}};
 const response=await createInstallationFirstKey(env.DB,origin,()=>true,selected)(request());
 expect(response.status).toBe(503);expect(await response.json()).toEqual({error:"native_first_key_policy_unavailable"});
});
it("the low-level production guard refuses the OLD40532 slash policy rather than silently upgrading it",async()=>{
 let verifierCalls=0;
 const handler=createWidgetFirstKeyHandler(env.DB,origin,()=>true,{id:"ios-native-push-development-40532/1",
  expiresAt:installationNativePolicy.expiresAt,isCurrent:()=>true,isPairCurrent:async()=>true,
  verifyApple:async()=>{verifierCalls++;return true;}},undefined,"installation");
 const response=await handler(request());expect(response.status).toBe(503);expect(verifierCalls).toBe(0);
});
