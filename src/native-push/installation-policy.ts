/** Explicit platform-selected limited development admission, not Apple evidence.
 * Signed artifact readback: iOS40532, source e0fa68b870893343f4660f42786e3697d0c8e35d.
 * Category3 is the selected server condition; the existing verifier must still
 * obtain and cryptographically validate the actual Apple attestation against it.
 */
export const installationNativePolicy = Object.freeze({
 id: "ios-native-push-development-40532/1",
 expiresAt: Date.parse("2026-12-23T10:00:00Z"),
 apple: Object.freeze({
  profile: "host_wake_apple_properties_attestation_v2" as const,
  app_identifier: "ZEML4LPXH4.dev.djconnect.ios",
  app_attest_environment: "development" as const,
  bundle_version: "40532",
  launch_validation_category_b64: "AwAAAA==",
 }),
});
