/** Explicit platform-selected limited development admission, not Apple evidence.
 * Signed artifact readback: iOS40533, source60fd1157207dfb0f8cc7fe5fbf3acfd26fd3ef58.
 * Category3 is the selected server condition; the existing verifier must still
 * obtain and cryptographically validate the actual Apple attestation against it.
 */
export const installationNativePolicy = Object.freeze({
 id: "ios-native-push-development-40533/1",
 expiresAt: Date.parse("2026-12-23T10:00:00Z"),
 apple: Object.freeze({
  profile: "host_wake_apple_properties_attestation_v2" as const,
  app_identifier: "ZEML4LPXH4.dev.djconnect.ios",
  app_attest_environment: "development" as const,
  bundle_version: "40533",
  launch_validation_category_b64: "AwAAAA==",
 }),
});
