/** First supported native-installation contract, with an Apple-signed build
 * floor. The persisted policy ID stays stable for current installation rows.
 * The Apple verifier still verifies the application, environment, category,
 * challenge, signed build and original receipt independently.
 */
export const installationNativePolicy = Object.freeze({
 id: "ios-native-push-development-40533/1",
 expiresAt: Date.parse("2026-12-23T10:00:00Z"),
 apple: Object.freeze({
  profile: "host_wake_apple_properties_attestation_v2" as const,
  app_identifier: "ZEML4LPXH4.dev.djconnect.ios",
  app_attest_environment: "development" as const,
  minimum_bundle_version: "40533",
  launch_validation_category_b64: "AwAAAA==",
 }),
});
