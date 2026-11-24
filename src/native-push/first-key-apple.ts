import {
	verifyAppleAttestationEvidence, type NativeAppleEvidencePolicy,
} from "../../coordinator/host-app-wake-receiving/native-apple-evidence.mjs";
import { RequestWindow } from "../../coordinator/host-app-wake-receiving/request-window";
import type { WidgetFirstKeyPolicy } from "./first-key-service";
import { canonical } from "../surface-push/wire";

export interface VerifiedFirstKeyApple { readonly kind: "native_first_key_apple_crypto_only" }
interface OriginalAppleKey {
 readonly key_id_b64: string;
 readonly public_key_spki_b64: string;
 readonly policy_json: string;
 readonly evidence_expires_at_ms: number;
 readonly status_expires_at_ms: number;
 readonly counter: 0;
}
const originals = new WeakMap<VerifiedFirstKeyApple, {key: Readonly<OriginalAppleKey>; transcript: Uint8Array; deadline: number}>();

/** Only the actual verifier continuation below can produce this one-use input.
 * It is native key DATA, not a role grant, SDK admission or enrolled ACK. */
export function consumeFirstKeyApple(value: unknown, transcript: Uint8Array, keyId: string): Readonly<OriginalAppleKey> | null {
 if (value === null || typeof value !== "object") return null;
 const original = originals.get(value as VerifiedFirstKeyApple);
 originals.delete(value as VerifiedFirstKeyApple);
 if (!original || Date.now() >= original.deadline || original.key.key_id_b64 !== keyId ||
  transcript.length !== original.transcript.length || !transcript.every((byte, i) => byte === original.transcript[i])) return null;
 return original.key;
}

/** The policy is supplied by the trusted server composition for one signed app. */
export function createWidgetFirstKeyAppleVerifier(
	policy: Readonly<NativeAppleEvidencePolicy>,
): WidgetFirstKeyPolicy["verifyApple"] {
	const selected = Object.freeze({
		...policy,
		allowed_launch_validation_categories_b64: policy.allowed_launch_validation_categories_b64 &&
			Object.freeze([...policy.allowed_launch_validation_categories_b64]),
	});
	return async (attestation, keyId, transcript, expiresAt, signal) => {
		const remaining = expiresAt - Date.now();
		if (remaining <= 0 || signal.aborted) return false;
		const deadline = AbortSignal.any([signal, AbortSignal.timeout(remaining)]);
		const window = new RequestWindow(Date.now, deadline);
		try {
			// The existing verifier hashes the raw transcript for App Attest.
			const evidence = await verifyAppleAttestationEvidence(attestation, transcript, keyId, selected, window, fetch);
			if (!evidence || Date.now() >= expiresAt || deadline.aborted) return false;
            const result = Object.freeze({kind: "native_first_key_apple_crypto_only" as const});
            originals.set(result, {transcript: Uint8Array.from(transcript), deadline: expiresAt,
                key: Object.freeze({key_id_b64: keyId, public_key_spki_b64: evidence.public_key_spki_b64,
                    policy_json: canonical({profile: "host_wake_apple_assertion_properties_v2",
                        app_identifier: selected.app_identifier, bundle_version: selected.bundle_version,
                        launch_validation_category_b64: evidence.launch_validation_category_b64}),
                    evidence_expires_at_ms: evidence.expires, status_expires_at_ms: evidence.statusExpiresAt,
                    counter: 0 as const})});
            return result;
		} finally {
			window.close();
		}
	};
}
