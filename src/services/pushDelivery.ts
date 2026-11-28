import { buildApnsPayload, isInvalidTokenReason, sendApns } from "../apns";
import { auditEvent, findActiveRegistrations, markRegistrationError, markRegistrationSuccess } from "../repository";
import type { AppEnv, ClientType, PushEventRequest, PushFailureSummary, Registration } from "../types";

export interface PushDeliveryResult {
	matched: number;
	delivered: number;
	failed: number;
	audit: Promise<void>;
}

function allowsAskDJ(registration: { categories_json: string }): boolean {
	try {
		const categories: unknown = JSON.parse(registration.categories_json);
		return Array.isArray(categories) && categories.includes("ask_dj");
	} catch {
		return false;
	}
}

export async function isAlertRecipientCurrent(db: D1Database, registration: Registration): Promise<boolean> {
	const row = await db.prepare(`SELECT 1 FROM registrations
		WHERE id = ? AND apns_token_nonce IS ? AND categories_json = ? AND disabled = 0 AND invalid = 0`)
		.bind(registration.id, registration.apns_token_nonce, registration.categories_json).first();
	return row !== null;
}

export async function deliverPushEvent(env: AppEnv, input: PushEventRequest, deviceID?: string): Promise<PushDeliveryResult> {
	const scoped = await findActiveRegistrations(env.DB, input);
	const matched = deviceID === undefined ? scoped : scoped.filter(row => row.device_id === deviceID);
	// Token rotation must leave a single current registration for targeted delivery.
	const registrations = deviceID !== undefined && matched.length !== 1 ? [] : matched;
	let delivered = 0;
	let failed = 0;
	const failures = new Map<string, PushFailureSummary>();
	const registrationChanged = new Error("registration_changed");

	for (const registration of registrations) {
		if (!allowsAskDJ(registration)) continue;
		const payload = buildApnsPayload({ ...input, locale: registration.locale });
		const result = await sendApns(env, registration, payload, async (endpoint, options) => {
			if (!await isAlertRecipientCurrent(env.DB, registration)) throw registrationChanged;
			return fetch(endpoint, options);
		}).catch((error: unknown) => {
			if (error === registrationChanged) return null;
			throw error;
		});
		if (!result) continue;
		if (result.ok) {
			delivered += 1;
			await markRegistrationSuccess(env.DB, registration);
		} else {
			failed += 1;
			incrementFailure(failures, registration.client_type, result.status, result.reason ?? `HTTP_${result.status}`);
			await markRegistrationError(
				env.DB,
				registration,
				result.reason ?? `HTTP_${result.status}`,
				isInvalidTokenReason(result.status, result.reason),
			);
		}
	}

	const audit = auditEvent(env.DB, {
		ha_install_id: input.ha_install_id,
		event_type: input.event_type,
		client_type: input.client_types?.length === 1 ? input.client_types[0] : undefined,
		target: delivered + failed,
		success: delivered,
		error: failed,
		failures: [...failures.values()],
	});

	return { matched: delivered + failed, delivered, failed, audit };
}

function incrementFailure(failures: Map<string, PushFailureSummary>, clientType: ClientType, status: number, reason: string): void {
	const key = `${clientType}:${status}:${reason}`;
	const existing = failures.get(key);
	if (existing) {
		existing.count += 1;
		return;
	}
	failures.set(key, { client_type: clientType, status, reason, count: 1 });
}
