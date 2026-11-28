import { requireInstallAuth } from "../auth";
import { HttpError, json, readJson } from "../http";
import { unregister, upsertRegistration } from "../repository";
import { deliverPushEvent } from "../services/pushDelivery";
import type { AppEnv, PushEventRequest, RegisterRequest, UnregisterRequest } from "../types";
import { requireBearerHeader, validatePushEvent, validateRegister, validateUnregister } from "../validation";

export async function registerDevice(request: Request, env: AppEnv): Promise<Response> {
	const input = await readJson<RegisterRequest>(request);
	requireBearerHeader(request);
	validateRegister(input);
	await requireInstallAuth(request, env, input.ha_install_id);
	const result = await upsertRegistration(env.DB, env, input);
	return json({ ok: true, id: result.id, apns_token_hash: result.tokenHash });
}

export async function unregisterDevice(request: Request, env: AppEnv): Promise<Response> {
	const input = await readJson<UnregisterRequest>(request);
	requireBearerHeader(request);
	validateUnregister(input);
	await requireInstallAuth(request, env, input.ha_install_id);
	const changes = await unregister(env.DB, input);
	return json({ ok: true, disabled: changes });
}

export async function sendPushEvent(request: Request, env: AppEnv, ctx: ExecutionContext): Promise<Response> {
	const wire = await readJson<Omit<PushEventRequest, "event_type"> & { event_type: string; target_device_id?: string }>(request);
	const event = wire.event_type;
	const targeted = event === "ask_dj_device_response" || event === "ask_dj_device_confirm";
	// Old relays reject the new event names and cannot deliver them without device targeting.
	const input = { ...wire, event_type: ((event === "ask_dj_device_response" ? "ask_dj_response" :
		event === "ask_dj_device_confirm" ? "ask_dj_confirm" : event) as PushEventRequest["event_type"]) };
	requireBearerHeader(request);
	validatePushEvent(input);
	if (!targeted && input.target_device_id !== undefined) throw new HttpError(400, "unsafe_payload");
	if (targeted && (typeof input.target_device_id !== "string" ||
		typeof input.history_revision !== "number" || !Number.isSafeInteger(input.history_revision) || input.history_revision < 1 ||
		typeof input.ha_user_hash !== "string" || !/^[a-f0-9]{64}$/.test(input.ha_user_hash) ||
		!Array.isArray(input.client_types) || input.client_types.length !== 1 ||
		!/^djconnect-(ios|macos|watchos)-[A-Za-z0-9]{12}$/.test(input.target_device_id) ||
		!input.target_device_id.startsWith("djconnect-" + input.client_types[0] + "-"))) {
		throw new HttpError(400, "unsafe_payload");
	}
	await requireInstallAuth(request, env, input.ha_install_id);
	const result = await deliverPushEvent(env, input, targeted ? input.target_device_id : undefined);
	ctx.waitUntil(result.audit);
	return json({ ok: true, matched: result.matched, delivered: result.delivered, failed: result.failed });
}
