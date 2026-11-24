import { findInstallTokenByBearer } from "../repository";
import type { InstallTokenRecord } from "../types";
import { need, SurfaceError } from "../surface-push/wire";
import { readFirstKeyBody } from "./first-key-service";

export const installationPrefix = "/v1/push/native/installation/";
const operations = new Set(["resolve", "publisher/operation", "publisher/withdraw"]);
const identifier = /^[A-Za-z0-9_-]{1,128}$/;
const hash = /^[a-f0-9]{64}$/;
const nowSQL = "CAST(unixepoch('subsec') * 1000 AS INTEGER)";
const credentialSQL = "EXISTS (SELECT 1 FROM install_tokens WHERE id=? AND token_hash=? AND ha_install_id=? AND disabled=0)";
const fields = ["install_credential_id", "operation_id", "pairing_generation", "pair_binding",
	"owner_binding", "device_binding", "core_key_thumbprint", "request_expires_at_ms", "consent_revision"];
function exact(value: unknown, names: string[]): asserts value is Record<string, unknown> {
	need(value !== null && typeof value === "object" && !Array.isArray(value) &&
		Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name)));
}
function positive(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}
function valid(value: unknown, pattern: RegExp): value is string {
	return typeof value === "string" && pattern.test(value);
}
const values = (credential: InstallTokenRecord) => [credential.id, credential.token_hash, credential.ha_install_id];
const response = (body: unknown, status = 200) => Response.json(body, { status, headers: {
	"cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff",
} });

/** Existing active credential, never a caller HA-ID or positive native witness. */
export async function authenticateInstallation(request: Request, db: D1Database, current: () => boolean) {
	need(current(), "native_installation_unavailable", 503);
	const match = /^Bearer (djci_[A-Za-z0-9_-]{43})$/.exec(request.headers.get("authorization") ?? "");
	need(match, "install_auth_required", 401);
	const credential = await findInstallTokenByBearer(db, match[1]);
	need(credential && current(), "install_auth_required", 401);
	return Object.freeze(credential);
}

/** Own-principal DATA publication only. This factory cannot enroll a native key. */
export function createInstallationPublisher(db: D1Database, origin: string, current: () => boolean,
	now: () => number = Date.now) {
	return async (request: Request) => {
		try {
			const path = new URL(request.url).pathname;
			const action = path.slice(installationPrefix.length);
			need(request.method === "POST" && operations.has(action) &&
				request.url === origin + installationPrefix + action, "native_installation_not_found", 404);
			const credential = await authenticateInstallation(request, db, current);
			const input = await readFirstKeyBody(request, 4096, true);
			exact(input, ["contract_version", ...(action === "resolve" ? [] :
				action === "publisher/withdraw" ? ["pair_binding", "consent_revision"] : fields)]);
			need(input.contract_version === 1);
			need(current() && !request.signal.aborted, "native_installation_unavailable", 503);
			if (action === "resolve") {
				const row = await db.prepare(`SELECT id,ha_install_id FROM install_tokens
					WHERE id=? AND token_hash=? AND ha_install_id=? AND disabled=0`).bind(...values(credential))
					.first<{ id: string; ha_install_id: string }>();
				need(row && current() && !request.signal.aborted, "install_auth_required", 401);
				return response({ contract_version: 1, install_credential_id: row.id, ha_install_id: row.ha_install_id });
			}
			need(valid(input.pair_binding, hash) && positive(input.consent_revision));
			let result: unknown;
			if (action === "publisher/withdraw") {
				result = await db.prepare(`INSERT INTO native_installation_consent_withdrawals
					(credential_id,pair_binding,through_revision) SELECT ?,?,? WHERE ${credentialSQL}
					ON CONFLICT(credential_id,pair_binding) DO UPDATE SET through_revision=MAX(through_revision,excluded.through_revision)
					RETURNING through_revision`).bind(credential.id, input.pair_binding, input.consent_revision,
					...values(credential)).first();
			} else {
				need(input.install_credential_id === credential.id && valid(input.operation_id, identifier) &&
					valid(input.pairing_generation, identifier) && ["owner_binding", "device_binding", "core_key_thumbprint"]
						.every(name => valid(input[name], hash)) && positive(input.request_expires_at_ms) &&
					now() < input.request_expires_at_ms && input.request_expires_at_ms <= now() + 120_000);
				result = await db.prepare(`INSERT INTO native_installation_pair_publications
					(credential_id,operation_id,pairing_generation,pair_binding,owner_binding,device_binding,
					 core_key_thumbprint,request_expires_at_ms,consent_revision)
					SELECT ?,?,?,?,?,?,?,?,? WHERE ${credentialSQL} AND ? > ${nowSQL}
					AND NOT EXISTS (SELECT 1 FROM native_installation_consent_withdrawals
						WHERE credential_id=? AND pair_binding=? AND through_revision>=?)
					AND NOT EXISTS (SELECT 1 FROM native_installation_key_retirements WHERE credential_id=? AND pair_binding=?)
					AND ((SELECT count(*) FROM native_installation_pair_publications pending WHERE pending.credential_id=?
                        AND NOT EXISTS(SELECT 1 FROM native_installation_key_retirements r
                          WHERE r.credential_id=pending.credential_id AND r.pair_binding=pending.pair_binding)
                        AND NOT EXISTS(SELECT 1 FROM native_installation_consent_withdrawals w
                          WHERE w.credential_id=pending.credential_id AND w.pair_binding=pending.pair_binding
                            AND w.through_revision>=pending.consent_revision)) < 64
						OR EXISTS (SELECT 1 FROM native_installation_pair_publications WHERE credential_id=? AND operation_id=?))
					ON CONFLICT(credential_id,operation_id) DO UPDATE SET operation_id=excluded.operation_id
					WHERE pairing_generation=excluded.pairing_generation AND pair_binding=excluded.pair_binding
					AND owner_binding=excluded.owner_binding AND device_binding=excluded.device_binding
					AND core_key_thumbprint=excluded.core_key_thumbprint AND request_expires_at_ms=excluded.request_expires_at_ms
					AND consent_revision=excluded.consent_revision RETURNING operation_id`).bind(credential.id,
					input.operation_id, input.pairing_generation, input.pair_binding, input.owner_binding, input.device_binding,
					input.core_key_thumbprint, input.request_expires_at_ms, input.consent_revision, ...values(credential),
					input.request_expires_at_ms, credential.id, input.pair_binding, input.consent_revision,
					credential.id, input.pair_binding, credential.id, credential.id, input.operation_id).first();
			}
			need(result, "native_installation_publication_conflict", 409);
			need(current() && !request.signal.aborted, "native_installation_unavailable", 503);
			return response({ ok: true });
		} catch (error) {
			return error instanceof SurfaceError ? response({ error: error.code }, error.status)
				: response({ error: "native_installation_unavailable" }, 503);
		}
	};
}
