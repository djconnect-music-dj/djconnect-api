import { base64Decode, base64Encode } from "../crypto";
import { need, parseStrictJson, SurfaceError } from "./wire";

export const RICH_ACTIVITY_PROFILE = "djconnect-session-rich-v1";
const BODY_LIMIT = 4096;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const foundationEpochSeconds = 978_307_200;
const fieldLimit = 120;

function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
	need(value !== null && typeof value === "object" && !Array.isArray(value));
	const record = value as Record<string, unknown>;
	need(required.every(key => Object.hasOwn(record, key)));
	need(Object.keys(record).every(key => required.includes(key) || optional.includes(key)));
	return record;
}

function string(value: unknown): asserts value is string {
	need(typeof value === "string" && !/[\uD800-\uDFFF]/u.test(value));
}

function finite(value: unknown): asserts value is number {
	need(typeof value === "number" && Number.isFinite(value));
}

function identifier(value: unknown): void {
	string(value);
	need(/^[A-Za-z0-9_-]{1,128}$/.test(value));
}

function fragment(value: unknown): Uint8Array {
	string(value);
	need(/^[A-Za-z0-9_-]+$/.test(value) && value.length % 4 !== 1);
	const bytes = base64Decode(value.replaceAll("-", "+").replaceAll("_", "/"));
	need(base64Encode(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "") === value);
	return bytes;
}

function decodeUtf8(bytes: Uint8Array): string {
	try { return decoder.decode(bytes); }
	catch { throw new SurfaceError(400, "invalid_json"); }
}

function foundationDate(value: unknown): number {
	string(value);
	need(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value));
	return Date.parse(value) / 1000 - foundationEpochSeconds;
}

function nestedField(
	value: unknown, fields: readonly string[], attribution: string, observedKey: string,
	observed: number, richExpiry: number,
): void {
	const record = object(value, fields);
	for (const [key, field] of Object.entries(record)) if (key !== attribution) string(field);
	const references = record[attribution];
	need(references !== null && typeof references === "object" && !Array.isArray(references));
	for (const [key, item] of Object.entries(references)) { string(key); string(item); }
	const seen = foundationDate(record[observedKey]);
	const expires = foundationDate(record.expires_at);
	need(seen <= observed && observed < expires && richExpiry <= expires);
}

function validateState(source: string): void {
	let richBytes = 0;
	const state = object(parseStrictJson(source, (depth, key, start, end) => {
		if (depth === 0 && key === "rich") richBytes = encoder.encode(source.slice(start, end)).length;
	}), ["observedAt", "expiresAt"], ["theme", "rich"]);
	const observed = state.observedAt, expires = state.expiresAt;
	finite(observed); finite(expires);
	need(observed < expires && expires - observed <= fieldLimit);
	if (state.theme !== undefined) {
		string(state.theme);
		need(["brand", "chill", "groove", "energy", "party"].includes(state.theme));
	}
	if (state.rich === undefined) return;
	need(richBytes <= 2800, "surface_content_too_large", 413);
	const rich = object(state.rich, ["bindingID", "generation", "sequence", "receivedAt", "receivedUptime", "expiresAt"],
		["contribution", "nowPlaying", "playbackState"]);
	identifier(rich.bindingID); identifier(rich.generation);
	need(typeof rich.sequence === "number" && Number.isSafeInteger(rich.sequence) && rich.sequence >= 0);
	const start = rich.receivedAt, uptime = rich.receivedUptime, end = rich.expiresAt;
	finite(start); finite(uptime); finite(end);
	need(uptime >= 0 && start <= observed && expires <= end && end - start <= fieldLimit);
	need(rich.contribution !== undefined || rich.nowPlaying !== undefined);
	if (rich.contribution !== undefined) nestedField(rich.contribution,
		["moment_id", "published_at", "text", "persona", "source_attribution", "usage_basis", "expires_at"],
		"source_attribution", "published_at", observed, end);
	if (rich.nowPlaying !== undefined) nestedField(rich.nowPlaying,
		["item_id", "subject_uri", "track", "artist", "album", "observed_at", "expires_at", "source_url", "attribution", "usage_basis"],
		"attribution", "observed_at", observed, end);
	if (rich.playbackState !== undefined) {
		string(rich.playbackState);
		need(rich.nowPlaying && ["idle", "stopped", "playing", "paused"].includes(rich.playbackState));
	}
}

/** Validate syntax and size only. The original Activity owner must authenticate the
 * native attributes, source bounds, field permissions and receiver clock separately. */
export function parseRichActivityFragments(carrier: Uint8Array) {
	need(carrier.length > 0 && carrier.length <= 16384, "surface_content_too_large", 413);
	const data = object(parseStrictJson(decodeUtf8(carrier)), ["schema_version", "profile_id", "attributes_utf8_b64u",
		"content_state_utf8_b64u", "source_observed_at_ms", "source_expires_at_ms"]);
	need(data.schema_version === 1 && data.profile_id === RICH_ACTIVITY_PROFILE);
	const observed = data.source_observed_at_ms, expires = data.source_expires_at_ms;
	need(typeof observed === "number" && Number.isSafeInteger(observed) && observed >= 0);
	need(typeof expires === "number" && Number.isSafeInteger(expires) && observed < expires);
	const attributes = fragment(data.attributes_utf8_b64u), state = fragment(data.content_state_utf8_b64u);
	need(attributes.length + state.length <= BODY_LIMIT, "surface_content_too_large", 413);
	string(object(parseStrictJson(decodeUtf8(attributes)), ["presentationID"]).presentationID);
	const rawState = decodeUtf8(state);
	validateState(rawState);
	return { attributes, rawState, observed, expires };
}

/** Compose exact bytes; the caller supplies previously authenticated owner bounds. */
export function encodeRichActivityUpdate(carrier: Uint8Array, owner: {
	attributes: Uint8Array;
	observed: number;
	expires: number;
}, event: "update" | "end", now: number): string {
	need(event === "update" || event === "end");
	const parsed = parseRichActivityFragments(carrier);
	need(parsed.attributes.length === owner.attributes.length &&
		parsed.attributes.every((byte, index) => byte === owner.attributes[index]), "surface_scope_mismatch", 403);
	need(parsed.observed === owner.observed && parsed.expires === owner.expires, "surface_scope_mismatch", 403);
	need(Number.isSafeInteger(now) && parsed.observed <= now && now < parsed.expires &&
		parsed.expires - parsed.observed <= fieldLimit * 1000, "surface_content_expired", 409);
	const timestamp = Math.floor(parsed.observed / 1000), stale = Math.floor(parsed.expires / 1000);
	need(stale > Math.floor(now / 1000), "surface_content_expired", 409);
	const dismissal = event === "end" ? ',"dismissal-date":' + (Math.floor(now / 1000) - 1) : "";
	const body = '{"aps":{"timestamp":' + timestamp + ',"event":' + JSON.stringify(event) +
		',"content-state":' + parsed.rawState + ',"stale-date":' + stale + dismissal + '}}';
	need(encoder.encode(body).length <= BODY_LIMIT, "surface_content_too_large", 413);
	return body;
}
