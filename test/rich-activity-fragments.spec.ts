import { describe, expect, it } from "vitest";
import { base64Url } from "../src/crypto";
import { encodeRichActivityUpdate, parseRichActivityFragments } from "../src/surface-push/rich-activity-fragments";

const bytes = new TextEncoder();
const attributes = '{"presentationID":"existing-activity"}';
const observed = 1_800_000_000_000;
const expires = observed + 20_000;
const owner = { attributes: bytes.encode(attributes), observed, expires };
const state = '{"observedAt":821692800.00,"expiresAt":821692820,"theme":"groove"}';
const carrier = (fragment = state, overrides = {}) => bytes.encode(JSON.stringify({
	schema_version: 1,
	profile_id: "djconnect-session-rich-v1",
	attributes_utf8_b64u: base64Url(attributes),
	content_state_utf8_b64u: base64Url(fragment),
	source_observed_at_ms: observed,
	source_expires_at_ms: expires,
	...overrides,
}));

describe("rich Live Activity fragments", () => {
	it("preserves the original Foundation Date encoding in both update and end payloads", () => {
		const update = encodeRichActivityUpdate(carrier(), owner, "update", observed + 1000);
		expect(update).toContain('"content-state":' + state);
		expect(JSON.parse(update).aps).toMatchObject({ event: "update", timestamp: observed / 1000, "stale-date": expires / 1000 });
		const end = JSON.parse(encodeRichActivityUpdate(carrier(), owner, "end", observed + 1000)).aps;
		expect(end).toMatchObject({ event: "end", "dismissal-date": observed / 1000 });
	});

	it("requires byte equality with the original creation attributes and matching source bounds", () => {
		expect(() => encodeRichActivityUpdate(carrier(), { ...owner, attributes: bytes.encode(attributes + " ") }, "update", observed))
			.toThrow("surface_scope_mismatch");
		expect(() => encodeRichActivityUpdate(carrier(), { ...owner, expires: expires + 1 }, "update", observed))
			.toThrow("surface_scope_mismatch");
	});

	it("rejects future or expired content and never rounds the original expiry up", () => {
		expect(() => encodeRichActivityUpdate(carrier(), owner, "update", observed - 1)).toThrow("surface_content_expired");
		expect(() => encodeRichActivityUpdate(carrier(), owner, "update", expires)).toThrow("surface_content_expired");
		const nearEnd = expires - 1;
		expect(() => encodeRichActivityUpdate(carrier(state, { source_expires_at_ms: nearEnd }),
			{ ...owner, expires: nearEnd }, "update", nearEnd - 1)).toThrow("surface_content_expired");
	});

	it("rejects alternate spellings, duplicate keys and invalid UTF-8 before composition", () => {
		expect(() => parseRichActivityFragments(carrier(state, { attributes_utf8_b64u: base64Url(attributes) + "=" }))).toThrow();
		expect(() => parseRichActivityFragments(carrier(state.replace('"theme":', '"theme":"chill","\\u0074heme":'))))
			.toThrow("duplicate_json_key");
		expect(() => parseRichActivityFragments(carrier(state, { content_state_utf8_b64u: "_w" }))).toThrow("invalid_json");
		expect(() => parseRichActivityFragments(carrier(state.replace('"groove"', 'null')))).toThrow();
	});

	it("counts the original rich object bytes, including escaping", () => {
		const rich = {
			bindingID: "pair", generation: "generation", sequence: 1,
			receivedAt: 821692800, receivedUptime: 10, expiresAt: 821692820,
			contribution: {
				moment_id: "moment",
				published_at: new Date(observed).toISOString(),
				expires_at: new Date(expires).toISOString(),
				text: "",
				persona: "DJ",
				source_attribution: { source: "DJConnect" },
				usage_basis: "source-owned",
			},
		};
		const emptySize = bytes.encode(JSON.stringify(rich)).length;
		rich.contribution.text = "é".repeat(Math.floor((2800 - emptySize) / 2))
			+ " ".repeat((2800 - emptySize) % 2);
		const withRich = () => JSON.stringify({ ...JSON.parse(state), rich });
		expect(() => parseRichActivityFragments(carrier(withRich()))).not.toThrow();
		rich.contribution.text += '"';
		expect(() => parseRichActivityFragments(carrier(withRich()))).toThrow("surface_content_too_large");
	});

	it("checks the exact final APNs bytes independently from the fragment cap", () => {
		const base = encodeRichActivityUpdate(carrier(), owner, "update", observed);
		const padding = " ".repeat(4096 - bytes.encode(base).length);
		expect(bytes.encode(encodeRichActivityUpdate(carrier(state + padding), owner, "update", observed)).length).toBe(4096);
		expect(() => encodeRichActivityUpdate(carrier(state + padding + " "), owner, "update", observed))
			.toThrow("surface_content_too_large");
	});
});
