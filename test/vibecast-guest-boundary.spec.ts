import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";

// The Core participation issuer and the native owner/screen rendezvous are
// different authorities. These are negative Worker/D1 integration scenarios,
// not a central guest API or a proof that native/physical joining works.
const guest = {
	contract_version: 1,
	issuer_epoch: "example-core-epoch",
	guest_id: "example-guest-id",
	invitation_id: "example-invitation-id",
	invitation_secret: "example-invitation-secret",
	text: "example-private-guest-question",
};
const guestBearer = "djcg_example-core-guest-bearer";

async function dispatch(path: string, admittedEdge = false, withBearer = true) {
	const request = new Request(`https://api.djconnect.dev${path}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...(admittedEdge ? { "CF-Connecting-IP": "192.0.2.26" } : { Origin: "https://vibecast.tv" }),
			...(withBearer ? { Authorization: `Bearer ${guestBearer}` } : {}),
		},
		body: JSON.stringify(admittedEdge ? { v: "djc-rendezvous/1", ...guest } : guest),
		...(admittedEdge ? { cf: { colo: "AMS" } } : {}),
	} as RequestInit);
	const ctx = createExecutionContext();
	// Fixed synthetic local policy/edge values exercise the open parser, never
	// actual Cloudflare provenance, native proof or production activation.
	const bindings = admittedEdge ? {
		...env,
		RENDEZVOUS_IP_HASH_KEY: btoa("Q".repeat(32)),
		RECEIPT_ACTIVE_KEY: btoa("R".repeat(32)),
	} : env;
	const response = await worker.fetch(request, bindings, ctx);
	await waitOnExecutionContext(ctx);
	return { request, response };
}

async function assertNoGuestContent(response: Response) {
	const output = JSON.stringify({
		body: await response.clone().text(),
		headers: [...response.headers],
		diagnostics: (await env.DB.prepare("SELECT * FROM api_diagnostics").all()).results,
	});
	for (const value of [...Object.values(guest), guestBearer]) {
		if (typeof value === "string") expect(output).not.toContain(value);
	}
}

describe("VibeCast guest/native API authority separation", () => {
	beforeAll(async () => {
		await env.DB.exec("CREATE TABLE IF NOT EXISTS api_diagnostics (id TEXT PRIMARY KEY, method TEXT NOT NULL, route TEXT NOT NULL, status INTEGER NOT NULL, error_code TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))");
	});
	beforeEach(async () => {
		await env.DB.exec("DELETE FROM api_diagnostics");
		vi.stubGlobal("fetch", vi.fn(() => { throw new Error("guest_boundary_must_not_egress"); }));
	});
	afterEach(() => {
		expect(fetch).not.toHaveBeenCalled();
		vi.unstubAllGlobals();
	});

	it.each(["redeem", "renew", "leave", "context", "ask", "request", "reaction"])(
		"does not proxy Core participation %s or retain its private input",
		async (action) => {
			const { request, response } = await dispatch(`/api/djconnect/v1/participation/${action}?invitation_id=${guest.invitation_id}`);
			expect(response.status).toBe(404);
			expect(await response.clone().json()).toEqual({ error: "not_found" });
			expect(request.bodyUsed).toBe(false);
			expect(response.headers.get("Location")).toBeNull();
			expect(response.headers.get("Set-Cookie")).toBeNull();
			expect((await env.DB.prepare("SELECT method, route, status, error_code FROM api_diagnostics").all()).results)
				.toEqual([{ method: "POST", route: "unmatched", status: 404, error_code: "not_found" }]);
			await assertNoGuestContent(response);
		},
	);

	it.each(["attestation/register", "submit-challenge", "submit"])(
		"does not promote a guest invitation into native %s admission",
		async (action) => {
			const { request, response } = await dispatch(`/v1/rendezvous/${action}`);
			expect(response.status).toBe(503);
			expect(await response.clone().json()).toEqual({ v: "djc-rendezvous/1", error: "service_unavailable" });
			expect(request.bodyUsed).toBe(false);
			expect((await env.DB.prepare("SELECT * FROM api_diagnostics").all()).results).toEqual([]);
			await assertNoGuestContent(response);
		},
	);

	it.each(["attestation/register", "submit-challenge", "submit"])(
		"rejects guest credentials at native %s even after local edge/policy admission",
		async (action) => {
			const { request, response } = await dispatch(`/v1/rendezvous/${action}`, true);
			expect(response.status).toBe(400);
			expect(await response.clone().json()).toEqual({ v: "djc-rendezvous/1", error: "invalid_request" });
			expect(request.bodyUsed).toBe(false);
			expect((await env.DB.prepare("SELECT * FROM api_diagnostics").all()).results).toEqual([]);
			await assertNoGuestContent(response);
		},
	);

	it.each(["attestation/register", "submit-challenge", "submit"])(
		"does not reinterpret a Core invitation as the native %s wire without a bearer",
		async (action) => {
			const { request, response } = await dispatch(`/v1/rendezvous/${action}`, true, false);
			expect(response.status).toBe(400);
			expect(await response.clone().json()).toEqual({ v: "djc-rendezvous/1", error: "invalid_request" });
			expect(request.bodyUsed).toBe(true);
			expect((await env.DB.prepare("SELECT * FROM api_diagnostics").all()).results).toEqual([]);
			await assertNoGuestContent(response);
		},
	);
});
