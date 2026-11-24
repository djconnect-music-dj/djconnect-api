import type { Fetcher } from "../apns";
import type { AppEnv } from "../types";
import { createMomentTransport, type MomentPorts } from "../watch-moment/service";
import { createRestoredWatchSender } from "./restore-dispatch";
import type { WatchDispatchScope } from "./dispatch-identity";

/** The actual owner supplies publication/recipient admission, not a caller flag.
 * No key, enrollment, preference or public endpoint is created by this adapter. */
export interface OwnedWatchMoment {
	env: AppEnv;
	actor: DurableObjectState;
	namespace: DurableObjectNamespace;
	scope: Readonly<WatchDispatchScope>;
	now: MomentPorts["now"];
	admit: MomentPorts["admit"];
	assertCurrent: MomentPorts["assertCurrent"];
	limits: MomentPorts["limits"];
}

/** Compose original-Moment delivery with the existing stable restore owner.
 * Callers cannot substitute a sender that bypasses signed preference withdrawal.
 * Fetch injection is for the existing provider boundary's isolated qualification. */
export function createOwnedWatchMoment(owner: OwnedWatchMoment, fetcher: Fetcher = fetch) {
	const env = Object.freeze({ ...owner.env });
	const scope = Object.freeze({ ...owner.scope });
	const now = owner.now;
	return createMomentTransport({
		db: env.DB,
		admit: owner.admit,
		assertCurrent: owner.assertCurrent,
		now,
		limits: owner.limits,
		send: createRestoredWatchSender(env, owner.actor, owner.namespace, scope, now, fetcher),
	});
}
