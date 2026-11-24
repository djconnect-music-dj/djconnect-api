import { createInstallationSurfaceEnrol, installationEnrolPath } from "./installation-surface-enrol";
import type { AppEnv } from "../types";
import { createInstallationPublisher, installationPrefix } from "./installation-publisher";
import { createInstallationFirstKey } from "./installation-first-key";
import { installationNativePolicy } from "./installation-policy";
import { isWidgetFirstKeyRoute } from "./first-key-service";

const origin = "https://api.djconnect.dev";
/** Authenticated own-installation publication, with separate native first trust.
 * No request/config flag selects a principal, signing policy or native grant.
 */
export function dispatchNativeInstallationRequest(request: Request, env: unknown): Promise<Response> | undefined {
 const path = new URL(request.url).pathname;
 const installation = path === installationPrefix.slice(0, -1) || path.startsWith(installationPrefix);
 if (!installation && !isWidgetFirstKeyRoute(path) && path !== "/v1/push/native/key/retire") return undefined;
 const selected = env as AppEnv;
 const db = selected.DB;
 const current = () => selected.DB === db;
 if (path === installationEnrolPath) return createInstallationSurfaceEnrol(selected, current)(request);
 return installation ? createInstallationPublisher(db, origin, current)(request) :
  createInstallationFirstKey(db, origin, current, installationNativePolicy)(request);
}
