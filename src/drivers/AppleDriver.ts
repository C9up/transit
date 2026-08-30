/**
 * Sign in with Apple.
 *
 * Apple speaks OpenID Connect, so most of this is the generic driver. Three
 * things differ, and each is a place implementations get caught:
 *
 *   - There is no client secret. Apple takes a short-lived JWT signed with the
 *     `.p8` private key from the developer account.
 *   - The callback arrives as a **POST**, not a redirect with a query string,
 *     because asking for a name or an address forces `response_mode=form_post`.
 *   - The name is sent **once**, in that first POST, and never again.
 *
 * Apple publishes no userinfo endpoint: everything there is comes from the
 * id_token.
 */

import { type AppleKey, appleClientSecret } from "../apple.js";
import type { TransitUser } from "../types.js";
import { OidcDriver } from "./OidcDriver.js";

export interface AppleConfig extends AppleKey {
	callbackUrl: string;
	/** Default `["name", "email"]`. */
	scopes?: string[];
	/** Extra parameters on the authorize URL. */
	authorizeParams?: Record<string, string>;
}

export class AppleDriver extends OidcDriver {
	constructor(config: AppleConfig) {
		super({
			issuer: "https://appleid.apple.com",
			clientId: config.clientId,
			clientSecret: () => appleClientSecret(config),
			callbackUrl: config.callbackUrl,
			scopes: config.scopes ?? ["name", "email"],
			authorizeParams: {
				// Apple refuses to send a name or an address back on a redirect,
				// so the callback route has to accept a POST.
				response_mode: "form_post",
				...config.authorizeParams,
			},
			// Apple has no userinfo endpoint; asking would be one failed request
			// per sign-in.
			userinfo: false,
		});
	}

	/**
	 * Apple sends `email_verified` and `is_private_email` as the strings
	 * `"true"` / `"false"`. Read as a boolean, a verified address reads as
	 * unverified — and an application that gates account linking on that would
	 * refuse every Apple sign-in.
	 */
	protected override mapUser(raw: Record<string, unknown>): TransitUser {
		const user = super.mapUser(raw);
		if (user.email === "") return user;
		return {
			...user,
			emailVerificationState: appleFlag(raw.email_verified)
				? "verified"
				: "unverified",
		};
	}
}

function appleFlag(value: unknown): boolean {
	return value === true || value === "true";
}
