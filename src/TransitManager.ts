/**
 * The providers an application signs people in through, keyed by the names its
 * config chose.
 *
 *   const { url, state, secret } = await transit.begin('google')
 *   const { user } = await transit.callback('google', code, state, expected, secret)
 *
 * The key is the caller's: two entries may speak to the same provider with
 * different credentials, and `use(name)` asks for the key, not the protocol.
 */

import type {
	OAuthToken,
	RedirectRequest,
	TransitDriver,
	TransitUser,
} from "./types.js";

export class TransitManager {
	#drivers: Map<string, TransitDriver> = new Map();

	use(name: string): TransitDriver {
		const driver = this.#drivers.get(name);
		if (!driver)
			throw new Error(
				`OAuth driver '${name}' not registered. Available: ${[...this.#drivers.keys()].join(", ")}`,
			);
		return driver;
	}

	register(name: string, driver: TransitDriver): void {
		this.#drivers.set(name, driver);
	}

	/**
	 * Where to send the user, plus what to keep until they come back.
	 *
	 * This is the path that works for every provider: it mints the state,
	 * fetches a request token where the protocol needs one, and returns the
	 * secret to store when there is one.
	 */
	async begin(name: string, state?: string): Promise<RedirectRequest> {
		const driver = this.use(name);
		if (typeof driver.begin !== "function") {
			throw new Error(
				`[transit] The '${name}' driver does not support begin(); use redirect().`,
			);
		}
		return driver.begin(state);
	}

	/**
	 * Where to send the user, when the provider can say so offline. `secret`
	 * is only read by providers that require PKCE — mint one with
	 * `createCodeVerifier()` and store it beside the state.
	 *
	 * An OAuth1 provider cannot answer here; call {@link begin} instead.
	 */
	redirect(name: string, state?: string, secret?: string): string {
		return this.use(name).redirectUrl(state, secret);
	}

	/**
	 * Handle the OAuth callback. Pass `state` (from the query string) and
	 * `expectedState` (from the session, stored at redirect time) for CSRF
	 * protection. Omitting `expectedState` logs a security warning.
	 */
	async callback(
		name: string,
		code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: TransitUser; token: OAuthToken }> {
		if (!expectedState) {
			throw new Error(
				`[transit] OAuth callback for '${name}' requires expectedState for CSRF protection. ` +
					`Store the state from redirect() in the session and pass it here.`,
			);
		}
		return this.use(name).callback(code, state, expectedState, secret);
	}

	/**
	 * Read the profile behind a token already held, through the named provider.
	 * Throws when that driver has no way to — rather than answering with a
	 * profile it did not fetch.
	 */
	async userFromToken(
		name: string,
		accessToken: string,
		tokenSecret?: string,
	): Promise<TransitUser> {
		const driver = this.use(name);
		if (typeof driver.userFromToken !== "function") {
			throw new Error(
				`[transit] The '${name}' driver cannot read a profile from an existing token.`,
			);
		}
		return driver.userFromToken(accessToken, tokenSecret);
	}

	get registeredDrivers(): string[] {
		return [...this.#drivers.keys()];
	}
}
