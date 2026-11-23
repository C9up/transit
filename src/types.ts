/**
 * The shapes every provider answers with, whatever protocol it speaks.
 */

import { timingSafeEqual } from "node:crypto";
import type { AuthorizeCustomizer } from "./AuthorizeRequest.js";
import {
	E_OAUTH_MISSING_CODE,
	E_OAUTH_STATE_MISMATCH,
	E_TRANSIT_STATE_REQUIRED,
} from "./errors.js";
export interface OAuthConfig {
	clientId: string;
	clientSecret: string;
	callbackUrl: string;
	scopes?: string[];
	/**
	 * Extra parameters appended to the authorize URL — a provider's own knobs
	 * (`prompt`, `display`, `show_dialog`, `guild_id`, …) without a config type
	 * per provider. They are applied after the driver's own defaults, so this
	 * can also override one.
	 */
	authorizeParams?: Record<string, string>;
}

/**
 * Whether the provider vouches for the address it returned.
 *
 * This decides whether an application may link the sign-in to an existing
 * account by email. `"unverified"` means anyone able to type that address at
 * the provider now holds it — linking on that basis hands them the account.
 * `"unsupported"` means the provider says nothing either way, which is not the
 * same as saying yes.
 */
export type EmailVerificationState = "verified" | "unverified" | "unsupported";

export interface TransitUser {
	id: string;
	email: string;
	name: string;
	/** The handle the provider shows: a login, a username, a display name. */
	nickName?: string;
	avatarUrl?: string;
	/** Defaults to `"unsupported"` — the answer that assumes nothing. */
	emailVerificationState?: EmailVerificationState;
	raw: Record<string, unknown>;
}

export interface OAuthToken {
	accessToken: string;
	refreshToken?: string;
	expiresIn?: number;
	/**
	 * OAuth1 only: the secret every later call has to be signed with. An
	 * OAuth1 access token is useless without it.
	 */
	tokenSecret?: string;
}

/**
 * What a redirect needs the caller to keep until the user comes back.
 *
 * `state` is what the callback's own `state` must match. `secret` is present
 * for the providers that mint one at redirect time — a PKCE verifier, or an
 * OAuth1 request-token secret — and must be handed back to `callback()`.
 * Store both where you store a session, and pull them once.
 */
export interface RedirectRequest {
	url: string;
	state: string;
	secret?: string;
}

export interface TransitDriver {
	/**
	 * Where to send the user. `secret` is only read by providers that require
	 * PKCE, and those refuse to build a URL without it.
	 *
	 * A provider whose redirect needs a round trip of its own — OAuth1 — cannot
	 * answer here at all and throws; use {@link TransitDriver.begin}.
	 */
	redirectUrl(
		state?: string,
		secret?: string,
		customize?: AuthorizeCustomizer,
	): string;
	/**
	 * Where to send the user, plus whatever has to be kept until they come
	 * back. Works for every provider, including the ones `redirectUrl` cannot
	 * serve, so it is the path to reach for.
	 *
	 * `customize` adjusts the scopes and authorize parameters of this one
	 * redirect (OAuth2 and OpenID Connect providers; the others refuse it).
	 */
	begin?(
		state?: string,
		customize?: AuthorizeCustomizer,
	): Promise<RedirectRequest>;
	/**
	 * Handle the OAuth callback. `state` MUST be validated against the value
	 * originally passed to `redirectUrl()` to prevent CSRF login attacks.
	 * Throws if state is missing or mismatched.
	 *
	 * `secret` is the value stored alongside the state at redirect time — a
	 * PKCE verifier, or an OAuth1 request-token secret.
	 */
	callback(
		code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: TransitUser; token: OAuthToken }>;
	/**
	 * Read the profile behind a token already held, with no code to exchange.
	 * `tokenSecret` is required by OAuth1 providers and ignored by the rest.
	 * Optional: a driver that cannot do it simply does not offer it.
	 */
	userFromToken?(
		accessToken: string,
		tokenSecret?: string,
	): Promise<TransitUser>;
}

/**
 * A directory that verifies credentials, rather than a provider a browser is
 * sent to. LDAP and Active Directory are this shape: nothing is redirected,
 * the application asks and the directory answers.
 */
export interface DirectoryDriver {
	/** Verify a login, and answer with who the directory says this is. */
	authenticate(username: string, password: string): Promise<TransitUser>;
}

/** Either shape a configured provider can take. */
export type TransitEntry = TransitDriver | DirectoryDriver;

/** Whether an entry verifies credentials rather than redirecting. */
export function isDirectory(entry: TransitEntry): entry is DirectoryDriver {
	return (
		typeof Reflect.get(entry, "authenticate") === "function" &&
		typeof Reflect.get(entry, "callback") !== "function"
	);
}

/**
 * Refuse a callback that came back without its grant (`param` names the
 * request parameter that carries it) before anything is sent to the
 * provider. The provider sends none when the user denied access; exchanging
 * nothing would only come back as a provider error.
 */
export function assertOAuthCode(code: string | undefined, param: string): void {
	if (!code) throw new E_OAUTH_MISSING_CODE([param]);
}

/**
 * Check the OAuth `state` round-trip, failing CLOSED.
 *
 * The check used to be `if (expectedState && state !== expectedState)`, so a
 * caller that passed no expected state got NO CSRF protection and no sign that
 * it was missing. A driver used directly — without the manager, which already
 * refuses — was therefore open by default. Anything that cannot be verified is
 * refused instead.
 */
export function assertOAuthState(
	state: string | undefined,
	expectedState: string | undefined,
): void {
	if (!expectedState) {
		throw new E_TRANSIT_STATE_REQUIRED([
			"[transit] OAuth callback requires expectedState for CSRF protection. " +
				"Store the state given to redirectUrl() in the session and pass it here.",
		]);
	}
	if (state === undefined || !sameSecret(state, expectedState)) {
		throw new E_OAUTH_STATE_MISMATCH();
	}
}

/**
 * Compare two states without leaking where they diverge.
 *
 * `!==` on strings stops at the first differing byte, and the state is the only
 * thing standing between an attacker's authorization code and the victim's
 * session. The leak is small against network noise, but every other secret
 * comparison in the framework is already constant-time and this one is the
 * outlier.
 *
 * The lengths are checked first because `timingSafeEqual` throws when they
 * differ. A state's length is not the secret; its content is.
 */
function sameSecret(given: string, expected: string): boolean {
	const left = Buffer.from(given, "utf8");
	const right = Buffer.from(expected, "utf8");
	return left.length === right.length && timingSafeEqual(left, right);
}
