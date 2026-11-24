/**
 * Transit's errors, one per code, namespaced `E_TRANSIT_` — except the OAuth
 * errors a client sees, which keep their upstream codes (`E_OAUTH_*`). A
 * caller branches on `error.code` or on `error instanceof errors.E_*`.
 *
 * A directory's refusal is an `E_TRANSIT_LDAP_ERROR`, whose `resultCode` is
 * the LDAP result code the directory answered with (49 for invalid
 * credentials). A message too irregular for one template takes `%s`, with the
 * text built where the error is thrown.
 */

import {
	createError,
	Exception,
	type ExceptionOptions,
	format,
} from "@c9up/flare";

/**
 * What {@link HttpResponseException.handle} reads from the request's context.
 * Structural, so transit depends on no host: the session, the redirect
 * builder and the translator are read when the host has them.
 */
export interface TransitErrorContext {
	request: {
		/** Content negotiation: the first of `types` the client accepts. */
		accepts?<T extends string>(types: T[]): T | null;
	};
	response: {
		status(code: number): unknown;
		send(body: unknown): unknown;
	};
}

function isObject(value: unknown): value is object {
	return typeof value === "object" && value !== null;
}

/** The formats an error is rendered in, in upstream's order. */
const RESPONSE_FORMATS = ["html", "application/vnd.api+json", "json"];

/**
 * An error a client sees, rendered by itself: a flash and a redirect back for
 * a browser with a session, the message as text without one, `{ errors:
 * [{ message }] }` for JSON, a JSON:API error object for JSON:API.
 */
export class HttpResponseException extends Exception {
	/** The translation key of the message (`ctx.i18n.t`). */
	readonly identifier: string = "";

	/** The message, translated through `ctx.i18n` when the request has one. */
	getResponseMessage(error: HttpResponseException, ctx: object): string {
		const i18n: unknown = Reflect.get(ctx, "i18n");
		const t: unknown = isObject(i18n) ? Reflect.get(i18n, "t") : undefined;
		if (!isObject(i18n) || typeof t !== "function") return error.message;
		const translated: unknown = Reflect.apply(t, i18n, [
			error.identifier,
			{},
			error.message,
		]);
		return typeof translated === "string" ? translated : error.message;
	}

	async handle(
		error: HttpResponseException,
		ctx: TransitErrorContext,
	): Promise<void> {
		const message = this.getResponseMessage(error, ctx);
		const format =
			typeof ctx.request.accepts === "function"
				? ctx.request.accepts(RESPONSE_FORMATS)
				: null;
		if (format === "json") {
			ctx.response.status(error.status);
			ctx.response.send({ errors: [{ message }] });
			return;
		}
		if (format === "application/vnd.api+json") {
			ctx.response.status(error.status);
			ctx.response.send({ errors: [{ code: error.code, title: message }] });
			return;
		}
		const session: unknown = Reflect.get(ctx, "session");
		const redirect: unknown = Reflect.get(ctx.response, "redirect");
		if (isObject(session) && typeof redirect === "function") {
			const flash: unknown = Reflect.get(session, "flash");
			const flashErrors: unknown = Reflect.get(session, "flashErrors");
			if (typeof flash === "function") {
				Reflect.apply(flash, session, ["error", message]);
			}
			if (typeof flashErrors === "function") {
				Reflect.apply(flashErrors, session, [
					{ [error.code ?? "E_UNKNOWN"]: message },
				]);
			}
			const builder: unknown = Reflect.apply(redirect, ctx.response, []);
			const back: unknown = isObject(builder)
				? Reflect.get(builder, "back")
				: undefined;
			if (isObject(builder) && typeof back === "function") {
				Reflect.apply(back, builder, []);
				return;
			}
		}
		ctx.response.status(error.status);
		ctx.response.send(message);
	}
}

/**
 * The callback came back without the parameter carrying the grant: `code`
 * (OAuth2, OpenID Connect), `oauth_verifier` (OAuth1), `SAMLResponse` (SAML).
 * The provider sends none when the user denied access.
 */
export class E_OAUTH_MISSING_CODE extends HttpResponseException {
	static override status = 500;
	static override code = "E_OAUTH_MISSING_CODE";
	override readonly identifier = "errors.E_OAUTH_MISSING_CODE";

	constructor(args: [string], options?: ErrorOptions) {
		super(
			format(
				'Cannot request access token. Redirect request is missing the "%s" param',
				args,
			),
			options,
		);
	}
}

/**
 * The callback's state is missing or differs from the stored one (possible
 * CSRF).
 */
export class E_OAUTH_STATE_MISMATCH extends HttpResponseException {
	static override status = 400;
	static override code = "E_OAUTH_STATE_MISMATCH";
	static override message = "Unable to verify re-redirect state";
	override readonly identifier = "errors.E_OAUTH_STATE_MISMATCH";
}

/**
 * No provider of this name is registered: 404, with upstream's message. It
 * names the provider asked for and nothing else, never the list of the
 * registered ones.
 *
 * DEVIATION (named): upstream's code is `E_UNKNOWN_ALLY_PROVIDER`, which
 * carries upstream's product name; the code (and its translation key) are
 * transit's own.
 */
export class E_TRANSIT_UNKNOWN_PROVIDER extends HttpResponseException {
	static override status = 404;
	static override code = "E_TRANSIT_UNKNOWN_PROVIDER";
	override readonly identifier = "errors.E_TRANSIT_UNKNOWN_PROVIDER";

	constructor(args: [string], options?: ErrorOptions) {
		super(format('Unknown authentication provider "%s"', args), options);
	}
}

/** `begin()` on a driver that has no `begin()`. */
export const E_TRANSIT_BEGIN_UNSUPPORTED = createError<[unknown]>(
	"[transit] The '%s' driver does not support begin(); use redirect().",
	"E_TRANSIT_BEGIN_UNSUPPORTED",
);

/** An OAuth1 provider did not confirm the callback URL. */
export const E_TRANSIT_CALLBACK_NOT_CONFIRMED = createError<[unknown, unknown]>(
	"%s did not confirm the callback URL — check that '%s' is registered on the application.",
	"E_TRANSIT_CALLBACK_NOT_CONFIRMED",
);

/** OpenID Connect discovery answered an HTTP error. */
export const E_TRANSIT_DISCOVERY_FAILED = createError<[unknown, unknown]>(
	"[transit] OpenID Connect discovery failed for '%s' (HTTP %s)",
	"E_TRANSIT_DISCOVERY_FAILED",
);

/**
 * A `FakeTransit` assertion (`assertBegan`, `assertSignedIn`,
 * `assertNobodySignedIn`) failed.
 */
export const E_TRANSIT_FAKE_ASSERTION = createError<[message: string]>(
	"%s",
	"E_TRANSIT_FAKE_ASSERTION",
);

/** `FakeTransit` was asked for a provider no `willReturn()` declared. */
export const E_TRANSIT_FAKE_NOT_DECLARED = createError<[message: string]>(
	"%s",
	"E_TRANSIT_FAKE_NOT_DECLARED",
);

/** The quasar connection lacks a command the replay store issues. */
export const E_TRANSIT_INCOMPLETE_CONNECTION = createError<[message: string]>(
	"%s",
	"E_TRANSIT_INCOMPLETE_CONNECTION",
);

/**
 * An OpenID Connect issuer is not an `https` URL. Discovery, the signing keys
 * and the token exchange would travel in the clear, where whoever sits on the
 * path can answer them. `http://localhost` is accepted, for development.
 */
export const E_TRANSIT_INSECURE_ISSUER = createError<[issuer: unknown]>(
	"[transit] the OpenID Connect issuer '%s' is not an https URL — only http://localhost is accepted without TLS",
	"E_TRANSIT_INSECURE_ISSUER",
);

/**
 * The discovery document lacks a required field, names another issuer, or
 * gives an endpoint that is not `https`.
 */
export const E_TRANSIT_INVALID_DISCOVERY = createError<[message: string]>(
	"%s",
	"E_TRANSIT_INVALID_DISCOVERY",
);

/**
 * The id_token is refused: malformed, bad signature or algorithm, wrong
 * issuer, audience or nonce, expired.
 */
export const E_TRANSIT_INVALID_ID_TOKEN = createError<[message: string]>(
	"%s",
	"E_TRANSIT_INVALID_ID_TOKEN",
);

/** A provider's response is not JSON, or not a JSON object. */
export const E_TRANSIT_INVALID_RESPONSE = createError<[message: string]>(
	"%s",
	"E_TRANSIT_INVALID_RESPONSE",
);

/** Fetching the provider's JWKS failed, or it has no `keys` array. */
export const E_TRANSIT_JWKS_FAILED = createError<[message: string]>(
	"%s",
	"E_TRANSIT_JWKS_FAILED",
);

/**
 * A flow lacks the secret it needs: the `secret` `begin()` returned (PKCE
 * verifier, OAuth1 request-token secret), or the token secret an OAuth1
 * access token signs with.
 */
export const E_TRANSIT_MISSING_SECRET = createError<[message: string]>(
	"%s",
	"E_TRANSIT_MISSING_SECRET",
);

/**
 * `directory()` / `authenticate()` named a redirect provider; call
 * `begin()`.
 */
export const E_TRANSIT_NOT_A_DIRECTORY = createError<[unknown, unknown]>(
	"[transit] '%s' is a redirect provider, not a directory. Use begin('%s').",
	"E_TRANSIT_NOT_A_DIRECTORY",
);

/** `use()` / `begin()` named a directory (LDAP); call `authenticate()`. */
export const E_TRANSIT_NOT_A_REDIRECT_PROVIDER = createError<
	[unknown, unknown]
>(
	"[transit] '%s' is a directory: it verifies credentials rather than redirecting. Use authenticate('%s', …).",
	"E_TRANSIT_NOT_A_REDIRECT_PROVIDER",
);

/**
 * `@c9up/transit/services/main` was read before the provider booted, or
 * before `setTransit()`.
 */
export const E_TRANSIT_NOT_BOOTED = createError(
	"[transit] accessed before initialization — register TransitProvider, or call setTransit() yourself.",
	"E_TRANSIT_NOT_BOOTED",
);

/** The token response carries no access token. */
export const E_TRANSIT_NO_ACCESS_TOKEN = createError<[message: string]>(
	"%s",
	"E_TRANSIT_NO_ACCESS_TOKEN",
);

/**
 * A customizer was passed to an OAuth1 or SAML sign-in, which has no
 * per-request scopes or parameters.
 */
export const E_TRANSIT_NO_AUTHORIZE_PARAMS = createError<[message: string]>(
	"%s",
	"E_TRANSIT_NO_AUTHORIZE_PARAMS",
);

/**
 * LinkedIn returned no email address; the application needs the
 * `r_emailaddress` scope.
 */
export const E_TRANSIT_NO_EMAIL = createError(
	"LinkedIn returned no email address — the application needs the 'r_emailaddress' scope.",
	"E_TRANSIT_NO_EMAIL",
);

/**
 * The token response carries no id_token; check that the `openid` scope is
 * granted.
 */
export const E_TRANSIT_NO_ID_TOKEN = createError(
	"[transit] the provider returned no id_token — check that the 'openid' scope is granted",
	"E_TRANSIT_NO_ID_TOKEN",
);

/** An OAuth1 provider answered without a request token. */
export const E_TRANSIT_NO_REQUEST_TOKEN = createError<[unknown]>(
	"%s OAuth: no request token in the response",
	"E_TRANSIT_NO_REQUEST_TOKEN",
);

/**
 * A profile was asked from a token alone and the provider publishes no
 * userinfo endpoint.
 */
export const E_TRANSIT_NO_USERINFO_ENDPOINT = createError<[unknown]>(
	"[transit] '%s' publishes no userinfo endpoint, so a profile cannot be read from a token alone.",
	"E_TRANSIT_NO_USERINFO_ENDPOINT",
);

/** A provider that requires PKCE got no code verifier. */
export const E_TRANSIT_PKCE_REQUIRED = createError<[message: string]>(
	"%s",
	"E_TRANSIT_PKCE_REQUIRED",
);

/** The provider's profile or userinfo endpoint answered an HTTP error. */
export const E_TRANSIT_PROFILE_REQUEST_FAILED = createError<[message: string]>(
	"%s",
	"E_TRANSIT_PROFILE_REQUEST_FAILED",
);

/**
 * A Redis replay store names a quasar connection and `@c9up/quasar` is not
 * installed, or its provider has not booted.
 */
export const E_TRANSIT_QUASAR_MISSING = createError<[message: string]>(
	"%s",
	"E_TRANSIT_QUASAR_MISSING",
);

/** A callback ran without `expectedState`. */
export const E_TRANSIT_STATE_REQUIRED = createError<[message: string]>(
	"%s",
	"E_TRANSIT_STATE_REQUIRED",
);

/** The provider's token endpoint answered an HTTP error. */
export const E_TRANSIT_TOKEN_EXCHANGE_FAILED = createError<[message: string]>(
	"%s",
	"E_TRANSIT_TOKEN_EXCHANGE_FAILED",
);

/**
 * `userFromToken()` on a driver that cannot read a profile from a token.
 */
export const E_TRANSIT_TOKEN_PROFILE_UNSUPPORTED = createError<[unknown]>(
	"[transit] The '%s' driver cannot read a profile from an existing token.",
	"E_TRANSIT_TOKEN_PROFILE_UNSUPPORTED",
);

/** The id_token names a signing key the provider did not publish. */
export const E_TRANSIT_UNKNOWN_SIGNING_KEY = createError<[unknown]>(
	"[transit] id_token names a signing key ('%s') the provider did not publish",
	"E_TRANSIT_UNKNOWN_SIGNING_KEY",
);

/**
 * The provider declares only id_token algorithms transit refuses (asymmetric
 * signatures are required).
 */
export const E_TRANSIT_UNSUPPORTED_ALGORITHM = createError<[unknown, unknown]>(
	"[transit] '%s' signs id_tokens only with algorithms Transit refuses (%s). Asymmetric signatures are required.",
	"E_TRANSIT_UNSUPPORTED_ALGORITHM",
);

/** The userinfo response describes another subject than the id_token. */
export const E_TRANSIT_USERINFO_MISMATCH = createError(
	"[transit] the userinfo response describes a different subject than the id_token",
	"E_TRANSIT_USERINFO_MISMATCH",
);

/**
 * `redirectUrl()` on a provider whose redirect needs a round trip (OAuth1,
 * OpenID Connect, SAML); call `begin()`.
 */
export const E_TRANSIT_USE_BEGIN = createError<[message: string]>(
	"%s",
	"E_TRANSIT_USE_BEGIN",
);

/** An XML document transit refuses to read: malformed, or past its limits. */
export const E_TRANSIT_INVALID_XML = createError<[message: string]>(
	"[transit] %s",
	"E_TRANSIT_INVALID_XML",
);

/** An LDAP message that does not encode or decode as BER. */
export const E_TRANSIT_INVALID_BER = createError<[message: string]>(
	"[transit] %s",
	"E_TRANSIT_INVALID_BER",
);

/** An XML signature transit refuses: missing, malformed or not verifying. */
export const E_TRANSIT_INVALID_SIGNATURE = createError<[message: string]>(
	"[transit] %s",
	"E_TRANSIT_INVALID_SIGNATURE",
);

/** A SAML response or assertion refused. */
export const E_TRANSIT_SAML_REJECTED = createError<[message: string]>(
	"[transit] %s",
	"E_TRANSIT_SAML_REJECTED",
);

/** A parameter an authorize callback tried to set that the flow owns. */
export class E_TRANSIT_PROTECTED_PARAMETER extends Exception {
	static override code = "E_TRANSIT_PROTECTED_PARAMETER";

	/** The parameter the callback tried to set. */
	readonly parameter: string;

	constructor(parameter: string, reason: string) {
		super(
			`[transit] the authorize parameter '${parameter}' cannot be changed per request: ${reason}.`,
		);
		this.parameter = parameter;
	}
}

/**
 * A directory refused, or could not be reached. `resultCode` is the LDAP
 * result code the directory answered with, when it answered one (49 for
 * invalid credentials, which maps to status 400).
 */
export class E_TRANSIT_LDAP_ERROR extends Exception {
	static override code = "E_TRANSIT_LDAP_ERROR";

	/** The directory's LDAP result code, when it answered one. */
	readonly resultCode: number | undefined;

	constructor(
		message: string,
		resultCode?: number,
		options?: ExceptionOptions,
	) {
		super(`[transit] ${message}`, {
			...options,
			status:
				options?.status ??
				(resultCode === INVALID_CREDENTIALS ? 400 : undefined),
		});
		this.resultCode = resultCode;
	}
}

/** The LDAP result code of a refused bind: the password or the login is wrong. */
const INVALID_CREDENTIALS = 49;
