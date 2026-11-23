/**
 * What one redirect asks the provider for: its scopes and extra authorize
 * parameters, adjusted per request.
 *
 *   await transit.begin('github', (request) => {
 *     request.scopes(['repo']).mergeScopes(['gist']).param('prompt', 'consent')
 *   })
 *
 * The builder a `begin()` / `redirect()` callback receives — upstream's
 * `RedirectRequest` (`scopes`, `mergeScopes`, `clearScopes`,
 * `transformScopes`, `param`, `clearParam`, `getParams`), for OAuth2 and
 * OpenID Connect providers. It starts from the configured scopes and
 * `authorizeParams`, so `mergeScopes` adds to them and `scopes` replaces them.
 *
 * Two named deviations:
 * - named `AuthorizeRequest`: `RedirectRequest` is already what `begin()`
 *   answers in this package (the URL, the state and the secret);
 * - the parameters that carry the flow's security — `state`, `nonce`, the PKCE
 *   challenge, `client_id`, `redirect_uri`, `response_type` — cannot be set or
 *   cleared here (better: upstream lets a callback overwrite the state it just
 *   set). Scopes go through the scope methods, not `param('scope', …)`.
 */

import { E_TRANSIT_PROTECTED_PARAMETER } from "./errors.js";

/** Adjusts one redirect. */
export type AuthorizeCustomizer = (request: AuthorizeRequest) => void;

/** The parameters the flow sets itself, after the callback has run. */
const PROTECTED = new Set([
	"state",
	"nonce",
	"code_challenge",
	"code_challenge_method",
	"client_id",
	"redirect_uri",
	"response_type",
]);

export class AuthorizeRequest {
	#scopes: string[];
	readonly #params: Map<string, string>;
	#transform: ((scopes: string[]) => string[]) | undefined;

	constructor(scopes: readonly string[], params: Record<string, string> = {}) {
		this.#scopes = [...scopes];
		this.#params = new Map(Object.entries(params));
	}

	/** Transform the scopes passed to {@link scopes} and {@link mergeScopes} from now on. */
	transformScopes(callback: (scopes: string[]) => string[]): this {
		this.#transform = callback;
		return this;
	}

	/** Ask for exactly these scopes, instead of the configured ones. */
	scopes(scopes: string[]): this {
		this.#scopes = this.#transformed(scopes);
		return this;
	}

	/** Ask for these scopes as well. */
	mergeScopes(scopes: string[]): this {
		for (const scope of this.#transformed(scopes)) {
			if (!this.#scopes.includes(scope)) this.#scopes.push(scope);
		}
		return this;
	}

	/** Ask for no scope (an OpenID Connect provider still gets `openid`). */
	clearScopes(): this {
		this.#scopes = [];
		return this;
	}

	/** Add, or replace, an authorize parameter for this redirect. */
	param(key: string, value: string | number | boolean): this {
		this.#assertOwnable(key);
		this.#params.set(key, String(value));
		return this;
	}

	/** Drop an authorize parameter, a configured one included. */
	clearParam(key: string): this {
		this.#assertOwnable(key);
		this.#params.delete(key);
		return this;
	}

	/** The scopes this redirect asks for. */
	getScopes(): string[] {
		return [...this.#scopes];
	}

	/** The parameters set so far, the flow's own excepted. */
	getParams(): Record<string, string> {
		return Object.fromEntries(this.#params);
	}

	#transformed(scopes: string[]): string[] {
		return this.#transform ? this.#transform([...scopes]) : [...scopes];
	}

	#assertOwnable(key: string): void {
		if (key === "scope") {
			throw new E_TRANSIT_PROTECTED_PARAMETER(
				key,
				"use scopes(), mergeScopes() or clearScopes()",
			);
		}
		if (PROTECTED.has(key)) {
			throw new E_TRANSIT_PROTECTED_PARAMETER(
				key,
				"the sign-in sets it, and the callback checks what it set",
			);
		}
	}
}

/** Run `customize`, if any, over the configured scopes and parameters. */
export function customizeAuthorize(
	scopes: readonly string[],
	params: Record<string, string>,
	customize: AuthorizeCustomizer | undefined,
): { scopes: string[]; params: Record<string, string> } {
	const request = new AuthorizeRequest(scopes, params);
	customize?.(request);
	return { scopes: request.getScopes(), params: request.getParams() };
}
