/**
 * Generic OpenID Connect.
 *
 * One driver for every provider that conforms: Keycloak, Auth0, Okta,
 * Entra ID, Authentik, Zitadel, Ping, Google. It is given an issuer and reads
 * the rest — endpoints, keys, supported algorithms — from what the provider
 * publishes about itself.
 *
 * What separates this from a plain OAuth2 driver is that the answer is a
 * SIGNED STATEMENT about who the user is, not just a token to go ask with.
 * That statement is only worth anything once it has been verified, which is
 * what `jwt.ts` does and what most of this class exists to feed.
 */

import { randomUUID } from "node:crypto";
import {
	assertIdTokenClaims,
	decodeJws,
	type IdTokenClaims,
	isSupportedAlg,
	type SupportedAlg,
	verifyJwsSignature,
} from "../jwt.js";
import { challengeFor, createCodeVerifier } from "../Oauth2Driver.js";
import {
	JwksCache,
	OidcDiscovery,
	type OidcMetadata,
	type RemoteOptions,
} from "../oidc.js";
import type {
	OAuthToken,
	RedirectRequest,
	TransitDriver,
	TransitUser,
} from "../types.js";
import { assertOAuthState } from "../types.js";

export interface OidcConfig {
	/** The provider's issuer URL, exactly as it appears in its tokens. */
	issuer: string;
	clientId: string;
	/**
	 * The client secret, or something that mints one. Apple has no static
	 * secret — it expects a short-lived JWT signed with a private key — so this
	 * is resolved at each token request rather than read once.
	 */
	clientSecret: string | (() => string | Promise<string>);
	callbackUrl: string;
	/** Default `["openid", "profile", "email"]`. `openid` is added if omitted. */
	scopes?: string[];
	/** Extra parameters on the authorize URL — `prompt`, `login_hint`, `acr_values`. */
	authorizeParams?: Record<string, string>;
	/**
	 * Also call the userinfo endpoint, when the provider advertises one.
	 * Default `true`: the id_token often carries only the subject.
	 */
	userinfo?: boolean;
	/** Tolerance for clock drift against the provider, in seconds. Default 60. */
	leewaySeconds?: number;
	/** Cache tuning for the discovery document and the signing keys. */
	cache?: RemoteOptions;
}

/**
 * `secret` carries two values here — the PKCE verifier and the nonce — and the
 * caller only has to store it and hand it back. Joined by a dot, which the
 * base64url alphabet does not contain, so neither half can forge a boundary.
 */
const SECRET_SEPARATOR = ".";

export class OidcDriver implements TransitDriver {
	readonly #config: OidcConfig;
	readonly #discovery: OidcDiscovery;
	readonly #jwks: JwksCache;

	constructor(config: OidcConfig) {
		this.#config = config;
		this.#discovery = new OidcDiscovery(config.issuer, config.cache);
		this.#jwks = new JwksCache(config.cache);
	}

	/**
	 * The endpoints are only known once the provider has been asked, so there
	 * is nothing to build offline.
	 */
	redirectUrl(): string {
		throw new Error(
			"[transit] an OpenID Connect provider publishes its endpoints, so the redirect is fetched. Use begin() instead of redirect().",
		);
	}

	async begin(state: string = randomUUID()): Promise<RedirectRequest> {
		const metadata = await this.#discovery.metadata();
		const verifier = createCodeVerifier();
		const nonce = randomUUID();

		const params = new URLSearchParams({
			client_id: this.#config.clientId,
			redirect_uri: this.#config.callbackUrl,
			response_type: "code",
			scope: this.#scopes().join(" "),
			state,
			nonce,
			...this.#config.authorizeParams,
		});

		// PKCE is not optional for a public client and costs nothing for a
		// confidential one, so it is always sent when the provider takes it.
		if (metadata.code_challenge_methods_supported?.includes("S256") !== false) {
			params.set("code_challenge", challengeFor(verifier));
			params.set("code_challenge_method", "S256");
		}

		return {
			url: `${metadata.authorization_endpoint}?${params}`,
			state,
			secret: `${verifier}${SECRET_SEPARATOR}${nonce}`,
		};
	}

	async callback(
		code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: TransitUser; token: OAuthToken }> {
		assertOAuthState(state, expectedState);
		const { verifier, nonce } = splitSecret(secret);

		const metadata = await this.#discovery.metadata();
		const tokens = await this.#exchange(metadata, code, verifier);

		const idToken = tokens.id_token;
		if (typeof idToken !== "string" || idToken === "") {
			throw new Error(
				"[transit] the provider returned no id_token — check that the 'openid' scope is granted",
			);
		}
		const claims = await this.#verifyIdToken(metadata, idToken, nonce);

		const accessToken = String(tokens.access_token ?? "");
		const profile = await this.#profile(metadata, accessToken, claims);

		return {
			user: this.mapUser(profile),
			token: {
				accessToken,
				...(typeof tokens.refresh_token === "string"
					? { refreshToken: tokens.refresh_token }
					: {}),
				...(typeof tokens.expires_in === "number"
					? { expiresIn: tokens.expires_in }
					: {}),
			},
		};
	}

	/** Read a profile behind a token already held, through the userinfo endpoint. */
	async userFromToken(accessToken: string): Promise<TransitUser> {
		const metadata = await this.#discovery.metadata();
		if (!metadata.userinfo_endpoint) {
			throw new Error(
				`[transit] '${this.#config.issuer}' publishes no userinfo endpoint, so a profile cannot be read from a token alone.`,
			);
		}
		return this.mapUser(
			await this.#userinfo(metadata.userinfo_endpoint, accessToken),
		);
	}

	/**
	 * Turn the claims into the shape every driver answers with. A provider that
	 * spells a standard claim its own way overrides this.
	 */
	protected mapUser(raw: Record<string, unknown>): TransitUser {
		return mapOidcUser(raw);
	}

	/** The secret for one token request. */
	async #clientSecret(): Promise<string> {
		const secret = this.#config.clientSecret;
		return typeof secret === "function" ? await secret() : secret;
	}

	#scopes(): string[] {
		const scopes = [...(this.#config.scopes ?? ["openid", "profile", "email"])];
		// Without `openid` the provider runs a plain OAuth2 flow and returns no
		// id_token, which fails later with a much less obvious message.
		if (!scopes.includes("openid")) scopes.unshift("openid");
		return scopes;
	}

	async #exchange(
		metadata: OidcMetadata,
		code: string,
		verifier: string,
	): Promise<Record<string, unknown>> {
		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: this.#config.callbackUrl,
			client_id: this.#config.clientId,
			client_secret: await this.#clientSecret(),
			code_verifier: verifier,
		});
		const response = await fetch(metadata.token_endpoint, {
			method: "POST",
			headers: {
				Accept: "application/json",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body,
		});
		if (!response.ok) {
			throw new Error(
				`[transit] OpenID Connect token exchange failed (HTTP ${response.status})`,
			);
		}
		return (await response.json()) as Record<string, unknown>;
	}

	/**
	 * The signature first, then every claim. The algorithm comes from what the
	 * provider declared it signs with, intersected with what can be verified —
	 * never from the token's own header.
	 */
	async #verifyIdToken(
		metadata: OidcMetadata,
		idToken: string,
		nonce: string,
	): Promise<IdTokenClaims> {
		const parts = decodeJws(idToken);
		const alg = this.#algorithmFor(metadata, parts.header.alg);
		const kid =
			typeof parts.header.kid === "string" ? parts.header.kid : undefined;

		const key = await this.#jwks.key(metadata.jwks_uri, kid);
		if (!verifyJwsSignature(parts, key, alg)) {
			throw new Error("[transit] id_token signature does not verify");
		}

		return assertIdTokenClaims(parts.payload, {
			issuer: metadata.issuer,
			audience: this.#config.clientId,
			nonce,
			leewaySeconds: this.#config.leewaySeconds,
		});
	}

	/**
	 * Which algorithm to verify with.
	 *
	 * The header's value is used only to CHOOSE among what the provider says it
	 * signs with; it can never introduce one that was not declared, and it can
	 * never select a family this refuses.
	 */
	#algorithmFor(metadata: OidcMetadata, headerAlg: unknown): SupportedAlg {
		// Every conforming provider supports RS256 and publishes the list; the
		// narrow reading when it does not is that RS256 is all there is.
		const declared = metadata.id_token_signing_alg_values_supported ?? [
			"RS256",
		];
		const allowed = declared.filter(isSupportedAlg);
		if (allowed.length === 0) {
			throw new Error(
				`[transit] '${this.#config.issuer}' signs id_tokens only with algorithms Transit refuses (${declared.join(", ")}). Asymmetric signatures are required.`,
			);
		}
		if (!isSupportedAlg(headerAlg)) {
			throw new Error(
				`[transit] id_token announces '${String(headerAlg)}', which Transit does not verify — only asymmetric signatures are accepted`,
			);
		}
		if (!allowed.includes(headerAlg)) {
			throw new Error(
				`[transit] id_token announces '${headerAlg}', which '${this.#config.issuer}' did not declare it signs with`,
			);
		}
		// The header only ever SELECTS from the set computed above. It cannot
		// introduce an algorithm, which is what keeps `none` and the
		// shared-secret families away from the verifier entirely.
		return headerAlg;
	}

	/**
	 * The claims, plus userinfo when there is one. The subject must be the same
	 * in both: a userinfo response describing another user is a substituted
	 * token, not a richer profile.
	 */
	async #profile(
		metadata: OidcMetadata,
		accessToken: string,
		claims: IdTokenClaims,
	): Promise<Record<string, unknown>> {
		if (
			this.#config.userinfo === false ||
			!metadata.userinfo_endpoint ||
			accessToken === ""
		) {
			return claims as unknown as Record<string, unknown>;
		}
		const info = await this.#userinfo(metadata.userinfo_endpoint, accessToken);
		if (info.sub !== claims.sub) {
			throw new Error(
				"[transit] the userinfo response describes a different subject than the id_token",
			);
		}
		return { ...(claims as unknown as Record<string, unknown>), ...info };
	}

	async #userinfo(
		endpoint: string,
		accessToken: string,
	): Promise<Record<string, unknown>> {
		const response = await fetch(endpoint, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: "application/json",
			},
		});
		if (!response.ok) {
			throw new Error(
				`[transit] OpenID Connect userinfo request failed (HTTP ${response.status})`,
			);
		}
		return (await response.json()) as Record<string, unknown>;
	}
}

/** Standard OpenID Connect claims, in the shape every driver answers with. */
export function mapOidcUser(raw: Record<string, unknown>): TransitUser {
	const given = str(raw, "given_name");
	const family = str(raw, "family_name");
	const email = str(raw, "email");
	return {
		id: String(raw.sub ?? ""),
		email: email ?? "",
		name: str(raw, "name") ?? [given, family].filter(Boolean).join(" "),
		nickName: str(raw, "preferred_username") ?? given,
		avatarUrl: str(raw, "picture"),
		emailVerificationState:
			email === undefined
				? "unsupported"
				: raw.email_verified === true
					? "verified"
					: "unverified",
		raw,
	};
}

function str(raw: Record<string, unknown>, key: string): string | undefined {
	const value = raw[key];
	return typeof value === "string" && value !== "" ? value : undefined;
}

/** Split the value `begin()` asked the caller to keep. */
function splitSecret(secret: string | undefined): {
	verifier: string;
	nonce: string;
} {
	const index = secret?.indexOf(SECRET_SEPARATOR) ?? -1;
	if (secret === undefined || index <= 0) {
		throw new Error(
			"[transit] OpenID Connect needs the value begin() returned as `secret` — store it with the state and pass it back here.",
		);
	}
	return {
		verifier: secret.slice(0, index),
		nonce: secret.slice(index + SECRET_SEPARATOR.length),
	};
}
