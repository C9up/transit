/**
 * The two documents an OpenID Connect provider publishes about itself: where
 * its endpoints are, and which keys it signs with.
 *
 * Both are cached, and both are refetched on a rule rather than on demand.
 * Keys rotate, so a cache that never refreshes locks an application out at
 * the worst moment; a cache that refreshes whenever a token names an unknown
 * key hands anyone a way to make this application hammer the provider. The
 * middle is a rate limit.
 */

import { fetchWithTimeout } from "./httpTimeout.js";
import { readJsonObject } from "./json.js";
import type { Jwk } from "./jwt.js";

/** The slice of the discovery document this reads. */
export interface OidcMetadata {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	userinfo_endpoint?: string;
	id_token_signing_alg_values_supported?: string[];
	code_challenge_methods_supported?: string[];
}

export interface RemoteOptions {
	/** How long a fetched document is trusted, in milliseconds. Default 1 hour. */
	ttlMs?: number;
	/** Shortest interval between two key refetches. Default 5 minutes. */
	minRefetchMs?: number;
	/** Injected in tests. */
	now?: () => number;
}

const DEFAULT_TTL_MS = 3_600_000;
const DEFAULT_MIN_REFETCH_MS = 300_000;

/**
 * Reads and caches `/.well-known/openid-configuration`.
 *
 * The document's own `issuer` is checked against the configured one. They are
 * allowed to differ in the specification's letter about as much as a passport
 * is allowed to name someone else: a mismatch means the URL that was asked is
 * not the authority that answered.
 */
export class OidcDiscovery {
	readonly #issuer: string;
	readonly #ttlMs: number;
	readonly #now: () => number;
	#cached: { metadata: OidcMetadata; fetchedAt: number } | undefined;
	#inFlight: Promise<OidcMetadata> | undefined;

	constructor(issuer: string, options: RemoteOptions = {}) {
		// Kept byte for byte: the discovery document's `issuer` and every
		// id_token's `iss` must be IDENTICAL to it (OpenID Connect Discovery
		// §4.3), and some providers' issuers end with a slash (Auth0's do).
		this.#issuer = issuer;
		this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
		this.#now = options.now ?? Date.now;
	}

	get issuer(): string {
		return this.#issuer;
	}

	get url(): string {
		// Only the well-known URL drops the trailing slash, so it is joined
		// without a double one.
		return `${this.#issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
	}

	async metadata(): Promise<OidcMetadata> {
		const cached = this.#cached;
		if (cached && this.#now() - cached.fetchedAt < this.#ttlMs) {
			return cached.metadata;
		}
		// One fetch at a time: a burst of sign-ins on a cold cache would
		// otherwise open one request per sign-in.
		this.#inFlight ??= this.#fetch().finally(() => {
			this.#inFlight = undefined;
		});
		return this.#inFlight;
	}

	async #fetch(): Promise<OidcMetadata> {
		const response = await fetchWithTimeout(this.url, {
			headers: { Accept: "application/json" },
		});
		if (!response.ok) {
			throw new Error(
				`[transit] OpenID Connect discovery failed for '${this.#issuer}' (HTTP ${response.status})`,
			);
		}
		const body = await readJsonObject(
			response,
			`the discovery document of '${this.#issuer}'`,
		);
		const metadata = assertMetadata(body, this.#issuer);
		this.#cached = { metadata, fetchedAt: this.#now() };
		return metadata;
	}
}

/**
 * Reads and caches a provider's signing keys, and knows when it is allowed to
 * look again.
 */
export class JwksCache {
	readonly #minRefetchMs: number;
	readonly #now: () => number;
	#keys: Jwk[] = [];
	#fetchedAt = 0;
	#inFlight: Promise<Jwk[]> | undefined;

	constructor(options: RemoteOptions = {}) {
		this.#minRefetchMs = options.minRefetchMs ?? DEFAULT_MIN_REFETCH_MS;
		this.#now = options.now ?? Date.now;
	}

	/**
	 * The key a token names.
	 *
	 * A `kid` that is not held triggers at most one refetch per interval — that
	 * is how a rotated key is picked up, and how a stream of tokens naming
	 * invented keys stays cheap.
	 */
	async key(uri: string, kid: string | undefined): Promise<Jwk> {
		const found = this.#find(kid);
		if (found) return found;

		if (
			this.#keys.length > 0 &&
			this.#now() - this.#fetchedAt < this.#minRefetchMs
		) {
			throw new Error(
				`[transit] id_token names a signing key ('${kid ?? "no kid"}') the provider did not publish`,
			);
		}

		await this.#fetchKeys(uri);
		const refreshed = this.#find(kid);
		if (!refreshed) {
			throw new Error(
				`[transit] id_token names a signing key ('${kid ?? "no kid"}') the provider did not publish`,
			);
		}
		return refreshed;
	}

	#find(kid: string | undefined): Jwk | undefined {
		const usable = this.#keys.filter(
			(jwk) => jwk.use === undefined || jwk.use === "sig",
		);
		if (kid !== undefined) return usable.find((jwk) => jwk.kid === kid);
		// No `kid` is only unambiguous when the provider publishes one key.
		return usable.length === 1 ? usable[0] : undefined;
	}

	async #fetchKeys(uri: string): Promise<Jwk[]> {
		this.#inFlight ??= this.#fetchOnce(uri).finally(() => {
			this.#inFlight = undefined;
		});
		return this.#inFlight;
	}

	async #fetchOnce(uri: string): Promise<Jwk[]> {
		const response = await fetchWithTimeout(uri, {
			headers: { Accept: "application/json" },
		});
		if (!response.ok) {
			throw new Error(
				`[transit] fetching the provider's signing keys failed (HTTP ${response.status})`,
			);
		}
		const { keys } = await readJsonObject(response, "the provider's JWKS");
		if (!Array.isArray(keys)) {
			throw new Error("[transit] the provider's JWKS has no `keys` array");
		}
		this.#keys = keys.filter(isJwk);
		this.#fetchedAt = this.#now();
		return this.#keys;
	}
}

function isJwk(value: unknown): value is Jwk {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "kty") === "string"
	);
}

function assertMetadata(
	body: Record<string, unknown>,
	expectedIssuer: string,
): OidcMetadata {
	const required = (field: string): string => {
		const value = body[field];
		if (typeof value !== "string" || value === "") {
			throw new Error(
				`[transit] the discovery document of '${expectedIssuer}' has no ${field}`,
			);
		}
		return value;
	};
	const issuer = required("issuer");
	const authorizationEndpoint = required("authorization_endpoint");
	const tokenEndpoint = required("token_endpoint");
	const jwksUri = required("jwks_uri");
	if (issuer !== expectedIssuer) {
		throw new Error(
			`[transit] discovery answered for issuer '${issuer}', not '${expectedIssuer}' — the URL asked is not the authority that replied`,
		);
	}
	const userinfo = body.userinfo_endpoint;
	const algs = stringList(body.id_token_signing_alg_values_supported);
	const challenges = stringList(body.code_challenge_methods_supported);
	return {
		issuer,
		authorization_endpoint: authorizationEndpoint,
		token_endpoint: tokenEndpoint,
		jwks_uri: jwksUri,
		...(typeof userinfo === "string" && userinfo !== ""
			? { userinfo_endpoint: userinfo }
			: {}),
		...(algs === undefined
			? {}
			: { id_token_signing_alg_values_supported: algs }),
		...(challenges === undefined
			? {}
			: { code_challenge_methods_supported: challenges }),
	};
}

/** A list of strings, or `undefined` when the field is not one. */
function stringList(value: unknown): string[] | undefined {
	return Array.isArray(value) &&
		value.every((item): item is string => typeof item === "string")
		? value
		: undefined;
}
