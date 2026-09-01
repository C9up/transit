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
		// A trailing slash changes the well-known URL and, on some providers,
		// the issuer claim it must be compared against.
		this.#issuer = issuer.replace(/\/+$/, "");
		this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
		this.#now = options.now ?? Date.now;
	}

	get issuer(): string {
		return this.#issuer;
	}

	get url(): string {
		return `${this.#issuer}/.well-known/openid-configuration`;
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
		const body = (await response.json()) as Partial<OidcMetadata>;
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
		const body = (await response.json()) as { keys?: unknown };
		if (!Array.isArray(body.keys)) {
			throw new Error("[transit] the provider's JWKS has no `keys` array");
		}
		this.#keys = body.keys.filter(isJwk);
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
	body: Partial<OidcMetadata>,
	expectedIssuer: string,
): OidcMetadata {
	for (const field of [
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
	] as const) {
		if (typeof body[field] !== "string" || body[field] === "") {
			throw new Error(
				`[transit] the discovery document of '${expectedIssuer}' has no ${field}`,
			);
		}
	}
	if (body.issuer !== expectedIssuer) {
		throw new Error(
			`[transit] discovery answered for issuer '${body.issuer}', not '${expectedIssuer}' — the URL asked is not the authority that replied`,
		);
	}
	return body as OidcMetadata;
}
