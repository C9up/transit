/**
 * The two documents a provider publishes about itself, and how often they are
 * allowed to be fetched.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { JwksCache, OidcDiscovery } from "../../src/oidc.js";

const ISSUER = "https://id.acme.test";

const metadata = {
	issuer: ISSUER,
	authorization_endpoint: `${ISSUER}/auth`,
	token_endpoint: `${ISSUER}/token`,
	jwks_uri: `${ISSUER}/jwks`,
	userinfo_endpoint: `${ISSUER}/userinfo`,
};

function stubFetch(
	...bodies: Array<{ ok?: boolean; status?: number; body: unknown }>
) {
	const calls: string[] = [];
	let i = 0;
	vi.stubGlobal("fetch", (url: string) => {
		calls.push(url);
		const reply = bodies[Math.min(i++, bodies.length - 1)];
		return Promise.resolve({
			ok: reply?.ok ?? true,
			status: reply?.status ?? 200,
			json: async () => reply?.body,
		});
	});
	return calls;
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("transit > discovery", () => {
	it("reads the well-known document and caches it", async () => {
		const calls = stubFetch({ body: metadata });
		const discovery = new OidcDiscovery(ISSUER);

		expect((await discovery.metadata()).token_endpoint).toBe(`${ISSUER}/token`);
		await discovery.metadata();

		expect(calls).toEqual([`${ISSUER}/.well-known/openid-configuration`]);
	});

	it("opens one request for a burst on a cold cache", async () => {
		const calls = stubFetch({ body: metadata });
		const discovery = new OidcDiscovery(ISSUER);

		await Promise.all([
			discovery.metadata(),
			discovery.metadata(),
			discovery.metadata(),
		]);

		expect(calls).toHaveLength(1);
	});

	it("refetches once the document is stale", async () => {
		const calls = stubFetch({ body: metadata });
		let clock = 0;
		const discovery = new OidcDiscovery(ISSUER, {
			ttlMs: 1000,
			now: () => clock,
		});

		await discovery.metadata();
		clock = 2000;
		await discovery.metadata();

		expect(calls).toHaveLength(2);
	});

	it("refuses a document that answers for another issuer", async () => {
		stubFetch({ body: { ...metadata, issuer: "https://evil.test" } });

		// The URL asked is not the authority that replied — which is exactly how
		// a mix-up attack starts.
		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			/not 'https:\/\/id\.acme\.test'/,
		);
	});

	it("names the endpoint a document is missing", async () => {
		const { token_endpoint: _dropped, ...incomplete } = metadata;
		stubFetch({ body: incomplete });

		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			/no token_endpoint/,
		);
	});

	it("ignores a trailing slash on the issuer", () => {
		expect(new OidcDiscovery(`${ISSUER}/`).issuer).toBe(ISSUER);
		expect(new OidcDiscovery(`${ISSUER}//`).url).toBe(
			`${ISSUER}/.well-known/openid-configuration`,
		);
	});

	it("says so when the provider does not answer", async () => {
		stubFetch({ ok: false, status: 503, body: {} });

		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			/discovery failed.*503/,
		);
	});
});

const keys = (...kids: string[]) => ({
	keys: kids.map((kid) => ({ kty: "RSA", kid, n: "x", e: "AQAB" })),
});

describe("transit > signing keys", () => {
	it("finds the key a token names", async () => {
		stubFetch({ body: keys("a", "b") });
		const cache = new JwksCache();

		expect((await cache.key(`${ISSUER}/jwks`, "b")).kid).toBe("b");
	});

	it("refetches when a key is unknown, which is how rotation is picked up", async () => {
		const calls = stubFetch({ body: keys("a") }, { body: keys("a", "b") });
		let clock = 0;
		const cache = new JwksCache({ now: () => clock });

		await cache.key(`${ISSUER}/jwks`, "a");
		clock = 600_000;
		expect((await cache.key(`${ISSUER}/jwks`, "b")).kid).toBe("b");
		expect(calls).toHaveLength(2);
	});

	it("does not refetch again within the interval", async () => {
		const calls = stubFetch({ body: keys("a") });
		let clock = 0;
		const cache = new JwksCache({ minRefetchMs: 300_000, now: () => clock });

		await cache.key(`${ISSUER}/jwks`, "a");
		clock = 1000;
		// A stream of tokens naming invented keys must not turn this application
		// into a load generator against the provider.
		await expect(cache.key(`${ISSUER}/jwks`, "invented")).rejects.toThrow(
			/did not publish/,
		);
		await expect(cache.key(`${ISSUER}/jwks`, "invented-2")).rejects.toThrow(
			/did not publish/,
		);
		expect(calls).toHaveLength(1);
	});

	it("takes the only key when a token names none", async () => {
		stubFetch({ body: keys("only") });

		expect((await new JwksCache().key(`${ISSUER}/jwks`, undefined)).kid).toBe(
			"only",
		);
	});

	it("refuses to guess when a token names none and there are several", async () => {
		stubFetch({ body: keys("a", "b") });

		await expect(
			new JwksCache().key(`${ISSUER}/jwks`, undefined),
		).rejects.toThrow(/did not publish/);
	});

	it("skips keys published for encryption", async () => {
		stubFetch({
			body: {
				keys: [
					{ kty: "RSA", kid: "enc", use: "enc" },
					{ kty: "RSA", kid: "sig", use: "sig" },
				],
			},
		});

		// With `use: enc` filtered out, one signing key remains and no kid is
		// needed to pick it.
		expect((await new JwksCache().key(`${ISSUER}/jwks`, undefined)).kid).toBe(
			"sig",
		);
	});

	it("says so when the JWKS has no keys array", async () => {
		stubFetch({ body: { nope: true } });

		await expect(new JwksCache().key(`${ISSUER}/jwks`, "a")).rejects.toThrow(
			/no `keys` array/,
		);
	});
});
