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
			expect.objectContaining({
				code: "E_TRANSIT_INVALID_DISCOVERY",
				message: expect.stringMatching(/not 'https:\/\/id\.acme\.test'/),
			}),
		);
	});

	it("refuses a discovery document that is not a JSON object", async () => {
		for (const body of [null, [metadata], "document"]) {
			stubFetch({ body });
			await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
				expect.objectContaining({
					code: "E_TRANSIT_INVALID_RESPONSE",
					message: expect.stringMatching(
						/discovery document of .* is not a JSON object/,
					),
				}),
			);
		}
	});

	it("keeps only the declared fields, each with the type it must have", async () => {
		stubFetch({
			body: {
				...metadata,
				userinfo_endpoint: 42,
				id_token_signing_alg_values_supported: ["RS256", 7],
				code_challenge_methods_supported: ["S256"],
				extra: "ignored",
			},
		});
		expect(await new OidcDiscovery(ISSUER).metadata()).toEqual({
			issuer: ISSUER,
			authorization_endpoint: `${ISSUER}/auth`,
			token_endpoint: `${ISSUER}/token`,
			jwks_uri: `${ISSUER}/jwks`,
			code_challenge_methods_supported: ["S256"],
		});
	});

	it("names the endpoint a document is missing", async () => {
		const { token_endpoint: _dropped, ...incomplete } = metadata;
		stubFetch({ body: incomplete });

		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_INVALID_DISCOVERY",
				message: expect.stringMatching(/no token_endpoint/),
			}),
		);
	});

	it("keeps the issuer verbatim and joins the well-known URL without a double slash", () => {
		expect(new OidcDiscovery(`${ISSUER}/`).issuer).toBe(`${ISSUER}/`);
		expect(new OidcDiscovery(`${ISSUER}/`).url).toBe(
			`${ISSUER}/.well-known/openid-configuration`,
		);
		expect(new OidcDiscovery(`${ISSUER}//`).url).toBe(
			`${ISSUER}/.well-known/openid-configuration`,
		);
	});

	it("accepts an issuer that ends with a slash when the document declares it so", async () => {
		// Auth0's issuer is `https://<tenant>.auth0.com/`, slash included, in
		// its discovery document and in its id_tokens.
		const calls = stubFetch({ body: { ...metadata, issuer: `${ISSUER}/` } });

		const found = await new OidcDiscovery(`${ISSUER}/`).metadata();

		expect(found.issuer).toBe(`${ISSUER}/`);
		expect(calls).toEqual([`${ISSUER}/.well-known/openid-configuration`]);
	});

	it("accepts an issuer without a slash against a document without one", async () => {
		stubFetch({ body: metadata });

		expect((await new OidcDiscovery(ISSUER).metadata()).issuer).toBe(ISSUER);
	});

	it("refuses an issuer whose trailing slash differs from the document's", async () => {
		// Discovery §4.3: the issuer returned MUST be identical to the one used.
		stubFetch({ body: { ...metadata, issuer: `${ISSUER}/` } });
		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			/discovery answered for issuer/,
		);

		stubFetch({ body: metadata });
		await expect(new OidcDiscovery(`${ISSUER}/`).metadata()).rejects.toThrow(
			/discovery answered for issuer/,
		);
	});

	it("says so when the provider does not answer", async () => {
		stubFetch({ ok: false, status: 503, body: {} });

		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_DISCOVERY_FAILED",
				message: expect.stringMatching(/discovery failed.*503/),
			}),
		);
	});
});

describe("transit > discovery > an issuer without TLS", () => {
	it.each([
		["plain http", "http://id.acme.test"],
		["plain http on a port", "http://id.acme.test:8080/realms/acme"],
		["http in capitals", "HTTP://ID.ACME.TEST"],
		["a host that only starts with localhost", "http://localhost.evil.test"],
		["another scheme on localhost", "ftp://localhost/realms/acme"],
		["no scheme", "id.acme.test"],
		["a scheme-relative address", "//id.acme.test"],
		["nothing", ""],
	])("refuses %s before anything is fetched", (_what, issuer) => {
		const calls = stubFetch({ body: metadata });

		expect(() => new OidcDiscovery(issuer)).toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_INSECURE_ISSUER",
				message: expect.stringMatching(/is not an https URL/),
			}),
		);
		expect(calls).toEqual([]);
	});

	it("accepts http://localhost, for a provider run on a laptop", async () => {
		const local = "http://localhost:8080/realms/acme";
		const calls = stubFetch({
			body: {
				issuer: local,
				authorization_endpoint: `${local}/auth`,
				token_endpoint: `${local}/token`,
				jwks_uri: `${local}/certs`,
				userinfo_endpoint: `${local}/userinfo`,
			},
		});

		const found = await new OidcDiscovery(local).metadata();

		expect(found.jwks_uri).toBe(`${local}/certs`);
		expect(calls).toEqual([`${local}/.well-known/openid-configuration`]);
	});

	it.each([
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"userinfo_endpoint",
	])("refuses a discovery document whose %s is plain http", async (field) => {
		// The issuer is https and so was this document. One endpoint is not:
		// that part of the sign-in would leave in the clear.
		stubFetch({ body: { ...metadata, [field]: "http://id.acme.test/x" } });

		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_INVALID_DISCOVERY",
				message: expect.stringMatching(
					new RegExp(`gives a ${field} that is not an https URL`),
				),
			}),
		);
	});

	it("refuses an endpoint that is not a URL at all", async () => {
		stubFetch({ body: { ...metadata, jwks_uri: "/jwks" } });

		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			/gives a jwks_uri that is not an https URL/,
		);
	});

	it("does not let an https issuer send its keys to http://localhost", async () => {
		// The exception is for an issuer that is itself local. A real issuer
		// naming a local endpoint would have this server fetch from itself.
		stubFetch({ body: { ...metadata, jwks_uri: "http://localhost/jwks" } });

		await expect(new OidcDiscovery(ISSUER).metadata()).rejects.toThrow(
			/gives a jwks_uri that is not an https URL/,
		);
	});

	it("does not let a local issuer name a plain-http endpoint elsewhere", async () => {
		const local = "http://localhost:8080";
		stubFetch({
			body: {
				issuer: local,
				authorization_endpoint: `${local}/auth`,
				token_endpoint: "http://id.acme.test/token",
				jwks_uri: `${local}/certs`,
			},
		});

		await expect(new OidcDiscovery(local).metadata()).rejects.toThrow(
			/gives a token_endpoint that is not an https URL/,
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
			expect.objectContaining({
				code: "E_TRANSIT_UNKNOWN_SIGNING_KEY",
				message: expect.stringMatching(/did not publish/),
			}),
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
		).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_UNKNOWN_SIGNING_KEY",
				message: expect.stringMatching(/did not publish/),
			}),
		);
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

	it("refuses a JWKS that is not a JSON object", async () => {
		stubFetch({ body: null });

		await expect(new JwksCache().key(`${ISSUER}/jwks`, "a")).rejects.toThrow(
			/JWKS is not a JSON object/,
		);
	});

	it("says so when the JWKS has no keys array", async () => {
		stubFetch({ body: { nope: true } });

		await expect(new JwksCache().key(`${ISSUER}/jwks`, "a")).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_JWKS_FAILED",
				message: expect.stringMatching(/no `keys` array/),
			}),
		);
	});
});

describe("transit > signing keys > a key the provider withdrew", () => {
	const URI = `${ISSUER}/jwks`;
	const HOUR = 3_600_000;

	it("stops answering a withdrawn key once the set is older than ttlMs", async () => {
		// The provider signs with two keys. One leaks and is withdrawn; tokens
		// go on naming the other, so nothing ever asks for an unknown key.
		const calls = stubFetch(
			{ body: keys("leaked", "current") },
			{
				body: keys("current"),
			},
		);
		let clock = 0;
		const cache = new JwksCache({ ttlMs: HOUR, now: () => clock });

		expect((await cache.key(URI, "current")).kid).toBe("current");
		// Thirty days of sign-ins with the key that is still published.
		for (let day = 1; day <= 30; day += 1) {
			clock = day * 24 * HOUR;
			expect((await cache.key(URI, "current")).kid).toBe("current");
		}

		await expect(cache.key(URI, "leaked")).rejects.toThrow(
			expect.objectContaining({ code: "E_TRANSIT_UNKNOWN_SIGNING_KEY" }),
		);
		// The set was read again each time it had aged out, never more.
		expect(calls).toHaveLength(31);
	});

	it("asks again for a held key exactly when the set reaches ttlMs", async () => {
		const calls = stubFetch({ body: keys("a") });
		let clock = 0;
		const cache = new JwksCache({ ttlMs: HOUR, now: () => clock });

		await cache.key(URI, "a");
		clock = HOUR - 1;
		await cache.key(URI, "a");
		expect(calls).toHaveLength(1);

		clock = HOUR;
		await cache.key(URI, "a");
		expect(calls).toHaveLength(2);

		// And the new set is trusted for a full ttlMs from its own fetch.
		clock = 2 * HOUR - 1;
		await cache.key(URI, "a");
		expect(calls).toHaveLength(2);
	});

	it("trusts a set for one hour when nothing says otherwise", async () => {
		const calls = stubFetch({ body: keys("a") });
		let clock = 0;
		const cache = new JwksCache({ now: () => clock });

		await cache.key(URI, "a");
		clock = HOUR - 1;
		await cache.key(URI, "a");
		expect(calls).toHaveLength(1);
		clock = HOUR;
		await cache.key(URI, "a");
		expect(calls).toHaveLength(2);
	});

	it("answers nothing from an aged set when the provider cannot be asked", async () => {
		stubFetch({ body: keys("a") }, { ok: false, status: 503, body: {} });
		let clock = 0;
		const cache = new JwksCache({ ttlMs: HOUR, now: () => clock });

		await cache.key(URI, "a");
		clock = HOUR;

		// The key is still in memory. It is past its age, so it is not used.
		await expect(cache.key(URI, "a")).rejects.toThrow(
			expect.objectContaining({ code: "E_TRANSIT_JWKS_FAILED" }),
		);
	});

	it("reads an aged set once for sign-ins that arrive together", async () => {
		const calls = stubFetch({ body: keys("a") });
		let clock = 0;
		const cache = new JwksCache({ ttlMs: HOUR, now: () => clock });

		await cache.key(URI, "a");
		clock = HOUR;
		await Promise.all([
			cache.key(URI, "a"),
			cache.key(URI, "a"),
			cache.key(URI, "a"),
		]);

		expect(calls).toHaveLength(2);
	});

	it("does not answer one address with the keys of another", async () => {
		const calls = stubFetch({ body: keys("a") }, { body: keys("b") });
		const cache = new JwksCache();

		await cache.key(URI, "a");
		// The provider moved its key set: what was read at the old address says
		// nothing about the new one.
		await expect(cache.key(`${ISSUER}/keys/v2`, "a")).rejects.toThrow(
			expect.objectContaining({ code: "E_TRANSIT_UNKNOWN_SIGNING_KEY" }),
		);
		expect(calls).toEqual([URI, `${ISSUER}/keys/v2`]);
	});

	it("reads the set again when the clock went backwards", async () => {
		const calls = stubFetch({ body: keys("a") });
		let clock = 10 * HOUR;
		const cache = new JwksCache({ ttlMs: HOUR, now: () => clock });

		await cache.key(URI, "a");
		// An age that cannot be computed is not an age under the limit.
		clock = 0;
		await cache.key(URI, "a");

		expect(calls).toHaveLength(2);
	});
});
