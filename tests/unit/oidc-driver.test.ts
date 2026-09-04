/**
 * The OpenID Connect flow end to end, against a provider whose keys and tokens
 * are real — generated here and signed here, so what is verified is what a
 * provider would actually send.
 */
import { generateKeyPairSync, sign as signData } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { oidc } from "../../src/config.js";
import { type OidcConfig, OidcDriver } from "../../src/drivers/OidcDriver.js";
import type { Jwk } from "../../src/jwt.js";
import { formBody } from "../__helpers__/defined.js";

const ISSUER = "https://id.acme.test";
const CLIENT = "client-1";

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
	modulusLength: 2048,
});
const jwk: Jwk = { ...(publicKey.export({ format: "jwk" }) as Jwk), kid: "k1" };

function idToken(
	payload: Record<string, unknown>,
	header?: Record<string, unknown>,
) {
	const b64 = (value: unknown) =>
		Buffer.from(JSON.stringify(value)).toString("base64url");
	const head = b64({ alg: "RS256", typ: "JWT", kid: "k1", ...header });
	const body = b64(payload);
	const signature = signData(
		"sha256",
		Buffer.from(`${head}.${body}`, "ascii"),
		privateKey,
	).toString("base64url");
	return `${head}.${body}.${signature}`;
}

const metadata = {
	issuer: ISSUER,
	authorization_endpoint: `${ISSUER}/auth`,
	token_endpoint: `${ISSUER}/token`,
	jwks_uri: `${ISSUER}/jwks`,
	userinfo_endpoint: `${ISSUER}/userinfo`,
	id_token_signing_alg_values_supported: ["RS256"],
	code_challenge_methods_supported: ["S256"],
};

/** Route each request by URL, so the order of calls is not baked in. */
function stubProvider(
	routes: Record<string, unknown>,
	status: Record<string, number> = {},
) {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	vi.stubGlobal("fetch", (url: string, init?: RequestInit) => {
		calls.push({ url, init });
		const key = Object.keys(routes).find((route) => url.startsWith(route));
		const code = key ? (status[key] ?? 200) : 404;
		return Promise.resolve({
			ok: code < 400,
			status: code,
			json: async () => (key ? routes[key] : {}),
		});
	});
	return calls;
}

const config: OidcConfig = {
	issuer: ISSUER,
	clientId: CLIENT,
	clientSecret: "shh",
	callbackUrl: "https://acme.test/cb",
};

const claims = (over: Record<string, unknown> = {}) => ({
	iss: ISSUER,
	sub: "user-1",
	aud: CLIENT,
	exp: Math.floor(Date.now() / 1000) + 600,
	iat: Math.floor(Date.now() / 1000),
	email: "ada@acme.test",
	email_verified: true,
	name: "Ada Lovelace",
	preferred_username: "ada",
	...over,
});

/** Run `begin()` and hand back what the caller would have stored. */
async function begin(
	driver: OidcDriver,
	meta: Record<string, unknown> = metadata,
) {
	stubProvider({ [`${ISSUER}/.well-known`]: meta });
	const started = await driver.begin();
	return { started, nonce: started.secret?.split(".")[1] as string };
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("transit > oidc > begin", () => {
	it("sends the user to the endpoint the provider published", async () => {
		const { started } = await begin(new OidcDriver(config));
		const url = new URL(started.url);

		expect(url.origin + url.pathname).toBe(`${ISSUER}/auth`);
		expect(url.searchParams.get("client_id")).toBe(CLIENT);
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("scope")).toBe("openid profile email");
	});

	it("carries a nonce and a PKCE challenge, and keeps neither in the URL", async () => {
		const { started } = await begin(new OidcDriver(config));
		const url = new URL(started.url);

		expect(url.searchParams.get("nonce")).toBeTruthy();
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		// `secret` holds the verifier and the nonce; only the nonce is public.
		const [verifier] = (started.secret as string).split(".");
		expect(url.searchParams.get("code_challenge")).not.toBe(verifier);
		expect(started.url).not.toContain(verifier);
	});

	it("sends no PKCE, and no verifier, to a provider that takes neither", async () => {
		const without = {
			...metadata,
			code_challenge_methods_supported: ["plain"],
		};
		const driver = new OidcDriver(config);
		const { started } = await begin(driver, without);

		expect(new URL(started.url).searchParams.get("code_challenge")).toBeNull();
		// `secret` still carries the nonce, with nothing before the separator.
		expect(started.secret?.startsWith(".")).toBe(true);

		const calls = stubProvider({
			[`${ISSUER}/.well-known`]: without,
			[`${ISSUER}/token`]: {
				access_token: "at",
				id_token: idToken(
					claims({ nonce: (started.secret as string).slice(1) }),
				),
			},
			[`${ISSUER}/jwks`]: { keys: [jwk] },
			[`${ISSUER}/userinfo`]: { sub: "user-1" },
		});
		await driver.callback("code", started.state, started.state, started.secret);

		// Sending a verifier for a challenge that was never sent is noise a
		// strict provider refuses the exchange over.
		const exchange = calls.find((call) =>
			call.url.startsWith(`${ISSUER}/token`),
		);
		expect(formBody(exchange).get("code_verifier")).toBeNull();
	});

	it("refuses a secret that did not come from begin()", async () => {
		const driver = new OidcDriver(config);
		const { started } = await begin(driver);

		for (const secret of ["", "no-separator", "."]) {
			await expect(
				driver.callback("code", started.state, started.state, secret),
			).rejects.toThrow(/begin\(\) returned as `secret`/);
		}
	});

	it("adds `openid` when a config forgets it", async () => {
		const driver = new OidcDriver({ ...config, scopes: ["email"] });
		const { started } = await begin(driver);

		// Without it the provider runs a plain OAuth2 flow and returns no
		// id_token, which fails much later with a far less obvious message.
		expect(new URL(started.url).searchParams.get("scope")).toBe("openid email");
	});

	it("refuses to build a redirect offline", () => {
		expect(() => new OidcDriver(config).redirectUrl()).toThrow(
			/begin\(\) instead of redirect\(\)/,
		);
	});
});

describe("transit > oidc > callback", () => {
	async function run(
		over: {
			claims?: Record<string, unknown>;
			header?: Record<string, unknown>;
			userinfo?: Record<string, unknown>;
			token?: Record<string, unknown>;
			nonce?: string;
			config?: Partial<OidcConfig>;
			metadata?: Record<string, unknown>;
		} = {},
	) {
		const driver = new OidcDriver({ ...config, ...over.config });
		// The discovery document is cached on the driver, so an override has to
		// be in place from the very first call.
		const { started, nonce } = await begin(driver, over.metadata ?? metadata);
		const payload = claims({ nonce: over.nonce ?? nonce, ...over.claims });

		const calls = stubProvider({
			[`${ISSUER}/.well-known`]: over.metadata ?? metadata,
			[`${ISSUER}/token`]: over.token ?? {
				access_token: "at",
				id_token: idToken(payload, over.header),
				refresh_token: "rt",
				expires_in: 300,
			},
			[`${ISSUER}/jwks`]: { keys: [jwk] },
			[`${ISSUER}/userinfo`]: over.userinfo ?? {
				sub: "user-1",
				picture: "https://cdn/ada.png",
			},
		});

		return {
			calls,
			result: driver.callback(
				"code",
				started.state,
				started.state,
				started.secret,
			),
		};
	}

	it("verifies the token and answers with the user", async () => {
		const { result } = await run();
		const { user, token } = await result;

		expect(user.id).toBe("user-1");
		expect(user.email).toBe("ada@acme.test");
		expect(user.name).toBe("Ada Lovelace");
		expect(user.nickName).toBe("ada");
		expect(user.emailVerificationState).toBe("verified");
		// userinfo enriches what the id_token carried.
		expect(user.avatarUrl).toBe("https://cdn/ada.png");
		expect(token).toEqual({
			accessToken: "at",
			refreshToken: "rt",
			expiresIn: 300,
		});
	});

	it("sends the PKCE verifier and the client credentials on the exchange", async () => {
		const { calls, result } = await run();
		await result;

		const exchange = calls.find((call) =>
			call.url.startsWith(`${ISSUER}/token`),
		);
		const body = exchange?.init?.body as URLSearchParams;
		expect(body.get("code_verifier")).toBeTruthy();
		expect(body.get("client_secret")).toBe("shh");
		expect(body.get("redirect_uri")).toBe("https://acme.test/cb");
	});

	it("refuses a token minted for an earlier sign-in", async () => {
		// A captured token, replayed into a fresh session, carries the old nonce.
		const { result } = await run({ claims: { nonce: "an-older-one" } });
		await expect(result).rejects.toThrow(/nonce/);
	});

	it("refuses a token from another issuer", async () => {
		const { result } = await run({ claims: { iss: "https://evil.test" } });
		await expect(result).rejects.toThrow(/issuer mismatch/);
	});

	it("refuses a token minted for another client", async () => {
		const { result } = await run({ claims: { aud: "client-2" } });
		await expect(result).rejects.toThrow(/not issued for this client/);
	});

	it("refuses a shared-secret algorithm, whatever the header says", async () => {
		// The header cannot introduce a family. HS256 signs with the client
		// secret, so every copy of the config could mint a token for any user;
		// `none` is not an algorithm at all.
		for (const alg of ["HS256", "none"]) {
			const { result } = await run({ header: { alg } });
			await expect(result).rejects.toThrow(/does not verify/);
		}
	});

	it("refuses an algorithm the provider never declared", async () => {
		const { result } = await run({ header: { alg: "ES256" } });
		await expect(result).rejects.toThrow(/did not declare it signs with/);
	});

	it("cannot be talked into the wrong verification path", async () => {
		// Provider declares both; the token is RS256 but announces ES256. The
		// header picks the path, so the signature simply fails — it can never
		// pick one that accepts.
		const { result } = await run({
			header: { alg: "ES256" },
			metadata: {
				...metadata,
				id_token_signing_alg_values_supported: ["RS256", "ES256"],
			},
		});
		// Node ignores the EC options when handed an RSA key, so this would
		// otherwise verify as RSA and report success for a path it never took.
		await expect(result).rejects.toThrow(/needs a EC key/);
	});

	it("refuses a signature made by another key", async () => {
		const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const driver = new OidcDriver(config);
		const { started, nonce } = await begin(driver);
		stubProvider({
			[`${ISSUER}/.well-known`]: metadata,
			[`${ISSUER}/token`]: {
				access_token: "at",
				id_token: idToken(claims({ nonce })),
			},
			[`${ISSUER}/jwks`]: {
				keys: [
					{ ...(other.publicKey.export({ format: "jwk" }) as Jwk), kid: "k1" },
				],
			},
		});

		await expect(
			driver.callback("code", started.state, started.state, started.secret),
		).rejects.toThrow(/signature does not verify/);
	});

	it("says which scope is missing when no id_token comes back", async () => {
		const { result } = await run({ token: { access_token: "at" } });
		await expect(result).rejects.toThrow(/'openid' scope/);
	});

	it("refuses a userinfo response about a different person", async () => {
		// A substituted access token would otherwise turn into a richer profile
		// for the wrong user.
		const { result } = await run({ userinfo: { sub: "someone-else" } });
		await expect(result).rejects.toThrow(/different subject/);
	});

	it("skips userinfo when the config says so", async () => {
		const { calls, result } = await run({ config: { userinfo: false } });
		await result;

		expect(
			calls.some((call) => call.url.startsWith(`${ISSUER}/userinfo`)),
		).toBe(false);
	});

	it("refuses a callback without the value begin() handed back", async () => {
		const driver = new OidcDriver(config);
		const { started } = await begin(driver);

		await expect(
			driver.callback("code", started.state, started.state),
		).rejects.toThrow(/begin\(\) returned as `secret`/);
	});

	it("still checks the state before anything else", async () => {
		const driver = new OidcDriver(config);
		const { started } = await begin(driver);

		await expect(
			driver.callback("code", "attacker", started.state, started.secret),
		).rejects.toThrow(/state mismatch/);
	});
});

describe("transit > oidc > a token already held", () => {
	it("reads the profile from userinfo", async () => {
		stubProvider({
			[`${ISSUER}/.well-known`]: metadata,
			[`${ISSUER}/userinfo`]: {
				sub: "user-1",
				email: "ada@acme.test",
				email_verified: false,
			},
		});

		const user = await new OidcDriver(config).userFromToken("at");

		expect(user.id).toBe("user-1");
		// The provider returned an address it does not vouch for.
		expect(user.emailVerificationState).toBe("unverified");
	});
});

describe("transit > oidc helper", () => {
	it("builds the driver", () => {
		expect(oidc(config)()).toBeInstanceOf(OidcDriver);
	});
});
