/**
 * Sign in with Apple.
 *
 * Apple speaks OpenID Connect, so what is worth testing is the three places it
 * does not: a client secret that is a JWT, a callback that arrives as a POST,
 * and a name that is sent once and never again.
 */
import {
	createPublicKey,
	generateKeyPairSync,
	sign as signData,
} from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { appleClientSecret, parseAppleUser } from "../../src/apple.js";
import { socials } from "../../src/config.js";
import { AppleDriver } from "../../src/drivers/AppleDriver.js";
import type { Jwk } from "../../src/jwt.js";
import { decodeJws, verifyJwsSignature } from "../../src/jwt.js";

const ISSUER = "https://appleid.apple.com";
const CLIENT = "com.acme.web";

/** The .p8 Apple issues is a PKCS#8 PEM over P-256. */
const p8 = generateKeyPairSync("ec", {
	namedCurve: "P-256",
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
	publicKeyEncoding: { type: "spki", format: "pem" },
});

const key = {
	clientId: CLIENT,
	teamId: "TEAM123456",
	keyId: "KEY1234567",
	privateKey: p8.privateKey,
};

describe("transit > apple > the client secret", () => {
	it("is a JWT Apple can verify with the public half of the .p8", () => {
		const parts = decodeJws(appleClientSecret(key, 1_000_000_000));
		const publicJwk = createPublicKey(p8.publicKey).export({
			format: "jwk",
		}) as Jwk;

		// Signed ES256 over P-256, which is the only thing Apple accepts.
		expect(parts.header.alg).toBe("ES256");
		expect(verifyJwsSignature(parts, publicJwk, "ES256")).toBe(true);
	});

	it("names the team, the client and Apple itself", () => {
		const parts = decodeJws(appleClientSecret(key, 1_000_000_000));

		expect(parts.header.kid).toBe("KEY1234567");
		expect(parts.payload.iss).toBe("TEAM123456");
		expect(parts.payload.sub).toBe(CLIENT);
		expect(parts.payload.aud).toBe(ISSUER);
	});

	it("is short-lived, and minted fresh", () => {
		const parts = decodeJws(appleClientSecret(key, 1_000_000_000));

		// Apple rejects anything valid for more than six months; a credential
		// living longer than the request has no reason to.
		expect(parts.payload.exp).toBe(1_000_000_300);
		expect(parts.payload.iat).toBe(1_000_000_000);
	});

	it("carries a JOSE signature, not DER", () => {
		// Apple rejects DER outright, and this is where a hand-rolled secret
		// usually fails with an unhelpful `invalid_client`.
		const parts = decodeJws(appleClientSecret(key));
		expect(parts.signature).toHaveLength(64);
	});
});

describe("transit > apple > the name that comes once", () => {
	it("reads the first and last name Apple sends on first consent", () => {
		const field = JSON.stringify({
			name: { firstName: "Ada", lastName: "Lovelace" },
			email: "ada@privaterelay.appleid.com",
		});

		expect(parseAppleUser(field)).toEqual({
			name: "Ada Lovelace",
			email: "ada@privaterelay.appleid.com",
		});
	});

	it("answers undefined for a returning user, which sends no name at all", () => {
		// The normal case on every sign-in after the first — not an error.
		expect(parseAppleUser(undefined)).toBeUndefined();
		expect(parseAppleUser("")).toBeUndefined();
	});

	it("answers undefined rather than throwing on anything unreadable", () => {
		expect(parseAppleUser("not json")).toBeUndefined();
		expect(parseAppleUser("null")).toBeUndefined();
		expect(parseAppleUser(JSON.stringify({ name: {} }))).toBeUndefined();
	});

	it("takes whichever half of the name is present", () => {
		expect(
			parseAppleUser(JSON.stringify({ name: { firstName: "Ada" } })),
		).toEqual({ name: "Ada" });
		expect(parseAppleUser(JSON.stringify({ email: "ada@acme.test" }))).toEqual({
			email: "ada@acme.test",
		});
	});
});

const metadata = {
	issuer: ISSUER,
	authorization_endpoint: `${ISSUER}/auth/authorize`,
	token_endpoint: `${ISSUER}/auth/token`,
	jwks_uri: `${ISSUER}/auth/keys`,
	id_token_signing_alg_values_supported: ["RS256"],
};

function stubApple(routes: Record<string, unknown>) {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	vi.stubGlobal("fetch", (url: string, init?: RequestInit) => {
		calls.push({ url, init });
		const route = Object.keys(routes).find((prefix) => url.startsWith(prefix));
		return Promise.resolve({
			ok: route !== undefined,
			status: route ? 200 : 404,
			json: async () => (route ? routes[route] : {}),
		});
	});
	return calls;
}

afterEach(() => {
	vi.unstubAllGlobals();
});

const config = { ...key, callbackUrl: "https://acme.test/auth/apple/callback" };

describe("transit > apple > the flow", () => {
	it("asks for a POST callback, because a name cannot come back on a redirect", async () => {
		stubApple({ [`${ISSUER}/.well-known`]: metadata });
		const started = await new AppleDriver(config).begin();
		const url = new URL(started.url);

		expect(url.origin + url.pathname).toBe(`${ISSUER}/auth/authorize`);
		expect(url.searchParams.get("response_mode")).toBe("form_post");
		expect(url.searchParams.get("scope")).toContain("name");
		expect(url.searchParams.get("scope")).toContain("email");
		expect(url.searchParams.get("nonce")).toBeTruthy();
	});

	it("sends a freshly minted JWT as the client secret", async () => {
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const jwk: Jwk = {
			...(rsa.publicKey.export({ format: "jwk" }) as Jwk),
			kid: "apple-1",
		};
		const driver = new AppleDriver(config);

		stubApple({ [`${ISSUER}/.well-known`]: metadata });
		const started = await driver.begin();
		const nonce = (started.secret as string).split(".")[1];

		const b64 = (value: unknown) =>
			Buffer.from(JSON.stringify(value)).toString("base64url");
		const head = b64({ alg: "RS256", typ: "JWT", kid: "apple-1" });
		const body = b64({
			iss: ISSUER,
			sub: "000123.abc.0001",
			aud: CLIENT,
			exp: Math.floor(Date.now() / 1000) + 600,
			nonce,
			email: "ada@privaterelay.appleid.com",
			email_verified: "true",
			is_private_email: "true",
		});
		const idToken = `${head}.${body}.${signData("sha256", Buffer.from(`${head}.${body}`, "ascii"), rsa.privateKey).toString("base64url")}`;

		const calls = stubApple({
			[`${ISSUER}/.well-known`]: metadata,
			[`${ISSUER}/auth/token`]: { access_token: "at", id_token: idToken },
			[`${ISSUER}/auth/keys`]: { keys: [jwk] },
		});

		const { user } = await driver.callback(
			"code",
			started.state,
			started.state,
			started.secret,
		);

		const exchange = calls.find((call) =>
			call.url.startsWith(`${ISSUER}/auth/token`),
		);
		const sent = (exchange?.init?.body as URLSearchParams).get("client_secret");
		expect(decodeJws(sent as string).payload.iss).toBe("TEAM123456");

		expect(user.id).toBe("000123.abc.0001");
		// Apple sends its booleans as strings; read as booleans, a verified
		// address would report unverified and block account linking.
		expect(user.emailVerificationState).toBe("verified");
		expect(user.raw.is_private_email).toBe("true");
	});

	it("does not call a userinfo endpoint, because Apple publishes none", async () => {
		stubApple({ [`${ISSUER}/.well-known`]: metadata });
		const driver = new AppleDriver(config);
		await driver.begin();

		await expect(driver.userFromToken("at")).rejects.toThrow(
			/publishes no userinfo endpoint/,
		);
	});
});

describe("transit > apple > helper", () => {
	it("builds the driver", () => {
		expect(socials.apple(config)()).toBeInstanceOf(AppleDriver);
	});
});
