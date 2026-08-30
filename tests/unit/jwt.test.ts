/**
 * Verifying an id_token.
 *
 * Real keys, real signatures: every token below is minted with node's crypto
 * and verified through the same path a provider's token takes, so a mistake in
 * the encoding shows up here rather than against a live IdP.
 */
import { generateKeyPairSync, sign as signData } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	assertIdTokenClaims,
	decodeJws,
	isSupportedAlg,
	type Jwk,
	type SupportedAlg,
	verifyJwsSignature,
} from "../../src/jwt.js";

const b64 = (value: unknown) =>
	Buffer.from(JSON.stringify(value)).toString("base64url");

interface Keys {
	jwk: Jwk;
	sign: (input: string) => Buffer;
}

function rsaKeys(kid = "rsa-1"): Keys {
	const { publicKey, privateKey } = generateKeyPairSync("rsa", {
		modulusLength: 2048,
	});
	return {
		jwk: { ...(publicKey.export({ format: "jwk" }) as Jwk), kid },
		sign: (input) =>
			signData("sha256", Buffer.from(input, "ascii"), privateKey),
	};
}

function ecKeys(kid = "ec-1"): Keys {
	const { publicKey, privateKey } = generateKeyPairSync("ec", {
		namedCurve: "P-256",
	});
	return {
		jwk: { ...(publicKey.export({ format: "jwk" }) as Jwk), kid },
		sign: (input) =>
			signData("sha256", Buffer.from(input, "ascii"), {
				key: privateKey,
				dsaEncoding: "ieee-p1363",
			}),
	};
}

function token(
	keys: Keys,
	alg: string,
	payload: Record<string, unknown>,
): string {
	const head = b64({ alg, typ: "JWT", kid: keys.jwk.kid });
	const body = b64(payload);
	return `${head}.${body}.${keys.sign(`${head}.${body}`).toString("base64url")}`;
}

const claims = {
	iss: "https://id.acme.test",
	sub: "user-1",
	aud: "client-1",
	exp: 2_000_000_000,
	iat: 1_000_000_000,
	nonce: "n-1",
};

const expected = {
	issuer: "https://id.acme.test",
	audience: "client-1",
	nonce: "n-1",
	now: 1_000_000_100,
};

describe("transit > jwt > signatures", () => {
	it("verifies an RSA-signed token", () => {
		const keys = rsaKeys();
		const parts = decodeJws(token(keys, "RS256", claims));

		expect(verifyJwsSignature(parts, keys.jwk, "RS256")).toBe(true);
	});

	it("verifies an EC-signed token, whose signature is not DER", () => {
		const keys = ecKeys();
		const parts = decodeJws(token(keys, "ES256", claims));

		// JOSE concatenates R and S; reading it as DER rejects every valid
		// signature, which is the classic reason ES256 "does not work".
		expect(verifyJwsSignature(parts, keys.jwk, "ES256")).toBe(true);
	});

	it("refuses a token whose payload was edited after signing", () => {
		const keys = rsaKeys();
		const original = token(keys, "RS256", claims);
		const [head, , signature] = original.split(".") as [string, string, string];
		const tampered = `${head}.${b64({ ...claims, sub: "someone-else" })}.${signature}`;

		expect(verifyJwsSignature(decodeJws(tampered), keys.jwk, "RS256")).toBe(
			false,
		);
	});

	it("refuses a token signed by another key", () => {
		const parts = decodeJws(token(rsaKeys(), "RS256", claims));

		expect(verifyJwsSignature(parts, rsaKeys("rsa-2").jwk, "RS256")).toBe(
			false,
		);
	});

	it("verifies with the algorithm it is given, not the one the token claims", () => {
		const keys = rsaKeys();
		// A token signed with RS256 but announcing ES512 in its header. A
		// verifier that trusted the header would pick the wrong path entirely.
		const parts = decodeJws(token(keys, "ES512", claims));

		expect(verifyJwsSignature(parts, keys.jwk, "RS256")).toBe(true);
	});
});

describe("transit > jwt > which algorithms exist at all", () => {
	it("accepts only asymmetric families", () => {
		for (const alg of ["RS256", "PS384", "ES512"] satisfies SupportedAlg[]) {
			expect(isSupportedAlg(alg)).toBe(true);
		}
	});

	it("does not know `none`, nor the symmetric family", () => {
		// `none` is not an algorithm. HS* signs with the client secret, so every
		// copy of the config could mint a token for any user.
		for (const alg of ["none", "None", "HS256", "HS512", ""]) {
			expect(isSupportedAlg(alg)).toBe(false);
		}
	});
});

describe("transit > jwt > claims", () => {
	it("accepts a token that is for us, from them, and still valid", () => {
		expect(assertIdTokenClaims(claims, expected).sub).toBe("user-1");
	});

	it("refuses a token from another issuer", () => {
		expect(() =>
			assertIdTokenClaims({ ...claims, iss: "https://evil.test" }, expected),
		).toThrow(/issuer mismatch/);
	});

	it("refuses a token minted for another client of the same issuer", () => {
		expect(() =>
			assertIdTokenClaims({ ...claims, aud: "client-2" }, expected),
		).toThrow(/not issued for this client/);
	});

	it("refuses several audiences unless azp names us", () => {
		const several = { ...claims, aud: ["client-1", "client-2"] };
		expect(() => assertIdTokenClaims(several, expected)).toThrow(/azp/);
		expect(
			assertIdTokenClaims({ ...several, azp: "client-1" }, expected).sub,
		).toBe("user-1");
		// A sibling client's token names us in `aud` but itself in `azp`.
		expect(() =>
			assertIdTokenClaims({ ...several, azp: "client-2" }, expected),
		).toThrow(/azp/);
	});

	it("refuses an expired token, allowing for clock drift", () => {
		const expiredAt = { ...claims, exp: 1_000_000_000 };
		expect(
			assertIdTokenClaims(expiredAt, { ...expected, now: 1_000_000_030 }).sub,
		).toBe("user-1");
		expect(() =>
			assertIdTokenClaims(expiredAt, { ...expected, now: 1_000_000_200 }),
		).toThrow(/expired/);
	});

	it("refuses a token issued in the future", () => {
		expect(() =>
			assertIdTokenClaims({ ...claims, iat: 1_000_100_000 }, expected),
		).toThrow(/issued in the future/);
	});

	it("refuses a token from an earlier sign-in of the same user", () => {
		// The nonce is what makes a captured token useless in a fresh session.
		expect(() =>
			assertIdTokenClaims({ ...claims, nonce: "n-0" }, expected),
		).toThrow(/nonce/);
		expect(() => {
			const { nonce: _dropped, ...without } = claims;
			return assertIdTokenClaims(without, expected);
		}).toThrow(/nonce/);
	});

	it("refuses a token with no subject or no expiry", () => {
		const { sub: _s, ...noSub } = claims;
		const { exp: _e, ...noExp } = claims;
		expect(() => assertIdTokenClaims(noSub, expected)).toThrow(/no subject/);
		expect(() => assertIdTokenClaims(noExp, expected)).toThrow(/no expiry/);
	});
});

describe("transit > jwt > decoding", () => {
	it("refuses anything that is not three segments", () => {
		expect(() => decodeJws("a.b")).toThrow(/three segments/);
		expect(() => decodeJws("a.b.c.d")).toThrow(/three segments/);
	});

	it("refuses a header or payload that is not a JSON object", () => {
		expect(() =>
			decodeJws(`${Buffer.from("[]").toString("base64url")}.${b64({})}.x`),
		).toThrow(/header is not an object/);
		expect(() => decodeJws(`${b64({})}.bm90LWpzb24.x`)).toThrow(
			/payload is not valid JSON/,
		);
	});
});

describe("transit > jwt > the key has to match the algorithm", () => {
	it("refuses an RSA key for an EC algorithm", () => {
		const keys = rsaKeys();
		const parts = decodeJws(token(keys, "RS256", claims));

		// Node ignores the EC-specific options when handed an RSA key, so this
		// would otherwise verify as RSA and report success for a path it never
		// took.
		expect(() => verifyJwsSignature(parts, keys.jwk, "ES256")).toThrow(
			/needs a EC key/,
		);
	});

	it("refuses an EC key on the wrong curve", () => {
		const keys = ecKeys();
		const parts = decodeJws(token(keys, "ES256", claims));

		// ES384 is defined over P-384 and nothing else.
		expect(() => verifyJwsSignature(parts, keys.jwk, "ES384")).toThrow(
			/defined over P-384/,
		);
	});

	it("refuses an EC key for an RSA algorithm", () => {
		const keys = ecKeys();
		const parts = decodeJws(token(keys, "ES256", claims));

		expect(() => verifyJwsSignature(parts, keys.jwk, "RS256")).toThrow(
			/needs a RSA key/,
		);
	});
});
