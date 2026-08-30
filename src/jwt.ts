/**
 * Verifying an OpenID Connect `id_token`.
 *
 * This is the file that decides whether a sign-in is genuine, so it is written
 * to refuse rather than to accept. Three rules shape it:
 *
 *   - The algorithm is chosen by US, never read from the token. A verifier that
 *     trusts the header's `alg` accepts `none`, and accepts an RS256 public key
 *     replayed as an HS256 shared secret — the two oldest JWT forgeries there
 *     are.
 *   - Every claim that binds the token to this exchange is checked: the issuer,
 *     the audience, the expiry, and the nonce. A token that is perfectly valid
 *     for somebody else is not valid here.
 *   - Nothing is decoded before the signature holds.
 *
 * No dependency: Node verifies RSA and EC against a JWK on its own.
 */

import {
	constants,
	createPublicKey,
	createVerify,
	verify as verifySignature,
} from "node:crypto";

/** A public key as a provider publishes it. */
export interface Jwk {
	kty: string;
	kid?: string;
	alg?: string;
	use?: string;
	[key: string]: unknown;
}

export interface IdTokenClaims {
	iss: string;
	sub: string;
	aud: string | string[];
	exp: number;
	iat?: number;
	nonce?: string;
	azp?: string;
	[claim: string]: unknown;
}

/**
 * The algorithms this verifies. Asymmetric only, and deliberately so: the
 * symmetric family signs with the client secret, so anyone holding it — every
 * copy of the config, every log line that leaked it — can mint a token for any
 * user. `none` is not an algorithm.
 */
const SUPPORTED = {
	RS256: { hash: "sha256", kind: "rsa", kty: "RSA" },
	RS384: { hash: "sha384", kind: "rsa", kty: "RSA" },
	RS512: { hash: "sha512", kind: "rsa", kty: "RSA" },
	PS256: { hash: "sha256", kind: "rsa-pss", kty: "RSA" },
	PS384: { hash: "sha384", kind: "rsa-pss", kty: "RSA" },
	PS512: { hash: "sha512", kind: "rsa-pss", kty: "RSA" },
	ES256: { hash: "sha256", kind: "ec", kty: "EC", crv: "P-256" },
	ES384: { hash: "sha384", kind: "ec", kty: "EC", crv: "P-384" },
	ES512: { hash: "sha512", kind: "ec", kty: "EC", crv: "P-521" },
} as const satisfies Record<
	string,
	{ hash: string; kind: string; kty: string; crv?: string }
>;

export type SupportedAlg = keyof typeof SUPPORTED;

export function isSupportedAlg(value: unknown): value is SupportedAlg {
	return typeof value === "string" && value in SUPPORTED;
}

/** The three parts of a compact JWS, still encoded. */
interface Parts {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
	signingInput: string;
	signature: Buffer;
}

/**
 * Split and decode a compact JWS. This says nothing about whether the token is
 * genuine — it is what the caller needs to find the right key.
 */
export function decodeJws(token: string): Parts {
	const segments = token.split(".");
	if (segments.length !== 3) {
		throw new Error("[transit] id_token is not a compact JWS (three segments)");
	}
	const [encodedHeader, encodedPayload, encodedSignature] = segments as [
		string,
		string,
		string,
	];
	return {
		header: decodeSegment(encodedHeader, "header"),
		payload: decodeSegment(encodedPayload, "payload"),
		signingInput: `${encodedHeader}.${encodedPayload}`,
		signature: Buffer.from(encodedSignature, "base64url"),
	};
}

/**
 * Check a token's signature against one key.
 *
 * `alg` is the caller's choice, not the token's. Passing the header's own
 * value would be the vulnerability this exists to avoid.
 */
export function verifyJwsSignature(
	parts: Parts,
	jwk: Jwk,
	alg: SupportedAlg,
): boolean {
	const spec = SUPPORTED[alg];
	assertKeyMatchesAlg(jwk, alg);
	const key = createPublicKey({ key: jwk as never, format: "jwk" });

	const data = Buffer.from(parts.signingInput, "ascii");
	if (spec.kind === "ec") {
		// JOSE concatenates R and S; Node reads DER unless told otherwise, and
		// would reject every valid signature without this.
		return verifySignature(
			spec.hash,
			data,
			{ key, dsaEncoding: "ieee-p1363" },
			parts.signature,
		);
	}
	if (spec.kind === "rsa-pss") {
		return verifySignature(
			spec.hash,
			data,
			{
				key,
				padding: constants.RSA_PKCS1_PSS_PADDING,
				saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
			},
			parts.signature,
		);
	}
	const verifier = createVerify(spec.hash);
	verifier.update(data);
	verifier.end();
	return verifier.verify(key, parts.signature);
}

export interface ClaimExpectations {
	/** The issuer the discovery document declared. */
	issuer: string;
	/** This application's client id. */
	audience: string;
	/** The nonce sent on the redirect. Required for the authorization-code flow. */
	nonce: string;
	/** Tolerance for clock drift between here and the provider, in seconds. */
	leewaySeconds?: number;
	/** Injected in tests; seconds since the epoch. */
	now?: number;
}

/**
 * Check every claim that binds this token to this exchange.
 *
 * Each of these has been a real vulnerability somewhere: a token from another
 * issuer, a token minted for another client of the same issuer, an expired one
 * replayed, and — the one people forget — a token from an older sign-in of the
 * same user, which is what the nonce catches.
 */
export function assertIdTokenClaims(
	payload: Record<string, unknown>,
	expected: ClaimExpectations,
): IdTokenClaims {
	const leeway = expected.leewaySeconds ?? 60;
	const now = expected.now ?? Math.floor(Date.now() / 1000);

	const iss = payload.iss;
	if (iss !== expected.issuer) {
		throw new Error(
			`[transit] id_token issuer mismatch: expected '${expected.issuer}'`,
		);
	}

	const sub = payload.sub;
	if (typeof sub !== "string" || sub === "") {
		throw new Error("[transit] id_token carries no subject");
	}

	const aud = payload.aud;
	const audiences = Array.isArray(aud) ? aud : [aud];
	if (!audiences.includes(expected.audience)) {
		throw new Error(
			"[transit] id_token was not issued for this client — check the audience",
		);
	}
	if (audiences.length > 1 && payload.azp !== expected.audience) {
		// With several audiences the spec requires `azp`, and it has to name us:
		// otherwise a token minted for a sibling client would pass the check
		// above.
		throw new Error(
			"[transit] id_token has several audiences and no azp naming this client",
		);
	}

	const exp = payload.exp;
	if (typeof exp !== "number") {
		throw new Error("[transit] id_token carries no expiry");
	}
	if (exp + leeway < now) {
		throw new Error("[transit] id_token has expired");
	}

	const iat = payload.iat;
	if (typeof iat === "number" && iat - leeway > now) {
		// A token issued in the future is either a clock problem or a forgery;
		// neither should sign anybody in.
		throw new Error("[transit] id_token is issued in the future");
	}

	if (payload.nonce !== expected.nonce) {
		// Without this, a token captured from an earlier sign-in of the same user
		// at the same provider can be replayed into a fresh session.
		throw new Error("[transit] id_token nonce does not match this sign-in");
	}

	return payload as unknown as IdTokenClaims;
}

function decodeSegment(segment: string, what: string): Record<string, unknown> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
	} catch {
		throw new Error(`[transit] id_token ${what} is not valid JSON`);
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new Error(`[transit] id_token ${what} is not an object`);
	}
	return parsed as Record<string, unknown>;
}

/**
 * Refuse a key that is not what the algorithm is defined over.
 *
 * Node ignores the EC-specific options when handed an RSA key, so verifying an
 * "ES256" token against an RSA key quietly becomes an RSA verification. That
 * is not a forgery on its own — it still needs a real signature — but a
 * verifier that reports success for a path it did not take is not one worth
 * trusting. The curve is checked for the same reason: ES256 is defined over
 * P-256 and nothing else.
 */
function assertKeyMatchesAlg(jwk: Jwk, alg: SupportedAlg): void {
	const spec = SUPPORTED[alg];
	if (jwk.kty !== spec.kty) {
		throw new Error(
			`[transit] ${alg} needs a ${spec.kty} key, and the provider published a ${String(jwk.kty)} one`,
		);
	}
	const curve = "crv" in spec ? spec.crv : undefined;
	if (curve !== undefined && jwk.crv !== curve) {
		throw new Error(
			`[transit] ${alg} is defined over ${curve}, and the key is on ${String(jwk.crv)}`,
		);
	}
}
