/**
 * The two things Sign in with Apple does differently from every other OpenID
 * Connect provider.
 *
 * Apple has no client secret. It has a private key, and expects a short-lived
 * JWT minted from it on every token request — which is why `clientSecret` is
 * allowed to be a function.
 *
 * And it sends the user's name exactly ONCE, in the body of the first consent
 * callback, never in a token and never again. An application that does not
 * store it then has no way to ask for it later.
 */

import { createPrivateKey, sign as signData } from "node:crypto";

export interface AppleKey {
	/** The Services ID (web) or App ID this signs for. */
	clientId: string;
	/** The ten-character Team ID from the developer account. */
	teamId: string;
	/** The Key ID of the .p8 this signs with. */
	keyId: string;
	/** The contents of the .p8 file, PEM as Apple issues it. */
	privateKey: string;
}

/** Apple rejects a secret valid for more than six months; minutes are plenty. */
const LIFETIME_SECONDS = 300;

/**
 * Mint the JWT Apple takes in place of a client secret.
 *
 * Signed ES256 with the .p8, naming the team as issuer and the client as
 * subject. Minted per request rather than cached: it costs one signature, and
 * a long-lived one is a credential sitting in memory for no reason.
 */
export function appleClientSecret(
	key: AppleKey,
	now: number = Math.floor(Date.now() / 1000),
): string {
	const header = { alg: "ES256", kid: key.keyId, typ: "JWT" };
	const claims = {
		iss: key.teamId,
		iat: now,
		exp: now + LIFETIME_SECONDS,
		aud: "https://appleid.apple.com",
		sub: key.clientId,
	};

	const signingInput = `${b64(header)}.${b64(claims)}`;
	// JOSE wants R concatenated with S; node emits DER unless told, and Apple
	// rejects DER.
	const signature = signData("sha256", Buffer.from(signingInput, "ascii"), {
		key: createPrivateKey(key.privateKey),
		dsaEncoding: "ieee-p1363",
	});
	return `${signingInput}.${signature.toString("base64url")}`;
}

/**
 * Read the `user` field of Apple's first consent callback.
 *
 * It arrives as JSON in the POST body, on that one request only. Store what
 * comes out — the id_token never carries a name, and a second sign-in by the
 * same person will not carry one either.
 *
 * Returns `undefined` for anything unreadable rather than throwing: a returning
 * user simply has no `user` field, and that is the normal case.
 */
export function parseAppleUser(
	value: unknown,
): { name?: string; email?: string } | undefined {
	if (typeof value !== "string" || value === "") return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(value);
	} catch {
		return undefined;
	}
	if (typeof parsed !== "object" || parsed === null) return undefined;

	const email = Reflect.get(parsed, "email");
	const rawName = Reflect.get(parsed, "name");
	const name =
		typeof rawName === "object" && rawName !== null
			? [Reflect.get(rawName, "firstName"), Reflect.get(rawName, "lastName")]
					.filter(
						(part): part is string => typeof part === "string" && part !== "",
					)
					.join(" ")
			: undefined;

	const out: { name?: string; email?: string } = {};
	if (name) out.name = name;
	if (typeof email === "string" && email !== "") out.email = email;
	return Object.keys(out).length > 0 ? out : undefined;
}

function b64(value: unknown): string {
	return Buffer.from(JSON.stringify(value)).toString("base64url");
}
