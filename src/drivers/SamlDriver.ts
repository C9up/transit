/**
 * SAML 2.0 Web Browser SSO.
 *
 * The pieces are the four layers below this one; what this adds is the walk
 * between them, and the two bindings a browser sign-in uses: the request
 * leaves deflated in a query string, and the response comes back base64 in a
 * form POST.
 *
 * The order here is the security. The signature is checked FIRST, and
 * everything read afterwards comes out of the element it covers — the status
 * being the one exception, and a deliberate one.
 */

import { randomUUID } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { verifyXmlSignature } from "../dsig.js";
import { inProduction } from "../nodeEnv.js";
import {
	type AssertionReplayStore,
	MemoryAssertionReplayStore,
} from "../replay.js";
import {
	assertionInside,
	assertResponseSucceeded,
	SamlError,
	type SamlIdentity,
	validateAssertion,
} from "../saml.js";
import type {
	OAuthToken,
	RedirectRequest,
	TransitDriver,
	TransitUser,
} from "../types.js";
import { assertOAuthState } from "../types.js";
import { parseXml } from "../xml.js";

const PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/**
 * The attribute names providers actually use for the same three things. A
 * config names its own when its provider invents another.
 */
const EMAIL_CLAIMS = [
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	"urn:oid:0.9.2342.19200300.100.1.3",
	"email",
	"mail",
	"emailAddress",
];
const NAME_CLAIMS = [
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
	"urn:oid:2.16.840.1.113730.3.1.241",
	"displayName",
	"cn",
	"name",
];
const NICK_CLAIMS = [
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
	"urn:oid:0.9.2342.19200300.100.1.1",
	"uid",
	"givenName",
];

export interface SamlConfig {
	/** This application's entity id, as the provider knows it. */
	entityId: string;
	/** Where the provider posts its response — this application's ACS URL. */
	callbackUrl: string;
	/** The provider's entity id, exactly as its metadata declares it. */
	issuer: string;
	/** The provider's sign-on endpoint, for the redirect binding. */
	signOnUrl: string;
	/**
	 * The provider's signing certificates, from its metadata. Several are
	 * accepted so a rotation can be prepared before it happens.
	 */
	certificates: string[];
	/** The name identifier format to ask for. */
	nameIdFormat?: string;
	/** Tolerance for clock drift against the provider. Default 60 seconds. */
	clockSkewSeconds?: number;
	/**
	 * Where used assertions are remembered.
	 *
	 * Defaults to this process's memory, which accepts the same assertion once
	 * per replica — pass `replayStores.redis(…)` as soon as there are two.
	 */
	replayStore?: AssertionReplayStore | (() => AssertionReplayStore);
	/** The attribute names this provider uses, when they are not the usual ones. */
	claims?: { email?: string; name?: string; nickName?: string };
}

/**
 * Refuse to fall into the memory replay store by DEFAULT in production.
 *
 * A store that bounds replay per process is real protection on one replica and
 * none at all on two, and nothing here can tell which is deployed. Defaulting
 * quietly means the protection disappears exactly when a service is scaled —
 * the moment nobody is looking at this file.
 *
 * Outside production the default stands: a single dev process is the case it
 * is correct for.
 */
function refuseImplicitMemoryReplayStoreInProduction(): void {
	if (!inProduction()) return;
	throw new SamlError(
		"SAML replay protection has no store configured, and the in-process default only bounds replay within ONE process — behind a second replica the same assertion is accepted again on each.\n" +
			"  Set `replayStore: replayStores.redis({ connection })` to share the record across replicas,\n" +
			"  or `replayStores.memory()` to state that a single process is intended.",
	);
}

export class SamlDriver implements TransitDriver {
	readonly #config: SamlConfig;
	#replay: AssertionReplayStore | undefined;

	constructor(config: SamlConfig) {
		if (config.certificates.length === 0) {
			// Without a certificate there is nothing to verify against, and a
			// driver that discovered that at the first sign-in would have let the
			// application boot looking healthy.
			throw new SamlError(
				`no signing certificate for '${config.issuer}' — take them from the provider's metadata`,
			);
		}
		if (config.replayStore === undefined) {
			// Decided here, not on the first sign-in: a driver that discovered
			// this mid-request would have let the application boot looking
			// healthy, and reported it to whoever happened to sign in first.
			refuseImplicitMemoryReplayStoreInProduction();
		}
		this.#config = config;
	}

	/**
	 * A SAML request carries its own id, and that id is what the response has
	 * to answer. There is nothing to build without minting one.
	 */
	redirectUrl(): string {
		throw new Error(
			"[transit] a SAML sign-in carries a request id the response must answer. Use begin() instead of redirect().",
		);
	}

	async begin(state: string = randomUUID()): Promise<RedirectRequest> {
		// A SAML id is an XML name: it may not start with a digit, and a bare
		// UUID often does.
		const requestId = `_${randomUUID()}`;
		const request = this.#authnRequest(requestId);

		// The redirect binding carries the request deflated — raw, with no zlib
		// header, which is what the specification asks for.
		const deflated = deflateRawSync(Buffer.from(request, "utf8")).toString(
			"base64",
		);
		const params = new URLSearchParams({
			SAMLRequest: deflated,
			RelayState: state,
		});

		return {
			url: `${this.#config.signOnUrl}${this.#config.signOnUrl.includes("?") ? "&" : "?"}${params}`,
			state,
			// The response is checked against this id; storing it is not optional.
			secret: requestId,
		};
	}

	/**
	 * `code` is the base64 `SAMLResponse` from the form post, `state` the
	 * `RelayState` that came back, `expectedState` the one sent, and `secret`
	 * the request id `begin()` minted.
	 */
	async callback(
		code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: TransitUser; token: OAuthToken }> {
		assertOAuthState(state, expectedState);
		if (!secret) {
			throw new SamlError(
				"the request id from begin() is missing — store it with the state and pass it back, or any assertion can be posted here",
			);
		}

		const document = parseXml(decode(code));
		if (
			document.namespaceUri !== PROTOCOL_NS ||
			document.local !== "Response"
		) {
			throw new SamlError(
				`expected a <Response>, and the document is <${document.qname}>`,
			);
		}

		// Read from the unsigned document exactly once, and only this: a refusal
		// arrives unsigned when the assertion is what carries the signature, and
		// it exists to be reported rather than trusted. Flipping it the other
		// way cannot produce an assertion that verifies.
		assertResponseSucceeded(document);

		// From here on, only what the signature covers.
		const signed = verifyXmlSignature(document, {
			certificates: this.#config.certificates,
		});
		const assertion = assertionInside(signed);

		const identity = validateAssertion(assertion, {
			issuer: this.#config.issuer,
			audience: this.#config.entityId,
			recipient: this.#config.callbackUrl,
			inResponseTo: secret,
			clockSkewSeconds: this.#config.clockSkewSeconds,
		});

		const fresh = await this.#replayStore().remember(
			identity.assertionId,
			identity.notOnOrAfter,
		);
		if (!fresh) {
			// Everything above passes on a captured response posted a second
			// time. This is what does not.
			throw new SamlError(
				"this assertion has already been used — a response cannot sign somebody in twice",
			);
		}

		return {
			user: this.#mapUser(identity),
			// SAML hands over a statement, not a token to go asking with. The
			// session index is what a single logout would name.
			token: { accessToken: identity.sessionIndex ?? identity.assertionId },
		};
	}

	#replayStore(): AssertionReplayStore {
		if (!this.#replay) {
			const configured = this.#config.replayStore;
			this.#replay =
				typeof configured === "function"
					? configured()
					: (configured ?? new MemoryAssertionReplayStore());
		}
		return this.#replay;
	}

	#authnRequest(id: string): string {
		const format = this.#config.nameIdFormat;
		return (
			`<samlp:AuthnRequest xmlns:samlp="${PROTOCOL_NS}"` +
			` ID="${escapeXml(id)}" Version="2.0"` +
			` IssueInstant="${new Date().toISOString()}"` +
			` Destination="${escapeXml(this.#config.signOnUrl)}"` +
			` AssertionConsumerServiceURL="${escapeXml(this.#config.callbackUrl)}"` +
			` ProtocolBinding="${HTTP_POST}">` +
			`<saml:Issuer xmlns:saml="${ASSERTION_NS}">${escapeXml(this.#config.entityId)}</saml:Issuer>` +
			(format
				? `<samlp:NameIDPolicy Format="${escapeXml(format)}" AllowCreate="true"/>`
				: "") +
			"</samlp:AuthnRequest>"
		);
	}

	#mapUser(identity: SamlIdentity): TransitUser {
		const claims = this.#config.claims ?? {};
		const email =
			pick(identity, claims.email, EMAIL_CLAIMS) ??
			(identity.nameIdFormat === EMAIL_FORMAT ? identity.nameId : undefined);
		const name = pick(identity, claims.name, NAME_CLAIMS);

		return {
			// The NameID is what the provider calls this person, and the only
			// value guaranteed to be there.
			id: identity.nameId,
			email: email ?? "",
			name: name ?? identity.nameId,
			nickName: pick(identity, claims.nickName, NICK_CLAIMS),
			// A provider that asserts an address has vouched for it: that is what
			// its directory is.
			emailVerificationState: email === undefined ? "unsupported" : "verified",
			raw: {
				nameId: identity.nameId,
				nameIdFormat: identity.nameIdFormat,
				sessionIndex: identity.sessionIndex,
				attributes: identity.attributes,
			},
		};
	}
}

/** The first value among the configured name, then the usual ones. */
function pick(
	identity: SamlIdentity,
	configured: string | undefined,
	candidates: string[],
): string | undefined {
	const names = configured ? [configured] : candidates;
	for (const name of names) {
		const value = identity.attributes[name]?.[0];
		if (value !== undefined && value !== "") return value;
	}
	return undefined;
}

function decode(value: string): string {
	const text = Buffer.from(value.replace(/\s+/g, ""), "base64").toString(
		"utf8",
	);
	if (!text.includes("<")) {
		throw new SamlError("the SAMLResponse is not base64-encoded XML");
	}
	return text;
}

function escapeXml(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}
