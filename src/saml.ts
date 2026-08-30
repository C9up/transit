/**
 * Reading a SAML response, once its signature has been verified.
 *
 * A valid signature says the identity provider wrote this. It says nothing
 * about whether the statement was meant for THIS application, at THIS moment,
 * in answer to THIS request — and a response that is genuine but not any of
 * those is exactly what a replay or a redirect to another service provider
 * looks like. Every condition below is one of those questions.
 *
 * Everything here works on the element the signature covers. Nothing searches
 * the document again: that is the guarantee `verifyXmlSignature` hands over,
 * and re-finding an element would throw it away.
 */

import { childrenNamed, textOf, walk, type XmlElement } from "./xml.js";

export const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
export const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

export class SamlError extends Error {
	constructor(message: string) {
		super(`[transit] ${message}`);
		this.name = "SamlError";
	}
}

/** What a validated assertion says about the person. */
export interface SamlIdentity {
	/** The `NameID`, which is what the provider calls this person. */
	nameId: string;
	nameIdFormat: string | undefined;
	/** Every attribute the assertion carried, values kept as a list. */
	attributes: Record<string, string[]>;
	/** The assertion's own id, for the replay check. */
	assertionId: string;
	/** When the assertion stops being usable, epoch seconds. */
	notOnOrAfter: number;
	/** The provider's session, when it named one. */
	sessionIndex: string | undefined;
}

export interface SamlExpectations {
	/** The provider's entity id, as its metadata declares it. */
	issuer: string;
	/** This application's entity id, which the assertion must be addressed to. */
	audience: string;
	/** The assertion consumer URL the response was meant to land on. */
	recipient: string;
	/**
	 * The id of the request this answers. Required for a sign-in this
	 * application started: without it, an assertion obtained elsewhere can be
	 * posted here.
	 */
	inResponseTo?: string;
	/** Tolerance for clock drift against the provider. Default 60 seconds. */
	clockSkewSeconds?: number;
	/** Injected in tests; seconds since the epoch. */
	now?: number;
}

/**
 * Check the `Status` of a response, and say what the provider refused.
 *
 * A failed status is the provider declining — an unknown user, a cancelled
 * consent — and it arrives signed just like a success.
 */
export function assertResponseSucceeded(response: XmlElement): void {
	const status = childrenNamed(response, SAML_PROTOCOL_NS, "Status")[0];
	const code = status
		? childrenNamed(status, SAML_PROTOCOL_NS, "StatusCode")[0]
		: undefined;
	const value = code?.attributes.find((a) => a.local === "Value")?.value;
	if (value === STATUS_SUCCESS) return;

	const message = status
		? childrenNamed(status, SAML_PROTOCOL_NS, "StatusMessage")[0]
		: undefined;
	throw new SamlError(
		`the provider refused the sign-in: ${value ?? "no status"}${
			message ? ` — ${textOf(message).trim()}` : ""
		}`,
	);
}

/**
 * Validate an assertion and read what it says.
 *
 * `assertion` must be the element the signature covers, or an element inside
 * it — never one looked up in the document afterwards.
 */
export function validateAssertion(
	assertion: XmlElement,
	expected: SamlExpectations,
): SamlIdentity {
	if (
		assertion.namespaceUri !== SAML_ASSERTION_NS ||
		assertion.local !== "Assertion"
	) {
		throw new SamlError(
			`expected a signed <Assertion>, and the signature covers <${assertion.qname}>`,
		);
	}

	const skew = expected.clockSkewSeconds ?? 60;
	const now = expected.now ?? Math.floor(Date.now() / 1000);

	const issuer = childrenNamed(assertion, SAML_ASSERTION_NS, "Issuer")[0];
	const issuerValue = issuer ? textOf(issuer).trim() : undefined;
	if (issuerValue !== expected.issuer) {
		throw new SamlError(
			`the assertion is issued by '${issuerValue ?? "nobody"}', not by '${expected.issuer}'`,
		);
	}

	const assertionId = assertion.attributes.find((a) => a.local === "ID")?.value;
	if (!assertionId) {
		throw new SamlError("the assertion carries no id, so it cannot be tracked");
	}

	const subject = one(assertion, "Subject");
	const confirmation = childrenNamed(
		subject,
		SAML_ASSERTION_NS,
		"SubjectConfirmation",
	).find(
		(c) => c.attributes.find((a) => a.local === "Method")?.value === BEARER,
	);
	if (!confirmation) {
		throw new SamlError(
			"the assertion has no bearer subject confirmation, which is the only method a browser sign-in uses",
		);
	}
	const data = childrenNamed(
		confirmation,
		SAML_ASSERTION_NS,
		"SubjectConfirmationData",
	)[0];
	if (!data) {
		throw new SamlError("the bearer confirmation carries no data to check");
	}

	const recipient = data.attributes.find((a) => a.local === "Recipient")?.value;
	if (recipient !== expected.recipient) {
		// A response addressed to another service provider is a genuine
		// assertion pointed at the wrong door.
		throw new SamlError(
			`the assertion was sent to '${recipient ?? "nowhere"}', and this application answers at '${expected.recipient}'`,
		);
	}

	const answered = data.attributes.find(
		(a) => a.local === "InResponseTo",
	)?.value;
	if (expected.inResponseTo !== undefined) {
		if (answered !== expected.inResponseTo) {
			// Without this, an assertion obtained anywhere else can be posted
			// here and accepted.
			throw new SamlError(
				"the assertion answers a different request than the one this sign-in made",
			);
		}
	} else if (answered !== undefined) {
		throw new SamlError(
			"the assertion answers a request this application did not make",
		);
	}

	const confirmationExpiry = epoch(
		data.attributes.find((a) => a.local === "NotOnOrAfter")?.value,
	);
	if (confirmationExpiry === undefined) {
		throw new SamlError("the bearer confirmation never expires, which it must");
	}
	if (now - skew >= confirmationExpiry) {
		throw new SamlError("the assertion is no longer usable");
	}

	const conditions = one(assertion, "Conditions");
	const notBefore = epoch(
		conditions.attributes.find((a) => a.local === "NotBefore")?.value,
	);
	const notOnOrAfter = epoch(
		conditions.attributes.find((a) => a.local === "NotOnOrAfter")?.value,
	);
	if (notBefore !== undefined && now + skew < notBefore) {
		throw new SamlError("the assertion is not valid yet");
	}
	if (notOnOrAfter === undefined) {
		throw new SamlError("the assertion has no expiry, which it must");
	}
	if (now - skew >= notOnOrAfter) {
		throw new SamlError("the assertion has expired");
	}

	const audiences = childrenNamed(
		conditions,
		SAML_ASSERTION_NS,
		"AudienceRestriction",
	).flatMap((restriction) =>
		childrenNamed(restriction, SAML_ASSERTION_NS, "Audience").map((a) =>
			textOf(a).trim(),
		),
	);
	if (audiences.length === 0) {
		throw new SamlError(
			"the assertion restricts no audience, so it does not say who it is for",
		);
	}
	if (!audiences.includes(expected.audience)) {
		throw new SamlError(
			`the assertion is for ${audiences.map((a) => `'${a}'`).join(", ")}, and this application is '${expected.audience}'`,
		);
	}

	const nameIdElement = childrenNamed(subject, SAML_ASSERTION_NS, "NameID")[0];
	if (!nameIdElement) {
		throw new SamlError("the assertion names nobody");
	}

	const authn = childrenNamed(
		assertion,
		SAML_ASSERTION_NS,
		"AuthnStatement",
	)[0];

	return {
		nameId: textOf(nameIdElement).trim(),
		nameIdFormat: nameIdElement.attributes.find((a) => a.local === "Format")
			?.value,
		attributes: readAttributes(assertion),
		assertionId,
		notOnOrAfter,
		sessionIndex: authn?.attributes.find((a) => a.local === "SessionIndex")
			?.value,
	};
}

/**
 * Every `<Attribute>` of the assertion, values kept as a list because SAML
 * attributes are multi-valued and collapsing them loses group memberships.
 */
function readAttributes(assertion: XmlElement): Record<string, string[]> {
	const out: Record<string, string[]> = {};
	for (const statement of childrenNamed(
		assertion,
		SAML_ASSERTION_NS,
		"AttributeStatement",
	)) {
		for (const attribute of childrenNamed(
			statement,
			SAML_ASSERTION_NS,
			"Attribute",
		)) {
			const name =
				attribute.attributes.find((a) => a.local === "Name")?.value ??
				attribute.attributes.find((a) => a.local === "FriendlyName")?.value;
			if (!name) continue;
			const values = childrenNamed(
				attribute,
				SAML_ASSERTION_NS,
				"AttributeValue",
			).map((value) => textOf(value).trim());
			const existing = out[name] ?? [];
			existing.push(...values);
			out[name] = existing;
		}
	}
	return out;
}

/** The assertion inside a signed response, when the response is what was signed. */
export function assertionInside(signed: XmlElement): XmlElement {
	if (
		signed.local === "Assertion" &&
		signed.namespaceUri === SAML_ASSERTION_NS
	) {
		return signed;
	}
	const assertions = [...walk(signed)].filter(
		(element) =>
			element.namespaceUri === SAML_ASSERTION_NS &&
			element.local === "Assertion",
	);
	if (assertions.length !== 1) {
		throw new SamlError(
			`the signed element contains ${assertions.length} assertions, and this reads one`,
		);
	}
	return assertions[0] as XmlElement;
}

function one(parent: XmlElement, local: string): XmlElement {
	const found = childrenNamed(parent, SAML_ASSERTION_NS, local);
	if (found.length !== 1) {
		throw new SamlError(
			`expected one <${local}> in the assertion, and there are ${found.length}`,
		);
	}
	return found[0] as XmlElement;
}

/** A SAML instant, in seconds. Anything unparseable is treated as absent. */
function epoch(value: string | undefined): number | undefined {
	if (value === undefined) return undefined;
	const parsed = Date.parse(value);
	return Number.isNaN(parsed) ? undefined : Math.floor(parsed / 1000);
}
