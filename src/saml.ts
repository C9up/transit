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
 * and re-finding an element would throw it away. Elements are reached one
 * named child at a time, in the SAML namespaces, so nothing is ever read from
 * under a `<ds:Signature>` — the one part of a signed element its own
 * signature does not cover.
 */

import { DSIG_NS, isDigested } from "./dsig.js";
import { E_TRANSIT_SAML_REJECTED } from "./errors.js";
import { childrenNamed, textOf, type XmlElement } from "./xml.js";

export const SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
export const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/** What a validated assertion says about the person. */
export interface SamlIdentity {
	/** The `NameID`, which is what the provider calls this person. */
	nameId: string;
	nameIdFormat: string | undefined;
	/** Every attribute the assertion carried, values kept as a list. */
	attributes: Record<string, string[]>;
	/** The assertion's own id, for the replay check. */
	assertionId: string;
	/** The `NotOnOrAfter` of the assertion's conditions, epoch seconds. */
	notOnOrAfter: number;
	/**
	 * Until when a replay record has to last, epoch seconds: the later of the
	 * two expiries the assertion carries (its conditions and its bearer
	 * confirmation) plus the clock skew this validation allowed. Before that
	 * instant the same assertion can still pass `validateAssertion`, so a
	 * record forgotten earlier lets a captured response sign in again.
	 */
	rememberUntil: number;
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

/** What the envelope of a response has to say, beyond its assertion. */
export interface SamlResponseExpectations {
	/** The provider's entity id, as its metadata declares it. */
	issuer: string;
	/** The assertion consumer URL the response was posted to. */
	destination: string;
	/** The id of the request this answers. */
	inResponseTo?: string;
	/**
	 * Whether the verified signature covers the response itself, and not only
	 * its assertion. A signed response has to say where it was sent and who
	 * issued it; an unsigned one may leave both out.
	 */
	signed: boolean;
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
	throw new E_TRANSIT_SAML_REJECTED([
		`the provider refused the sign-in: ${value ?? "no status"}${
			message ? ` — ${textOf(message).trim()}` : ""
		}`,
	]);
}

/**
 * Check who a response is from, where it was sent and what it answers.
 *
 * The assertion says all three again, and `validateAssertion` checks them
 * there. These are the response's own: a signed response posted to another
 * address, or answering another request, is refused even when the assertion
 * inside it would pass (SAML 2.0 core, section 3.2.2; bindings, section
 * 3.5.5.2; profiles, section 4.1.4.2).
 *
 * On a response that is not itself signed these attributes are whatever the
 * sender wrote, so matching them proves nothing — and a mismatch is still a
 * response that says it was meant for somewhere else.
 */
export function validateResponse(
	response: XmlElement,
	expected: SamlResponseExpectations,
): void {
	const destination = response.attributes.find(
		(a) => a.namespaceUri === "" && a.local === "Destination",
	)?.value;
	if (destination === undefined) {
		if (expected.signed) {
			throw new E_TRANSIT_SAML_REJECTED([
				"the response is signed and names no destination, which a signed response must",
			]);
		}
	} else if (destination !== expected.destination) {
		throw new E_TRANSIT_SAML_REJECTED([
			`the response was sent to '${destination}', and this application answers at '${expected.destination}'`,
		]);
	}

	const issuer = childrenNamed(response, SAML_ASSERTION_NS, "Issuer")[0];
	if (issuer === undefined) {
		if (expected.signed) {
			throw new E_TRANSIT_SAML_REJECTED([
				"the response is signed and names no issuer, which a signed response must",
			]);
		}
	} else if (textOf(issuer).trim() !== expected.issuer) {
		throw new E_TRANSIT_SAML_REJECTED([
			`the response is issued by '${textOf(issuer).trim()}', not by '${expected.issuer}'`,
		]);
	}

	const answered = response.attributes.find(
		(a) => a.namespaceUri === "" && a.local === "InResponseTo",
	)?.value;
	if (answered !== undefined && answered !== expected.inResponseTo) {
		throw new E_TRANSIT_SAML_REJECTED([
			expected.inResponseTo === undefined
				? "the response answers a request this application did not make"
				: "the response answers a different request than the one this sign-in made",
		]);
	}
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
		throw new E_TRANSIT_SAML_REJECTED([
			`expected a signed <Assertion>, and the signature covers <${assertion.qname}>`,
		]);
	}

	const skew = expected.clockSkewSeconds ?? 60;
	const now = expected.now ?? Math.floor(Date.now() / 1000);

	const issuer = childrenNamed(assertion, SAML_ASSERTION_NS, "Issuer")[0];
	const issuerValue = issuer ? textOf(issuer).trim() : undefined;
	if (issuerValue !== expected.issuer) {
		throw new E_TRANSIT_SAML_REJECTED([
			`the assertion is issued by '${issuerValue ?? "nobody"}', not by '${expected.issuer}'`,
		]);
	}

	const assertionId = assertion.attributes.find((a) => a.local === "ID")?.value;
	if (!assertionId) {
		throw new E_TRANSIT_SAML_REJECTED([
			"the assertion carries no id, so it cannot be tracked",
		]);
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
		throw new E_TRANSIT_SAML_REJECTED([
			"the assertion has no bearer subject confirmation, which is the only method a browser sign-in uses",
		]);
	}
	const data = childrenNamed(
		confirmation,
		SAML_ASSERTION_NS,
		"SubjectConfirmationData",
	)[0];
	if (!data) {
		throw new E_TRANSIT_SAML_REJECTED([
			"the bearer confirmation carries no data to check",
		]);
	}

	const recipient = data.attributes.find((a) => a.local === "Recipient")?.value;
	if (recipient !== expected.recipient) {
		// A response addressed to another service provider is a genuine
		// assertion pointed at the wrong door.
		throw new E_TRANSIT_SAML_REJECTED([
			`the assertion was sent to '${recipient ?? "nowhere"}', and this application answers at '${expected.recipient}'`,
		]);
	}

	const answered = data.attributes.find(
		(a) => a.local === "InResponseTo",
	)?.value;
	if (expected.inResponseTo !== undefined) {
		if (answered !== expected.inResponseTo) {
			// Without this, an assertion obtained anywhere else can be posted
			// here and accepted.
			throw new E_TRANSIT_SAML_REJECTED([
				"the assertion answers a different request than the one this sign-in made",
			]);
		}
	} else if (answered !== undefined) {
		throw new E_TRANSIT_SAML_REJECTED([
			"the assertion answers a request this application did not make",
		]);
	}

	const confirmationExpiry = epoch(
		data.attributes.find((a) => a.local === "NotOnOrAfter")?.value,
	);
	if (confirmationExpiry === undefined) {
		throw new E_TRANSIT_SAML_REJECTED([
			"the bearer confirmation never expires, which it must",
		]);
	}
	if (now - skew >= confirmationExpiry) {
		throw new E_TRANSIT_SAML_REJECTED(["the assertion is no longer usable"]);
	}

	const conditions = one(assertion, "Conditions");
	const notBefore = epoch(
		conditions.attributes.find((a) => a.local === "NotBefore")?.value,
	);
	const notOnOrAfter = epoch(
		conditions.attributes.find((a) => a.local === "NotOnOrAfter")?.value,
	);
	if (notBefore !== undefined && now + skew < notBefore) {
		throw new E_TRANSIT_SAML_REJECTED(["the assertion is not valid yet"]);
	}
	if (notOnOrAfter === undefined) {
		throw new E_TRANSIT_SAML_REJECTED([
			"the assertion has no expiry, which it must",
		]);
	}
	if (now - skew >= notOnOrAfter) {
		throw new E_TRANSIT_SAML_REJECTED(["the assertion has expired"]);
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
		throw new E_TRANSIT_SAML_REJECTED([
			"the assertion restricts no audience, so it does not say who it is for",
		]);
	}
	if (!audiences.includes(expected.audience)) {
		throw new E_TRANSIT_SAML_REJECTED([
			`the assertion is for ${audiences.map((a) => `'${a}'`).join(", ")}, and this application is '${expected.audience}'`,
		]);
	}

	const nameIdElement = childrenNamed(subject, SAML_ASSERTION_NS, "NameID")[0];
	if (!nameIdElement) {
		throw new E_TRANSIT_SAML_REJECTED(["the assertion names nobody"]);
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
		rememberUntil: Math.max(notOnOrAfter, confirmationExpiry) + skew,
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

/**
 * The assertion the verified signature vouches for.
 *
 * `response` is the document that was posted, and `signed` what
 * `verifyXmlSignature` answered for it. The assertion is the one `<Assertion>`
 * child of the response, and it is accepted only when it is part of what the
 * signature digested: it is the signed element, or the signed element is the
 * response around it. Which case holds is decided by the identity of the
 * nodes, never by looking for an assertion under the signed element — that
 * search walks into the `<ds:Signature>` the digest leaves out, where anybody
 * can write one.
 *
 * So the signed element is the response or its assertion, and nothing else:
 * a signed document of another kind (the provider's metadata, a refusal
 * tucked inside another response) vouches for no assertion here.
 *
 * A document that carries SAML under a `<ds:Signature>` is refused outright,
 * before any of that. Nothing would read it, and no provider writes it: it is
 * only ever there to be mistaken for signed content.
 */
export function assertionInside(
	signed: XmlElement,
	response: XmlElement,
): XmlElement {
	if (
		response.namespaceUri !== SAML_PROTOCOL_NS ||
		response.local !== "Response" ||
		response.parent !== undefined
	) {
		throw new E_TRANSIT_SAML_REJECTED([
			`expected the <Response> that was posted, and this is <${response.qname}>`,
		]);
	}
	refuseSamlUnderSignature(response, false);
	const assertions = childrenNamed(response, SAML_ASSERTION_NS, "Assertion");
	const [assertion, ...others] = assertions;
	if (assertion === undefined || others.length > 0) {
		throw new E_TRANSIT_SAML_REJECTED([
			`the response carries ${assertions.length} assertions, and this reads one`,
		]);
	}
	if (!isDigested(signed, assertion)) {
		throw new E_TRANSIT_SAML_REJECTED([
			`the signature covers <${signed.qname}>, which is neither the response nor its assertion`,
		]);
	}
	return assertion;
}

function refuseSamlUnderSignature(
	element: XmlElement,
	underSignature: boolean,
): void {
	const inside =
		underSignature ||
		(element.namespaceUri === DSIG_NS && element.local === "Signature");
	if (
		inside &&
		(element.namespaceUri === SAML_ASSERTION_NS ||
			element.namespaceUri === SAML_PROTOCOL_NS)
	) {
		throw new E_TRANSIT_SAML_REJECTED([
			`the document carries <${element.qname}> under a signature, where nothing is signed`,
		]);
	}
	for (const child of element.children) {
		if (child.type === "element") refuseSamlUnderSignature(child, inside);
	}
}

function one(parent: XmlElement, local: string): XmlElement {
	const found = childrenNamed(parent, SAML_ASSERTION_NS, local);
	const [element, ...others] = found;
	if (element === undefined || others.length > 0) {
		throw new E_TRANSIT_SAML_REJECTED([
			`expected one <${local}> in the assertion, and there are ${found.length}`,
		]);
	}
	return element;
}

/** A SAML instant, in seconds. Anything unparseable is treated as absent. */
function epoch(value: string | undefined): number | undefined {
	if (value === undefined) return undefined;
	const parsed = Date.parse(value);
	return Number.isNaN(parsed) ? undefined : Math.floor(parsed / 1000);
}
