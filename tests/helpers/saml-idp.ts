/**
 * An identity provider, in process: it builds SAML documents and really signs
 * them, with the throwaway key in `tests/fixtures`.
 *
 * The signatures are genuine, over the canonical form this package produces,
 * so a test that edits a signed document afterwards is doing exactly what an
 * attacker can do: change bytes, without the key.
 */

import { createHash, createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../../src/c14n.js";
import { parseXml, walk, type XmlNode } from "../../src/xml.js";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "../fixtures");
export const certificate = readFileSync(join(fixtures, "cert.pem"), "utf8");
const privateKey = createPrivateKey(
	readFileSync(join(fixtures, "key.pem"), "utf8"),
);

export const IDP = "https://idp.acme.test/metadata";
export const SP = "https://app.acme.test/saml";
export const ACS = "https://app.acme.test/saml/acs";
export const SSO = "https://idp.acme.test/sso";

const DS = "http://www.w3.org/2000/09/xmldsig#";
const EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

/** Where a signature goes in a document that is still to be signed. */
export const SIGNATURE = "__SIGNATURE__";

const iso = (offset: number) =>
	new Date(Date.now() + offset * 1000).toISOString();

/**
 * Sign the element carrying `id`, the way an identity provider does: digest
 * it with the signature left out, sign SignedInfo, and envelope the result
 * where `placeholder` stands.
 */
export function sign(xml: string, id: string, placeholder = SIGNATURE): string {
	const bare = parseXml(xml.replace(placeholder, ""));
	const target = [...walk(bare)].find((element) =>
		element.attributes.some((a) => a.local === "ID" && a.value === id),
	);
	if (!target) throw new Error(`no element with ID '${id}'`);

	const digest = createHash("sha256")
		.update(canonicalize(target, { omit: new Set<XmlNode>() }), "utf8")
		.digest("base64");

	const signedInfo =
		"<ds:SignedInfo>" +
		`<ds:CanonicalizationMethod Algorithm="${EXC}"/>` +
		'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
		`<ds:Reference URI="#${id}">` +
		"<ds:Transforms>" +
		`<ds:Transform Algorithm="${DS}enveloped-signature"/>` +
		`<ds:Transform Algorithm="${EXC}"/>` +
		"</ds:Transforms>" +
		'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' +
		`<ds:DigestValue>${digest}</ds:DigestValue>` +
		"</ds:Reference>" +
		"</ds:SignedInfo>";

	const canonical = canonicalize(
		parseXml(
			signedInfo.replace("<ds:SignedInfo>", `<ds:SignedInfo xmlns:ds="${DS}">`),
		),
	);
	const value = signBytes(
		"sha256",
		Buffer.from(canonical, "utf8"),
		privateKey,
	).toString("base64");

	return xml.replace(
		placeholder,
		`<ds:Signature xmlns:ds="${DS}">` +
			signedInfo +
			`<ds:SignatureValue>${value}</ds:SignatureValue>` +
			"</ds:Signature>",
	);
}

/**
 * An assertion answering `requestId`, with a place for its signature. Sign it
 * with `sign(xml, id)`, or drop the placeholder to leave it unsigned — which
 * is all somebody without the key can write.
 */
export function assertion(
	requestId: string,
	over: { id?: string; nameId?: string; advice?: string } = {},
): string {
	return (
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${over.id ?? "_assertion"}">` +
		`<saml:Issuer>${IDP}</saml:Issuer>` +
		SIGNATURE +
		"<saml:Subject>" +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${over.nameId ?? "ada@acme.test"}</saml:NameID>` +
		'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
		`<saml:SubjectConfirmationData Recipient="${ACS}" InResponseTo="${requestId}" NotOnOrAfter="${iso(300)}"/>` +
		"</saml:SubjectConfirmation>" +
		"</saml:Subject>" +
		`<saml:Conditions NotBefore="${iso(-60)}" NotOnOrAfter="${iso(300)}">` +
		`<saml:AudienceRestriction><saml:Audience>${SP}</saml:Audience></saml:AudienceRestriction>` +
		"</saml:Conditions>" +
		(over.advice ? `<saml:Advice>${over.advice}</saml:Advice>` : "") +
		'<saml:AuthnStatement SessionIndex="session-9"/>' +
		"</saml:Assertion>"
	);
}

/** The assertion a provider issued: signed. */
export function signedAssertion(
	requestId: string,
	over: { id?: string; nameId?: string } = {},
): string {
	return sign(assertion(requestId, over), over.id ?? "_assertion");
}

/** The same document with no signature where one was expected. */
export function unsigned(xml: string): string {
	return xml.replace(SIGNATURE, "");
}

/** An assertion naming `victim`, written without the key. */
export function forgedAssertion(requestId: string, victim: string): string {
	return unsigned(assertion(requestId, { id: "_forged", nameId: victim }));
}

export interface ResponseShape {
	id?: string;
	status?: string;
	/** `null` leaves the attribute or the element out. */
	destination?: string | null;
	issuer?: string | null;
	inResponseTo?: string | null;
	/** Written between the status and the content, e.g. `<samlp:Extensions>`. */
	extensions?: string;
}

/**
 * A response around `content`, with a place for its own signature held by
 * `placeholder`. Leave the default and call `sign(xml, id)` to sign it, or
 * use {@link unsignedResponse}.
 */
export function response(
	requestId: string,
	content: string,
	over: ResponseShape = {},
	placeholder = SIGNATURE,
): string {
	const destination =
		over.destination === null
			? ""
			: ` Destination="${over.destination ?? ACS}"`;
	const inResponseTo =
		over.inResponseTo === null
			? ""
			: ` InResponseTo="${over.inResponseTo ?? requestId}"`;
	const issuer =
		over.issuer === null
			? ""
			: `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${over.issuer ?? IDP}</saml:Issuer>`;
	return (
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${over.id ?? "_response"}" Version="2.0"${destination}${inResponseTo}>` +
		issuer +
		placeholder +
		`<samlp:Status><samlp:StatusCode Value="${over.status ?? SUCCESS}"/></samlp:Status>` +
		(over.extensions ?? "") +
		content +
		"</samlp:Response>"
	);
}

/** A response the provider signed, around `content`. */
export function signedResponse(
	requestId: string,
	content: string,
	over: ResponseShape = {},
): string {
	// A placeholder of its own: `content` may still carry the assertion's.
	const placeholder = "__RESPONSE_SIGNATURE__";
	return sign(
		response(requestId, content, over, placeholder),
		over.id ?? "_response",
		placeholder,
	);
}

/** A response nobody signed: what an attacker can write around anything. */
export function unsignedResponse(
	requestId: string,
	content: string,
	over: ResponseShape = {},
): string {
	return response(requestId, content, over, "");
}

/** The form field a browser posts: the document, base64. */
export function encode(xml: string): string {
	return Buffer.from(xml, "utf8").toString("base64");
}
