/**
 * XML signature verification.
 *
 * The signatures below are real: signed here with a throwaway certificate,
 * over a canonical form this package produced. What is being tested is not the
 * cryptography — it is that a signature cannot be made to cover one part of a
 * document while a reader uses another.
 */
import { createHash, createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/c14n.js";
import { verifyXmlSignature } from "../../src/dsig.js";
import { parseXml, textOf, walk, type XmlNode } from "../../src/xml.js";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "../fixtures");
const certificate = readFileSync(join(fixtures, "cert.pem"), "utf8");
const privateKey = createPrivateKey(
	readFileSync(join(fixtures, "key.pem"), "utf8"),
);

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/**
 * Sign the element carrying `id` in `xml`, the way an identity provider does:
 * digest the element with the signature left out, then sign SignedInfo.
 */
function sign(
	xml: string,
	id: string,
	over: {
		signatureMethod?: string;
		digestMethod?: string;
		transform?: string;
		uri?: string;
	} = {},
): string {
	// The signature goes inside the element, so the digest is computed with a
	// placeholder in place and the placeholder is what gets replaced.
	const placeholder = "<!--SIGNATURE-->";
	const withPlaceholder = xml.replace(placeholder, "");
	const root = parseXml(withPlaceholder);
	const target = [...walk(root)].find((e) =>
		e.attributes.some((a) => a.local === "ID" && a.value === id),
	);
	if (!target) throw new Error(`no element with ID '${id}'`);

	const digest = createHash("sha256")
		.update(canonicalize(target, { omit: new Set<XmlNode>() }), "utf8")
		.digest("base64");

	const signedInfoXml =
		'<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
		`<ds:CanonicalizationMethod Algorithm="${EXC}"/>` +
		`<ds:SignatureMethod Algorithm="${over.signatureMethod ?? RSA_SHA256}"/>` +
		`<ds:Reference URI="${over.uri ?? `#${id}`}">` +
		"<ds:Transforms>" +
		`<ds:Transform Algorithm="${over.transform ?? ENVELOPED}"/>` +
		`<ds:Transform Algorithm="${EXC}"/>` +
		"</ds:Transforms>" +
		`<ds:DigestMethod Algorithm="${over.digestMethod ?? SHA256}"/>` +
		`<ds:DigestValue>${digest}</ds:DigestValue>` +
		"</ds:Reference>" +
		"</ds:SignedInfo>";

	const canonicalSignedInfo = canonicalize(parseXml(signedInfoXml));
	const signatureValue = signBytes(
		"sha256",
		Buffer.from(canonicalSignedInfo, "utf8"),
		privateKey,
	).toString("base64");

	const signature =
		'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
		signedInfoXml.replace(
			' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"',
			"",
		) +
		`<ds:SignatureValue>${signatureValue}</ds:SignatureValue>` +
		"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" +
		certificate.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "") +
		"</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
		"</ds:Signature>";

	return xml.replace(placeholder, signature);
}

const template =
	'<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">' +
	'<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a-1">' +
	"<!--SIGNATURE-->" +
	"<Subject>ada@acme.test</Subject>" +
	"</Assertion>" +
	"</Response>";

const certificates = [certificate];

describe("transit > dsig > a genuine signature", () => {
	it("verifies, and hands back the element it covers", () => {
		const signed = verifyXmlSignature(parseXml(sign(template, "a-1")), {
			certificates,
		});

		// The RETURNED element is the contract: a caller reading this cannot be
		// reading a part of the document the signature does not cover.
		expect(signed.local).toBe("Assertion");
		expect(textOf(signed)).toContain("ada@acme.test");
	});

	it("accepts a certificate given as bare base64, as metadata carries it", () => {
		const bare = certificate
			.replace(/-----[A-Z ]+-----/g, "")
			.replace(/\s+/g, "");

		expect(
			verifyXmlSignature(parseXml(sign(template, "a-1")), {
				certificates: [bare],
			}).local,
		).toBe("Assertion");
	});
});

describe("transit > dsig > wrapping", () => {
	it("refuses a second element carrying the signed element's id", () => {
		// The classic payload: the signature stays valid over the real
		// assertion, and a reader that looks the id up finds the attacker's.
		const attacked = sign(template, "a-1").replace(
			"</Response>",
			'<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a-1">' +
				"<Subject>attacker@evil.test</Subject></Assertion></Response>",
		);

		expect(() =>
			verifyXmlSignature(parseXml(attacked), { certificates }),
		).toThrow(/elements carry the id 'a-1'/);
	});

	it("refuses a signature that references something it does not sit inside", () => {
		const moved = sign(template, "a-1")
			.replace(/<ds:Signature[\s\S]*<\/ds:Signature>/, "")
			.replace(
				"</Response>",
				`${/<ds:Signature[\s\S]*<\/ds:Signature>/.exec(sign(template, "a-1"))?.[0]}</Response>`,
			);

		expect(() => verifyXmlSignature(parseXml(moved), { certificates })).toThrow(
			/sits outside the element it references/,
		);
	});

	it("refuses more than one signature", () => {
		const twice = sign(template, "a-1").replace(
			"</Assertion>",
			`${/<ds:Signature[\s\S]*<\/ds:Signature>/.exec(sign(template, "a-1"))?.[0]}</Assertion>`,
		);

		expect(() => verifyXmlSignature(parseXml(twice), { certificates })).toThrow(
			/carries 2 signatures/,
		);
	});

	it("refuses a reference that does not point inside the document", () => {
		const external = sign(template, "a-1", {
			uri: "https://evil.test/assertion.xml",
		});

		expect(() =>
			verifyXmlSignature(parseXml(external), { certificates }),
		).toThrow(/same-document '#id' reference/);
	});
});

describe("transit > dsig > what it refuses to compute", () => {
	it("refuses SHA-1, whose collisions are practical", () => {
		const sha1 = sign(template, "a-1", {
			signatureMethod: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		});

		expect(() => verifyXmlSignature(parseXml(sha1), { certificates })).toThrow(
			/SHA-1 and the symmetric methods are not accepted/,
		);
	});

	it("refuses a SHA-1 digest", () => {
		const sha1 = sign(template, "a-1", {
			digestMethod: "http://www.w3.org/2000/09/xmldsig#sha1",
		});

		expect(() => verifyXmlSignature(parseXml(sha1), { certificates })).toThrow(
			/SHA-1 is not accepted/,
		);
	});

	it("refuses an XPath or XSLT transform", () => {
		// One can make the digest cover something other than the element; the
		// other is executable.
		const xpath = sign(template, "a-1", {
			transform: "http://www.w3.org/TR/1999/REC-xpath-19991116",
		});

		expect(() => verifyXmlSignature(parseXml(xpath), { certificates })).toThrow(
			/refuses/,
		);
	});
});

describe("transit > dsig > the key", () => {
	it("refuses a document signed with a certificate the metadata does not list", () => {
		// A perfectly valid certificate — just not the one this provider is
		// known by. The error says so, rather than leaving an operator to guess
		// at "does not verify" after a rotation.
		const other = readFileSync(join(fixtures, "other-cert.pem"), "utf8");

		expect(() =>
			verifyXmlSignature(parseXml(sign(template, "a-1")), {
				certificates: [other],
			}),
		).toThrow(/metadata does not list/);
	});

	it("accepts a rotation prepared in advance", () => {
		const next = readFileSync(join(fixtures, "other-cert.pem"), "utf8");

		// Listing both is how a provider's key change is absorbed without an
		// outage.
		expect(
			verifyXmlSignature(parseXml(sign(template, "a-1")), {
				certificates: [next, certificate],
			}).local,
		).toBe("Assertion");
	});

	it("refuses to run with no certificate at all", () => {
		// Verifying a document against a key it carries is verifying it against
		// itself.
		expect(() =>
			verifyXmlSignature(parseXml(sign(template, "a-1")), { certificates: [] }),
		).toThrow(/never from the document itself/);
	});
});

describe("transit > dsig > tampering", () => {
	it("refuses a signed element changed after signing", () => {
		const tampered = sign(template, "a-1").replace(
			"ada@acme.test",
			"attacker@evil.test",
		);

		expect(() =>
			verifyXmlSignature(parseXml(tampered), { certificates }),
		).toThrow(/does not match its digest/);
	});

	it("refuses a SignedInfo changed after signing", () => {
		const tampered = sign(template, "a-1").replace(
			`Algorithm="${SHA256}"`,
			'Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"',
		);

		expect(() =>
			verifyXmlSignature(parseXml(tampered), { certificates }),
		).toThrow(/does not verify/);
	});

	it("refuses a document with no signature at all", () => {
		expect(() =>
			verifyXmlSignature(parseXml(template.replace("<!--SIGNATURE-->", "")), {
				certificates,
			}),
		).toThrow(/carries no signature/);
	});
});
