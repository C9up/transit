/**
 * Validating a SAML assertion.
 *
 * A valid signature says the provider wrote this. It says nothing about
 * whether the statement was meant for THIS application, at THIS moment, in
 * answer to THIS request — and a response that is genuine but none of those is
 * what a replay or a misdirected sign-in looks like.
 */
import { describe, expect, it } from "vitest";
import {
	assertionInside,
	assertResponseSucceeded,
	validateAssertion,
} from "../../src/saml.js";
import { parseXml, walk } from "../../src/xml.js";

const NOW = 1_700_000_000;
const iso = (offset: number) => new Date((NOW + offset) * 1000).toISOString();

const expected = {
	issuer: "https://idp.acme.test/metadata",
	audience: "https://app.acme.test/saml",
	recipient: "https://app.acme.test/saml/acs",
	inResponseTo: "req-1",
	now: NOW,
};

function assertionXml(
	over: {
		issuer?: string;
		recipient?: string;
		inResponseTo?: string | null;
		audience?: string;
		notBefore?: string;
		notOnOrAfter?: string;
		confirmationExpiry?: string;
		attributes?: string;
		nameId?: string;
		conditions?: string;
	} = {},
): string {
	const inResponseTo =
		over.inResponseTo === null
			? ""
			: ` InResponseTo="${over.inResponseTo ?? "req-1"}"`;
	return (
		'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a-1">' +
		`<saml:Issuer>${over.issuer ?? expected.issuer}</saml:Issuer>` +
		"<saml:Subject>" +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${over.nameId ?? "ada@acme.test"}</saml:NameID>` +
		'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
		`<saml:SubjectConfirmationData Recipient="${over.recipient ?? expected.recipient}"${inResponseTo} NotOnOrAfter="${over.confirmationExpiry ?? iso(300)}"/>` +
		"</saml:SubjectConfirmation>" +
		"</saml:Subject>" +
		(over.conditions ??
			`<saml:Conditions NotBefore="${over.notBefore ?? iso(-300)}" NotOnOrAfter="${over.notOnOrAfter ?? iso(300)}">` +
				"<saml:AudienceRestriction>" +
				`<saml:Audience>${over.audience ?? expected.audience}</saml:Audience>` +
				"</saml:AudienceRestriction>" +
				"</saml:Conditions>") +
		'<saml:AuthnStatement SessionIndex="session-9"/>' +
		(over.attributes ?? "") +
		"</saml:Assertion>"
	);
}

const validate = (xml: string, over: Partial<typeof expected> = {}) =>
	validateAssertion(parseXml(xml), { ...expected, ...over });

describe("transit > saml > a good assertion", () => {
	it("reads who the provider says this is", () => {
		const identity = validate(assertionXml());

		expect(identity.nameId).toBe("ada@acme.test");
		expect(identity.nameIdFormat).toContain("emailAddress");
		expect(identity.assertionId).toBe("a-1");
		expect(identity.sessionIndex).toBe("session-9");
	});

	it("keeps every value of a multi-valued attribute", () => {
		const identity = validate(
			assertionXml({
				attributes:
					'<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
					'<saml:Attribute Name="groups">' +
					"<saml:AttributeValue>staff</saml:AttributeValue>" +
					"<saml:AttributeValue>admin</saml:AttributeValue>" +
					"</saml:Attribute>" +
					'<saml:Attribute Name="mail"><saml:AttributeValue>ada@acme.test</saml:AttributeValue></saml:Attribute>' +
					"</saml:AttributeStatement>",
			}),
		);

		// Collapsing these to one value loses group memberships, which is
		// usually what the application authorises on.
		expect(identity.attributes.groups).toEqual(["staff", "admin"]);
		expect(identity.attributes.mail).toEqual(["ada@acme.test"]);
	});
});

describe("transit > saml > who it is from and for", () => {
	it("refuses an assertion from another issuer", () => {
		expect(() =>
			validate(assertionXml({ issuer: "https://evil.test" })),
		).toThrow(/issued by 'https:\/\/evil.test'/);
	});

	it("refuses an assertion addressed to another application", () => {
		expect(() =>
			validate(assertionXml({ audience: "https://other.test/saml" })),
		).toThrow(/this application is/);
	});

	it("refuses an assertion sent to another door", () => {
		// A genuine assertion pointed at a different service provider.
		expect(() =>
			validate(assertionXml({ recipient: "https://other.test/acs" })),
		).toThrow(/answers at/);
	});

	it("refuses an assertion that restricts no audience", () => {
		expect(() =>
			validate(
				assertionXml({
					conditions: `<saml:Conditions xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NotOnOrAfter="${iso(300)}"/>`,
				}),
			),
		).toThrow(/restricts no audience/);
	});
});

describe("transit > saml > which request it answers", () => {
	it("refuses an assertion answering another request", () => {
		// Without this, an assertion obtained anywhere else can be posted here.
		expect(() =>
			validate(assertionXml({ inResponseTo: "someone-elses-request" })),
		).toThrow(/answers a different request/);
	});

	it("refuses an unsolicited assertion when a request was made", () => {
		expect(() => validate(assertionXml({ inResponseTo: null }))).toThrow(
			/answers a different request/,
		);
	});

	it("refuses an assertion answering a request this application never made", () => {
		expect(() => validate(assertionXml(), { inResponseTo: undefined })).toThrow(
			/did not make/,
		);
	});
});

describe("transit > saml > when it is usable", () => {
	it("refuses an expired assertion", () => {
		expect(() => validate(assertionXml({ notOnOrAfter: iso(-300) }))).toThrow(
			/has expired/,
		);
	});

	it("refuses an assertion that is not valid yet", () => {
		expect(() => validate(assertionXml({ notBefore: iso(300) }))).toThrow(
			/not valid yet/,
		);
	});

	it("allows for clock drift against the provider", () => {
		// Thirty seconds past, inside the default minute of tolerance.
		expect(validate(assertionXml({ notOnOrAfter: iso(-30) })).nameId).toBe(
			"ada@acme.test",
		);
	});

	it("refuses an assertion with no expiry at all", () => {
		expect(() =>
			validate(
				assertionXml({
					conditions:
						'<saml:Conditions xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
						"<saml:AudienceRestriction><saml:Audience>https://app.acme.test/saml</saml:Audience></saml:AudienceRestriction>" +
						"</saml:Conditions>",
				}),
			),
		).toThrow(/no expiry/);
	});

	it("refuses a bearer confirmation that never expires", () => {
		const xml = assertionXml().replace(/ NotOnOrAfter="[^"]*"\/>/, "/>");

		expect(() => validate(xml)).toThrow(/never expires/);
	});
});

describe("transit > saml > the shape it insists on", () => {
	it("refuses anything that is not an assertion", () => {
		// The signature covering a <Response> does not make it an assertion.
		expect(() =>
			validateAssertion(
				parseXml(
					'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
				),
				expected,
			),
		).toThrow(/signature covers <samlp:Response>/);
	});

	it("refuses a confirmation method other than bearer", () => {
		const xml = assertionXml().replace(
			"urn:oasis:names:tc:SAML:2.0:cm:bearer",
			"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
		);

		expect(() => validate(xml)).toThrow(/no bearer subject confirmation/);
	});

	it("refuses an assertion that names nobody", () => {
		const xml = assertionXml().replace(
			/<saml:NameID[^>]*>[^<]*<\/saml:NameID>/,
			"",
		);

		expect(() => validate(xml)).toThrow(/names nobody/);
	});
});

describe("transit > saml > the response status", () => {
	const response = (status: string, message = "") =>
		parseXml(
			'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">' +
				`<samlp:Status><samlp:StatusCode Value="${status}"/>${message}</samlp:Status>` +
				"</samlp:Response>",
		);

	it("accepts a success", () => {
		expect(() =>
			assertResponseSucceeded(
				response("urn:oasis:names:tc:SAML:2.0:status:Success"),
			),
		).not.toThrow();
	});

	it("says what the provider refused", () => {
		// A refusal arrives signed exactly like a success.
		expect(() =>
			assertResponseSucceeded(
				response(
					"urn:oasis:names:tc:SAML:2.0:status:Responder",
					"<samlp:StatusMessage>No such user</samlp:StatusMessage>",
				),
			),
		).toThrow(/status:Responder — No such user/);
	});

	it("refuses a response with no status", () => {
		expect(() =>
			assertResponseSucceeded(
				parseXml(
					'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
				),
			),
		).toThrow(/no status/);
	});
});

describe("transit > saml > finding the assertion in a signed response", () => {
	const signedResponse = parseXml(
		'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">' +
			assertionXml() +
			"</samlp:Response>",
	);

	it("takes the one assertion a signed response carries", () => {
		expect(assertionInside(signedResponse).local).toBe("Assertion");
	});

	it("hands back the assertion itself when that is what was signed", () => {
		const assertion = [...walk(signedResponse)].find(
			(e) => e.local === "Assertion",
		);
		if (!assertion) throw new Error("no assertion");

		expect(assertionInside(assertion)).toBe(assertion);
	});

	it("refuses a signed response carrying several assertions", () => {
		const two = parseXml(
			'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">' +
				assertionXml() +
				assertionXml() +
				"</samlp:Response>",
		);

		expect(() => assertionInside(two)).toThrow(/contains 2 assertions/);
	});
});
