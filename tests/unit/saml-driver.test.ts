/**
 * SAML 2.0 end to end, against a provider whose responses are really signed.
 *
 * The order is the security: the signature is checked first, and everything
 * read afterwards comes out of the element it covers.
 */
import { createHash, createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/c14n.js";
import { saml } from "../../src/config.js";
import { SamlDriver } from "../../src/drivers/SamlDriver.js";
import { MemoryAssertionReplayStore } from "../../src/replay.js";
import { parseXml, textOf, walk, type XmlNode } from "../../src/xml.js";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "../fixtures");
const certificate = readFileSync(join(fixtures, "cert.pem"), "utf8");
const privateKey = createPrivateKey(
	readFileSync(join(fixtures, "key.pem"), "utf8"),
);

const IDP = "https://idp.acme.test/metadata";
const SP = "https://app.acme.test/saml";
const ACS = "https://app.acme.test/saml/acs";
const SSO = "https://idp.acme.test/sso";

const config = {
	entityId: SP,
	callbackUrl: ACS,
	issuer: IDP,
	signOnUrl: SSO,
	certificates: [certificate],
};

const iso = (offset: number) =>
	new Date(Date.now() + offset * 1000).toISOString();

/** A response the identity provider would send, signed over its assertion. */
function response(
	requestId: string,
	over: {
		id?: string;
		status?: string;
		recipient?: string;
		audience?: string;
		attributes?: string;
		nameId?: string;
	} = {},
): string {
	const assertionId = over.id ?? `_a-${requestId}`;
	const assertion =
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}">` +
		`<saml:Issuer>${IDP}</saml:Issuer>` +
		"__SIGNATURE__" +
		"<saml:Subject>" +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${over.nameId ?? "ada@acme.test"}</saml:NameID>` +
		'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
		`<saml:SubjectConfirmationData Recipient="${over.recipient ?? ACS}" InResponseTo="${requestId}" NotOnOrAfter="${iso(300)}"/>` +
		"</saml:SubjectConfirmation>" +
		"</saml:Subject>" +
		`<saml:Conditions NotBefore="${iso(-300)}" NotOnOrAfter="${iso(300)}">` +
		`<saml:AudienceRestriction><saml:Audience>${over.audience ?? SP}</saml:Audience></saml:AudienceRestriction>` +
		"</saml:Conditions>" +
		'<saml:AuthnStatement SessionIndex="session-9"/>' +
		(over.attributes ?? "") +
		"</saml:Assertion>";

	const signed = assertion.replace(
		"__SIGNATURE__",
		signatureFor(assertion, assertionId),
	);
	const status = over.status ?? "urn:oasis:names:tc:SAML:2.0:status:Success";

	return Buffer.from(
		'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">' +
			`<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
			signed +
			"</samlp:Response>",
		"utf8",
	).toString("base64");
}

/** Sign the assertion the way an identity provider does. */
function signatureFor(assertionXml: string, id: string): string {
	const bare = parseXml(assertionXml.replace("__SIGNATURE__", ""));
	const target = [...walk(bare)].find((e) =>
		e.attributes.some((a) => a.local === "ID" && a.value === id),
	);
	if (!target) throw new Error("no assertion");

	const digest = createHash("sha256")
		.update(canonicalize(target, { omit: new Set<XmlNode>() }), "utf8")
		.digest("base64");

	const signedInfo =
		"<ds:SignedInfo>" +
		'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
		'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
		`<ds:Reference URI="#${id}">` +
		"<ds:Transforms>" +
		'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>' +
		'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
		"</ds:Transforms>" +
		'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' +
		`<ds:DigestValue>${digest}</ds:DigestValue>` +
		"</ds:Reference>" +
		"</ds:SignedInfo>";

	const canonical = canonicalize(
		parseXml(
			signedInfo.replace(
				"<ds:SignedInfo>",
				'<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
			),
		),
	);
	const value = signBytes(
		"sha256",
		Buffer.from(canonical, "utf8"),
		privateKey,
	).toString("base64");

	return (
		'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
		signedInfo +
		`<ds:SignatureValue>${value}</ds:SignatureValue>` +
		"</ds:Signature>"
	);
}

/** Start a sign-in and hand back what the caller would have stored. */
async function begin(driver: SamlDriver) {
	const started = await driver.begin();
	return { started, requestId: started.secret as string };
}

describe("transit > saml > begin", () => {
	it("sends a deflated request to the provider's sign-on endpoint", async () => {
		const { started } = await begin(new SamlDriver(config));
		const url = new URL(started.url);

		expect(url.origin + url.pathname).toBe(SSO);
		expect(url.searchParams.get("RelayState")).toBe(started.state);

		// Raw deflate, with no zlib header — what the redirect binding asks for.
		const request = parseXml(
			inflateRawSync(
				Buffer.from(url.searchParams.get("SAMLRequest") as string, "base64"),
			).toString("utf8"),
		);
		expect(request.local).toBe("AuthnRequest");
		expect(
			request.attributes.find((a) => a.local === "AssertionConsumerServiceURL")
				?.value,
		).toBe(ACS);
		expect(textOf(request).trim()).toBe(SP);
	});

	it("keeps the request id, which the response has to answer", async () => {
		const { started } = await begin(new SamlDriver(config));

		// A SAML id is an XML name: it may not start with a digit.
		expect(started.secret).toMatch(/^_/);
		expect(new URL(started.url).searchParams.get("SAMLRequest")).toBeTruthy();
	});

	it("refuses to build a redirect without minting a request", () => {
		expect(() => new SamlDriver(config).redirectUrl()).toThrow(
			/begin\(\) instead of redirect\(\)/,
		);
	});

	it("refuses to exist without a certificate", () => {
		// A driver that discovered this at the first sign-in would have let the
		// application boot looking healthy.
		expect(() => new SamlDriver({ ...config, certificates: [] })).toThrow(
			/no signing certificate/,
		);
	});
});

describe("transit > saml > callback", () => {
	it("verifies the response and answers with the person", async () => {
		const driver = new SamlDriver(config);
		const { started, requestId } = await begin(driver);

		const { user, token } = await driver.callback(
			response(requestId, {
				attributes:
					'<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
					'<saml:Attribute Name="displayName"><saml:AttributeValue>Ada Lovelace</saml:AttributeValue></saml:Attribute>' +
					'<saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue></saml:Attribute>' +
					"</saml:AttributeStatement>",
			}),
			started.state,
			started.state,
			started.secret,
		);

		expect(user.id).toBe("ada@acme.test");
		expect(user.name).toBe("Ada Lovelace");
		// A directory that asserts an address has vouched for it.
		expect(user.email).toBe("ada@acme.test");
		expect(user.emailVerificationState).toBe("verified");
		expect(user.raw.sessionIndex).toBe("session-9");
		expect(token.accessToken).toBe("session-9");
	});

	it("refuses the same response a second time", async () => {
		const driver = new SamlDriver({
			...config,
			replayStore: new MemoryAssertionReplayStore(),
		});
		const { started, requestId } = await begin(driver);
		const posted = response(requestId);

		await driver.callback(posted, started.state, started.state, started.secret);

		// Everything else passes on a captured response posted twice. This is
		// what does not.
		await expect(
			driver.callback(posted, started.state, started.state, started.secret),
		).rejects.toThrow(/already been used/);
	});

	it("refuses a response answering another request", async () => {
		const driver = new SamlDriver(config);
		const { started } = await begin(driver);

		await expect(
			driver.callback(
				response("_someone-elses-request"),
				started.state,
				started.state,
				started.secret,
			),
		).rejects.toThrow(/answers a different request/);
	});

	it("refuses a callback with no request id kept", async () => {
		const driver = new SamlDriver(config);
		const { started, requestId } = await begin(driver);

		await expect(
			driver.callback(response(requestId), started.state, started.state),
		).rejects.toThrow(/request id from begin\(\) is missing/);
	});

	it("refuses a RelayState that was not round-tripped", async () => {
		const driver = new SamlDriver(config);
		const { started, requestId } = await begin(driver);

		await expect(
			driver.callback(
				response(requestId),
				"attacker",
				started.state,
				started.secret,
			),
		).rejects.toThrow(/state mismatch/);
	});

	it("reports what the provider refused", async () => {
		const driver = new SamlDriver(config);
		const { started, requestId } = await begin(driver);

		await expect(
			driver.callback(
				response(requestId, {
					status: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
				}),
				started.state,
				started.state,
				started.secret,
			),
		).rejects.toThrow(/status:AuthnFailed/);
	});

	it("refuses a response addressed to another application", async () => {
		const driver = new SamlDriver(config);
		const { started, requestId } = await begin(driver);

		await expect(
			driver.callback(
				response(requestId, { audience: "https://other.test/saml" }),
				started.state,
				started.state,
				started.secret,
			),
		).rejects.toThrow(/this application is/);
	});

	it("refuses an assertion edited after it was signed", async () => {
		const driver = new SamlDriver(config);
		const { started, requestId } = await begin(driver);
		const tampered = Buffer.from(
			Buffer.from(response(requestId), "base64")
				.toString("utf8")
				.replace("ada@acme.test", "attacker@evil.test"),
			"utf8",
		).toString("base64");

		await expect(
			driver.callback(tampered, started.state, started.state, started.secret),
		).rejects.toThrow(/does not match its digest/);
	});

	it("refuses anything that is not a SAML response", async () => {
		const driver = new SamlDriver(config);
		const { started } = await begin(driver);

		await expect(
			driver.callback(
				Buffer.from("<nope/>", "utf8").toString("base64"),
				started.state,
				started.state,
				started.secret,
			),
		).rejects.toThrow(/expected a <Response>/);

		await expect(
			driver.callback(
				"not base64 at all",
				started.state,
				started.state,
				started.secret,
			),
		).rejects.toThrow(/not base64-encoded XML/);
	});
});

describe("transit > saml helper", () => {
	it("builds the driver", () => {
		expect(saml(config)()).toBeInstanceOf(SamlDriver);
	});
});
