/**
 * XML Signature Wrapping against the SAML sign-in.
 *
 * Every attack below starts from a document the identity provider really
 * signed, and edits it without the key: the signature keeps verifying, and
 * the question is which element the sign-in then reads. The assertion it
 * reads has to be part of what the signature digested — the signed element,
 * or the one assertion of a signed response — and never anything else in the
 * document, least of all under the `<ds:Signature>` the digest leaves out.
 */
import { describe, expect, it } from "vitest";
import { SamlDriver } from "../../src/drivers/SamlDriver.js";
import { MemoryAssertionReplayStore } from "../../src/replay.js";
import {
	ACS,
	assertion,
	certificate,
	encode,
	forgedAssertion,
	IDP,
	SIGNATURE,
	SP,
	SSO,
	sign,
	signedAssertion,
	signedResponse,
	unsigned,
	unsignedResponse,
} from "../helpers/saml-idp.js";

const VICTIM = "ceo@acme.test";
const AUTHN_FAILED = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

/** Post what `document` builds for the request a fresh sign-in started. */
async function signIn(document: (requestId: string) => string) {
	const driver = new SamlDriver({
		entityId: SP,
		callbackUrl: ACS,
		issuer: IDP,
		signOnUrl: SSO,
		certificates: [certificate],
		trustEmail: true,
		replayStore: new MemoryAssertionReplayStore(),
	});
	const started = await driver.begin();
	const requestId = started.secret ?? "";
	return driver.callback(
		encode(document(requestId)),
		started.state,
		started.state,
		requestId,
	);
}

const rejected = (message: RegExp) =>
	expect.objectContaining({
		code: "E_TRANSIT_SAML_REJECTED",
		message: expect.stringMatching(message),
	});

const invalidSignature = (message: RegExp) =>
	expect.objectContaining({
		code: "E_TRANSIT_INVALID_SIGNATURE",
		message: expect.stringMatching(message),
	});

/** Write `payload` inside the first signature of `xml`, in `container`. */
function underSignature(
	xml: string,
	container: (payload: string) => string,
	payload: string,
): string {
	return xml.replace("</ds:Signature>", `${container(payload)}</ds:Signature>`);
}

/** The places XML-DSig lets a signature carry arbitrary content. */
const CONTAINERS: Array<[name: string, wrap: (payload: string) => string]> = [
	["ds:Object", (payload) => `<ds:Object>${payload}</ds:Object>`],
	[
		"ds:KeyInfo",
		(payload) =>
			`<ds:KeyInfo><ds:KeyName>idp</ds:KeyName>${payload}</ds:KeyInfo>`,
	],
	[
		"ds:SignatureProperties",
		(payload) =>
			"<ds:Object><ds:SignatureProperties>" +
			`<ds:SignatureProperty Target="#_response">${payload}</ds:SignatureProperty>` +
			"</ds:SignatureProperties></ds:Object>",
	],
];

/** A refusal the provider signed: it carries no assertion at all. */
function signedRefusal(requestId: string): string {
	return signedResponse(requestId, "", {
		id: "_refusal",
		status: AUTHN_FAILED,
	});
}

/** The provider's published metadata, signed. Anybody can fetch it. */
function signedMetadata(): string {
	return sign(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_metadata" entityID="${IDP}">` +
			SIGNATURE +
			'<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
			`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${SSO}"/>` +
			"</md:IDPSSODescriptor></md:EntityDescriptor>",
		"_metadata",
	);
}

describe("transit > saml > the shapes a provider signs", () => {
	it("accepts a signed assertion in an unsigned response", async () => {
		const { user } = await signIn((requestId) =>
			unsignedResponse(requestId, signedAssertion(requestId)),
		);

		expect(user.id).toBe("ada@acme.test");
	});

	it("accepts a signed response around an unsigned assertion", async () => {
		const { user } = await signIn((requestId) =>
			signedResponse(requestId, unsigned(assertion(requestId))),
		);

		expect(user.id).toBe("ada@acme.test");
	});

	it("accepts a response signed at both levels", async () => {
		const { user } = await signIn((requestId) =>
			signedResponse(requestId, signedAssertion(requestId)),
		);

		expect(user.id).toBe("ada@acme.test");
	});

	it("accepts an unsigned response that leaves its envelope out", async () => {
		// Only the assertion is signed: the response around it may say nothing
		// about where it was sent, who issued it or what it answers.
		const { user } = await signIn((requestId) =>
			unsignedResponse(requestId, signedAssertion(requestId), {
				destination: null,
				issuer: null,
				inResponseTo: null,
			}),
		);

		expect(user.id).toBe("ada@acme.test");
	});
});

describe("transit > saml > a forged assertion under the signature", () => {
	// The enveloped-signature transform leaves the whole <ds:Signature> out of
	// the digest, so anything written there keeps the signature valid.
	describe.each(CONTAINERS)("in %s", (_name, container) => {
		it("is refused inside a signed refusal tucked into another response", async () => {
			await expect(
				signIn((requestId) =>
					unsignedResponse(requestId, "", {
						extensions: `<samlp:Extensions>${underSignature(
							signedRefusal(requestId),
							container,
							forgedAssertion(requestId, VICTIM),
						)}</samlp:Extensions>`,
					}),
				),
			).rejects.toThrow(rejected(/under a signature/));
		});

		it("is refused inside the signature of a signed response", async () => {
			// The genuine assertion is still there and still signed: the document
			// is refused all the same, not read around the forgery.
			await expect(
				signIn((requestId) =>
					underSignature(
						signedResponse(requestId, unsigned(assertion(requestId))),
						container,
						forgedAssertion(requestId, VICTIM),
					),
				),
			).rejects.toThrow(rejected(/under a signature/));
		});

		it("is refused inside the signature of a signed assertion", async () => {
			await expect(
				signIn((requestId) =>
					unsignedResponse(
						requestId,
						underSignature(
							signedAssertion(requestId),
							container,
							forgedAssertion(requestId, VICTIM),
						),
					),
				),
			).rejects.toThrow(rejected(/under a signature/));
		});
	});

	it("is refused inside the provider's signed metadata", async () => {
		await expect(
			signIn((requestId) =>
				unsignedResponse(requestId, "", {
					extensions: `<samlp:Extensions>${underSignature(
						signedMetadata(),
						(payload) => `<ds:Object>${payload}</ds:Object>`,
						forgedAssertion(requestId, VICTIM),
					)}</samlp:Extensions>`,
				}),
			),
		).rejects.toThrow(rejected(/under a signature/));
	});

	it("is refused when the forged response itself sits under the signature", async () => {
		// A whole response, not only an assertion: nothing in the SAML
		// namespaces belongs under a signature.
		await expect(
			signIn((requestId) =>
				underSignature(
					signedResponse(requestId, unsigned(assertion(requestId))),
					(payload) => `<ds:Object>${payload}</ds:Object>`,
					unsignedResponse(requestId, forgedAssertion(requestId, VICTIM), {
						id: "_inner",
					}),
				),
			),
		).rejects.toThrow(rejected(/<samlp:Response> under a signature/));
	});
});

describe("transit > saml > a forged assertion beside what is signed", () => {
	it("refuses one beside a signed refusal tucked into the response", async () => {
		// Nothing is hidden under a signature here. The signature is genuine,
		// and it covers a document that vouches for no assertion.
		await expect(
			signIn((requestId) =>
				unsignedResponse(requestId, forgedAssertion(requestId, VICTIM), {
					extensions: `<samlp:Extensions>${signedRefusal(requestId)}</samlp:Extensions>`,
				}),
			),
		).rejects.toThrow(rejected(/neither the response nor its assertion/));
	});

	it("refuses one beside the provider's signed metadata", async () => {
		await expect(
			signIn((requestId) =>
				unsignedResponse(requestId, forgedAssertion(requestId, VICTIM), {
					extensions: `<samlp:Extensions>${signedMetadata()}</samlp:Extensions>`,
				}),
			),
		).rejects.toThrow(rejected(/neither the response nor its assertion/));
	});

	it("refuses one beside a signed response wrapped in another response", async () => {
		// The inner response is whole and genuine, assertion included. What was
		// posted is the outer one, and its assertion is the forged sibling.
		await expect(
			signIn((requestId) =>
				unsignedResponse(
					requestId,
					signedResponse(requestId, unsigned(assertion(requestId)), {
						id: "_inner",
					}) + forgedAssertion(requestId, VICTIM),
				),
			),
		).rejects.toThrow(rejected(/neither the response nor its assertion/));
	});

	it("refuses one added to a signed response", async () => {
		await expect(
			signIn((requestId) =>
				signedResponse(requestId, unsigned(assertion(requestId))).replace(
					"</samlp:Response>",
					`${forgedAssertion(requestId, VICTIM)}</samlp:Response>`,
				),
			),
		).rejects.toThrow(invalidSignature(/does not match its digest/));
	});

	it.each([
		["before", (forged: string, genuine: string) => forged + genuine],
		["after", (forged: string, genuine: string) => genuine + forged],
	])(
		"refuses one %s a signed assertion in an unsigned response",
		async (_where, order) => {
			await expect(
				signIn((requestId) =>
					unsignedResponse(
						requestId,
						order(
							forgedAssertion(requestId, VICTIM),
							signedAssertion(requestId),
						),
					),
				),
			).rejects.toThrow(rejected(/carries 2 assertions/));
		},
	);

	it("refuses one standing where the signed assertion was moved from", async () => {
		// The signed assertion is kept in the document so the signature still
		// verifies, and moved out of the way.
		await expect(
			signIn((requestId) =>
				unsignedResponse(requestId, forgedAssertion(requestId, VICTIM), {
					extensions: `<samlp:Extensions>${signedAssertion(requestId)}</samlp:Extensions>`,
				}),
			),
		).rejects.toThrow(rejected(/neither the response nor its assertion/));
	});

	it("refuses one that carries the signed assertion as advice", async () => {
		await expect(
			signIn((requestId) =>
				unsignedResponse(
					requestId,
					unsigned(
						assertion(requestId, {
							id: "_forged",
							nameId: VICTIM,
							advice: signedAssertion(requestId),
						}),
					),
				),
			),
		).rejects.toThrow(rejected(/neither the response nor its assertion/));
	});

	it("refuses one with no signed element around it at all", async () => {
		await expect(
			signIn((requestId) =>
				unsignedResponse(requestId, forgedAssertion(requestId, VICTIM)),
			),
		).rejects.toThrow(invalidSignature(/carries no signature/));
	});
});

describe("transit > saml > the envelope of a response", () => {
	const content = (requestId: string) => unsigned(assertion(requestId));

	it("refuses a signed response sent to another address", async () => {
		await expect(
			signIn((requestId) =>
				signedResponse(requestId, content(requestId), {
					destination: "https://other.acme.test/saml/acs",
				}),
			),
		).rejects.toThrow(rejected(/the response was sent to/));
	});

	it("refuses a signed response that names no destination", async () => {
		await expect(
			signIn((requestId) =>
				signedResponse(requestId, content(requestId), { destination: null }),
			),
		).rejects.toThrow(rejected(/signed and names no destination/));
	});

	it("refuses a signed response from another issuer", async () => {
		await expect(
			signIn((requestId) =>
				signedResponse(requestId, content(requestId), {
					issuer: "https://idp.evil.test/metadata",
				}),
			),
		).rejects.toThrow(rejected(/the response is issued by/));
	});

	it("refuses a signed response that names no issuer", async () => {
		await expect(
			signIn((requestId) =>
				signedResponse(requestId, content(requestId), { issuer: null }),
			),
		).rejects.toThrow(rejected(/signed and names no issuer/));
	});

	it("refuses a response answering another request than its assertion", async () => {
		await expect(
			signIn((requestId) =>
				signedResponse(requestId, content(requestId), {
					inResponseTo: "_someone-elses-request",
				}),
			),
		).rejects.toThrow(rejected(/the response answers a different request/));
	});

	it("refuses an unsigned response that says it was sent elsewhere", async () => {
		await expect(
			signIn((requestId) =>
				unsignedResponse(requestId, signedAssertion(requestId), {
					destination: "https://other.acme.test/saml/acs",
				}),
			),
		).rejects.toThrow(rejected(/the response was sent to/));
	});
});
