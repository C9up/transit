/**
 * XML Signature verification.
 *
 * The danger in XML-DSig is not the cryptography — it is that a signature can
 * be perfectly valid over one part of a document while the application reads
 * another. That is XML Signature Wrapping, and it has broken SAML
 * implementations repeatedly. The mitigation is structural, not a check:
 *
 *   **This returns the element the signature actually covers, and the caller
 *   must read that object. Never search the document again afterwards.**
 *
 * Everything else here exists to make that guarantee hold:
 *
 *   - Exactly one reference. Several is not a shape a signed assertion needs,
 *     and it multiplies what "the signed element" could mean.
 *   - The reference must resolve to exactly ONE element. A second element
 *     carrying the same ID is the classic wrapping payload.
 *   - The signature must sit inside the element it signs. A signature that
 *     references a sibling is describing a document this refuses to reason
 *     about.
 *   - Only the enveloped-signature and exclusive-c14n transforms are accepted.
 *     XPath and XSLT transforms are a way to make the digest cover something
 *     other than the element, and XSLT is executable.
 *   - SHA-1 is refused. Collisions against it are practical, and a signature
 *     over attacker-influenced XML is exactly where that matters.
 *   - The key comes from the caller, from the provider's metadata. The
 *     certificate embedded in the document is checked against it, never
 *     trusted on its own: verifying a document against a key it carries is
 *     verifying it against itself.
 */

import {
	createHash,
	type KeyObject,
	verify as verifySignature,
	X509Certificate,
} from "node:crypto";
import { canonicalize } from "./c14n.js";
import {
	childrenNamed,
	textOf,
	walk,
	type XmlElement,
	type XmlNode,
} from "./xml.js";

export const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const EC_NS = "http://www.w3.org/2001/10/xml-exc-c14n#";

/** Digest algorithms, by their URI. SHA-1 is absent on purpose. */
const DIGESTS: Record<string, string> = {
	"http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
	"http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
};

/** Signature algorithms, by their URI. SHA-1 is absent on purpose. */
const SIGNATURES: Record<string, { hash: string; kind: "rsa" | "ec" }> = {
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": {
		hash: "sha256",
		kind: "rsa",
	},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": {
		hash: "sha384",
		kind: "rsa",
	},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": {
		hash: "sha512",
		kind: "rsa",
	},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": {
		hash: "sha256",
		kind: "ec",
	},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": {
		hash: "sha384",
		kind: "ec",
	},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": {
		hash: "sha512",
		kind: "ec",
	},
};

export class SignatureError extends Error {
	constructor(message: string) {
		super(`[transit] ${message}`);
		this.name = "SignatureError";
	}
}

export interface VerifyOptions {
	/**
	 * The provider's signing certificates, from its metadata — PEM, or the
	 * bare base64 an `<X509Certificate>` element carries. Several are accepted
	 * so a rotation can be prepared before it happens.
	 */
	certificates: string[];
}

/**
 * Verify one signature under `root`, and answer with the element it covers.
 *
 * Read the returned element. Reading anything found by searching the document
 * afterwards throws the guarantee away.
 */
export function verifyXmlSignature(
	root: XmlElement,
	options: VerifyOptions,
): XmlElement {
	const signatures = [...walk(root)].filter(
		(element) =>
			element.namespaceUri === DSIG_NS && element.local === "Signature",
	);
	if (signatures.length === 0) {
		throw new SignatureError("the document carries no signature");
	}
	if (signatures.length > 1) {
		// Which one covers what a reader will use is exactly the ambiguity
		// wrapping attacks live in.
		throw new SignatureError(
			`the document carries ${signatures.length} signatures, and this verifies documents with one`,
		);
	}
	const signature = signatures[0] as XmlElement;

	const signedInfo = only(signature, "SignedInfo");
	const method = only(signedInfo, "SignatureMethod").attributes.find(
		(a) => a.local === "Algorithm",
	)?.value;
	const spec = method === undefined ? undefined : SIGNATURES[method];
	if (spec === undefined) {
		throw new SignatureError(
			`the signature uses '${method ?? "no algorithm"}', which this refuses. SHA-1 and the symmetric methods are not accepted.`,
		);
	}

	const canonicalizationMethod = only(
		signedInfo,
		"CanonicalizationMethod",
	).attributes.find((a) => a.local === "Algorithm")?.value;
	if (
		canonicalizationMethod !== EXC_C14N &&
		canonicalizationMethod !== EXC_C14N_COMMENTS
	) {
		throw new SignatureError(
			`SignedInfo is canonicalized with '${canonicalizationMethod ?? "nothing"}', and this verifies exclusive canonicalization`,
		);
	}

	// The signature is over SignedInfo, canonicalized. Everything the reference
	// claims is only trustworthy once this holds.
	const signedBytes = Buffer.from(
		canonicalize(signedInfo, {
			withComments: canonicalizationMethod === EXC_C14N_COMMENTS,
		}),
		"utf8",
	);
	const signatureValue = Buffer.from(
		textOf(only(signature, "SignatureValue")).replace(/\s+/g, ""),
		"base64",
	);

	// `some` stops at the first key that holds. Any of the provider's listed
	// certificates is an acceptable signer; none of them is attacker-supplied.
	const holds = resolveKeys(signature, options.certificates).some((key) =>
		verifySignature(
			spec.hash,
			signedBytes,
			spec.kind === "ec" ? { key, dsaEncoding: "ieee-p1363" } : key,
			signatureValue,
		),
	);
	if (!holds) {
		throw new SignatureError("the signature does not verify");
	}

	return verifyReference(root, signature, signedInfo);
}

/**
 * Check the digest, and answer with the element it was computed over.
 *
 * The element is resolved once, here, and handed back. That is the whole
 * defence: a caller that uses this object cannot be reading a different part of
 * the document than the one the signature covers.
 */
function verifyReference(
	root: XmlElement,
	signature: XmlElement,
	signedInfo: XmlElement,
): XmlElement {
	const references = childrenNamed(signedInfo, DSIG_NS, "Reference");
	if (references.length !== 1) {
		throw new SignatureError(
			`SignedInfo carries ${references.length} references, and this verifies one`,
		);
	}
	const reference = references[0] as XmlElement;

	const uri = reference.attributes.find((a) => a.local === "URI")?.value;
	if (uri === undefined || !uri.startsWith("#") || uri.length < 2) {
		throw new SignatureError(
			`the reference points at '${uri ?? "nothing"}', and this verifies a same-document '#id' reference`,
		);
	}
	const id = uri.slice(1);

	const matches = [...walk(root)].filter((element) =>
		element.attributes.some(
			(a) => a.namespaceUri === "" && isIdAttribute(a.local) && a.value === id,
		),
	);
	if (matches.length === 0) {
		throw new SignatureError(
			`the reference names '${id}', which is not in the document`,
		);
	}
	if (matches.length > 1) {
		// A second element carrying the signed element's ID is the classic
		// wrapping payload: the signature stays valid, and a reader that looks
		// the ID up finds the attacker's copy.
		throw new SignatureError(
			`${matches.length} elements carry the id '${id}', which is how a signature gets pointed at the wrong one`,
		);
	}
	const signed = matches[0] as XmlElement;

	if (!contains(signed, signature)) {
		throw new SignatureError(
			"the signature sits outside the element it references, which this refuses to reason about",
		);
	}

	const { inclusivePrefixes, withComments } = readTransforms(
		reference,
		signature,
	);

	const digestMethod = only(reference, "DigestMethod").attributes.find(
		(a) => a.local === "Algorithm",
	)?.value;
	const hash = digestMethod === undefined ? undefined : DIGESTS[digestMethod];
	if (hash === undefined) {
		throw new SignatureError(
			`the digest uses '${digestMethod ?? "no algorithm"}', which this refuses. SHA-1 is not accepted.`,
		);
	}

	// The enveloped-signature transform: the element cannot carry a digest of
	// itself, so the signature is left out of what is hashed.
	const omit: ReadonlySet<XmlNode> = new Set<XmlNode>([signature]);
	const digest = createHash(hash)
		.update(
			canonicalize(signed, { inclusivePrefixes, withComments, omit }),
			"utf8",
		)
		.digest("base64");

	const expected = textOf(only(reference, "DigestValue")).replace(/\s+/g, "");
	if (digest !== expected) {
		throw new SignatureError(
			"the signed element does not match its digest — it was changed after signing",
		);
	}

	return signed;
}

/** Which transforms the reference asks for, refusing the dangerous ones. */
function readTransforms(
	reference: XmlElement,
	signature: XmlElement,
): { inclusivePrefixes: string[]; withComments: boolean } {
	const container = childrenNamed(reference, DSIG_NS, "Transforms")[0];
	const transforms = container
		? childrenNamed(container, DSIG_NS, "Transform")
		: [];

	let sawEnveloped = false;
	let inclusivePrefixes: string[] = [];
	let withComments = false;

	for (const transform of transforms) {
		const algorithm = transform.attributes.find(
			(a) => a.local === "Algorithm",
		)?.value;
		if (algorithm === ENVELOPED) {
			sawEnveloped = true;
			continue;
		}
		if (algorithm === EXC_C14N || algorithm === EXC_C14N_COMMENTS) {
			withComments = algorithm === EXC_C14N_COMMENTS;
			const list = childrenNamed(transform, EC_NS, "InclusiveNamespaces")[0];
			const prefixes = list?.attributes.find(
				(a) => a.local === "PrefixList",
			)?.value;
			if (prefixes) {
				inclusivePrefixes = prefixes.split(/\s+/).filter(Boolean);
			}
			continue;
		}
		// XPath and XSLT can make the digest cover something other than the
		// element, and one of them is executable.
		throw new SignatureError(
			`the reference asks for the transform '${algorithm ?? "(none)"}', which this refuses`,
		);
	}

	if (!sawEnveloped && contains(signature.parent ?? signature, signature)) {
		// A signature inside the element it signs has to be excluded from the
		// digest, and the transform is how that is declared.
		throw new SignatureError(
			"the signature is inside the element it signs and does not declare the enveloped-signature transform",
		);
	}
	return { inclusivePrefixes, withComments };
}

/**
 * The keys to verify with — the caller's, from the provider's metadata.
 *
 * When the document carries a certificate it must be one of them, and that one
 * alone is returned. The check gives a clear error instead of an opaque "does
 * not verify" when a provider has rotated and the metadata has not been
 * updated.
 *
 * Without one, every certificate the metadata lists is a candidate. A provider
 * mid-rotation publishes the outgoing and the incoming certificate together and
 * signs with either; trying only the first would reject every assertion signed
 * with the other, for the whole rotation window, under a message blaming the
 * signature. `certificates` is plural for this reason.
 */
function resolveKeys(
	signature: XmlElement,
	certificates: string[],
): KeyObject[] {
	if (certificates.length === 0) {
		throw new SignatureError(
			"no certificate was supplied — the key has to come from the provider's metadata, never from the document itself",
		);
	}
	const known = certificates.map(toCertificate);
	const embedded = embeddedCertificate(signature);
	if (embedded !== undefined) {
		const match = known.find((cert) => cert.raw.equals(embedded.raw));
		if (!match) {
			throw new SignatureError(
				"the document is signed with a certificate the provider's metadata does not list",
			);
		}
		return [match.publicKey];
	}
	return known.map((cert) => cert.publicKey);
}

function embeddedCertificate(
	signature: XmlElement,
): X509Certificate | undefined {
	for (const element of walk(signature)) {
		if (
			element.namespaceUri === DSIG_NS &&
			element.local === "X509Certificate"
		) {
			return toCertificate(textOf(element));
		}
	}
	return undefined;
}

function toCertificate(value: string): X509Certificate {
	const trimmed = value.trim();
	const pem = trimmed.includes("BEGIN CERTIFICATE")
		? trimmed
		: `-----BEGIN CERTIFICATE-----\n${trimmed.replace(/\s+/g, "").replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----`;
	try {
		return new X509Certificate(pem);
	} catch {
		throw new SignatureError("a certificate could not be read");
	}
}

/** Exactly one child named `local`, or a clear refusal. */
function only(parent: XmlElement, local: string): XmlElement {
	const found = childrenNamed(parent, DSIG_NS, local);
	if (found.length !== 1) {
		throw new SignatureError(
			`expected one <${local}> under <${parent.local}>, and there are ${found.length}`,
		);
	}
	return found[0] as XmlElement;
}

/** Whether `descendant` sits inside `ancestor`, or is it. */
function contains(ancestor: XmlElement, descendant: XmlElement): boolean {
	for (
		let node: XmlElement | undefined = descendant;
		node !== undefined;
		node = node.parent
	) {
		if (node === ancestor) return true;
	}
	return false;
}

/**
 * SAML identifies signed elements with `ID`; other dialects use `Id` or `id`.
 * All three are accepted, and a document mixing them is what the
 * duplicate check above catches.
 */
function isIdAttribute(local: string): boolean {
	return local === "ID" || local === "Id" || local === "id";
}
