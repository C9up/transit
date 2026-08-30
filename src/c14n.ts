/**
 * Exclusive XML Canonicalization (`xml-exc-c14n#`).
 *
 * A signature is over BYTES, and two parties only agree on which bytes if they
 * agree on this algorithm exactly. Every rule below comes from the
 * specification, and the awkward ones are the ones that matter:
 *
 *   - Only namespaces an element **visibly utilizes** are written out, and only
 *     when an output ancestor has not already written the same prefix with the
 *     same value. That is what makes a signed fragment survive being moved
 *     between documents — and it is the whole reason exclusive exists.
 *   - An unprefixed attribute is in NO namespace, so it never makes the default
 *     namespace visibly utilized.
 *   - The `xml` prefix is bound by the XML specification and is never declared.
 *
 * Getting any of these wrong yields a canonical form that differs from the
 * signer's by a few bytes, and every signature then fails — or, worse, one is
 * accepted over a document that is not the one that was signed.
 */

import {
	resolvePrefix,
	XML_NS,
	type XmlAttribute,
	type XmlElement,
	type XmlNode,
} from "./xml.js";

export interface CanonicalizeOptions {
	/**
	 * Prefixes to treat the inclusive way, from a `<InclusiveNamespaces
	 * PrefixList="…">` transform parameter.
	 */
	inclusivePrefixes?: string[];
	/** Comments are excluded unless the algorithm says otherwise. */
	withComments?: boolean;
	/**
	 * Nodes to leave out of the output — what the enveloped-signature transform
	 * needs, since an element cannot carry a digest of itself.
	 */
	omit?: ReadonlySet<XmlNode>;
}

/** The canonical form of an element and everything under it. */
export function canonicalize(
	element: XmlElement,
	options: CanonicalizeOptions = {},
): string {
	const out: string[] = [];
	writeElement(element, out, new Map(), options);
	return out.join("");
}

/**
 * The prefixes this element makes visible: its own, and those of its
 * attributes. The default namespace counts only when the element itself has no
 * prefix.
 */
function visiblyUtilized(
	element: XmlElement,
	inclusivePrefixes: string[],
): Set<string> {
	const used = new Set<string>([element.prefix]);
	for (const attribute of element.attributes) {
		if (attribute.prefix !== "") used.add(attribute.prefix);
	}
	// The prefix list is handled inclusively: a listed prefix is rendered
	// whenever it is in scope, utilized or not.
	for (const prefix of inclusivePrefixes) {
		if (resolvePrefix(element, prefix) !== undefined) used.add(prefix);
	}
	// Never declared — the specification binds it.
	used.delete("xml");
	return used;
}

function writeElement(
	element: XmlElement,
	out: string[],
	rendered: Map<string, string>,
	options: CanonicalizeOptions,
): void {
	const inclusive = options.inclusivePrefixes ?? [];
	const utilized = [...visiblyUtilized(element, inclusive)].sort(compare);

	const declarations: Array<[prefix: string, uri: string]> = [];
	const childRendered = new Map(rendered);

	for (const prefix of utilized) {
		const uri = resolvePrefix(element, prefix) ?? "";
		if (prefix === "" && uri === "") {
			// `xmlns=""` is written only to undo a default namespace an output
			// ancestor put in scope. Writing it otherwise is noise the signer
			// did not produce.
			if ((rendered.get("") ?? "") !== "") {
				declarations.push(["", ""]);
				childRendered.set("", "");
			}
			continue;
		}
		if (rendered.get(prefix) !== uri) {
			declarations.push([prefix, uri]);
			childRendered.set(prefix, uri);
		}
	}

	out.push("<", element.qname);
	for (const [prefix, uri] of declarations) {
		out.push(
			" ",
			prefix === "" ? "xmlns" : `xmlns:${prefix}`,
			'="',
			escapeAttribute(uri),
			'"',
		);
	}
	for (const attribute of [...element.attributes].sort(byNamespaceThenLocal)) {
		out.push(" ", attribute.qname, '="', escapeAttribute(attribute.value), '"');
	}
	out.push(">");

	for (const child of element.children) {
		if (options.omit?.has(child)) continue;
		writeNode(child, out, childRendered, options);
	}

	// Empty elements are written as a start/end pair, never self-closed.
	out.push("</", element.qname, ">");
}

function writeNode(
	node: XmlNode,
	out: string[],
	rendered: Map<string, string>,
	options: CanonicalizeOptions,
): void {
	switch (node.type) {
		case "element":
			writeElement(node, out, rendered, options);
			return;
		case "text":
			out.push(escapeText(node.value));
			return;
		case "comment":
			if (options.withComments) out.push("<!--", node.value, "-->");
			return;
		case "instruction":
			out.push(
				"<?",
				node.target,
				node.data === "" ? "" : ` ${node.data}`,
				"?>",
			);
			return;
	}
}

/** Namespace URI first, then local name; an empty URI sorts least. */
function byNamespaceThenLocal(a: XmlAttribute, b: XmlAttribute): number {
	const uri = compare(a.namespaceUri, b.namespaceUri);
	return uri !== 0 ? uri : compare(a.local, b.local);
}

/** Byte order, which is what the specification means by lexicographic here. */
function compare(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

function escapeText(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/\r/g, "&#xD;");
}

function escapeAttribute(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/"/g, "&quot;")
		.replace(/\t/g, "&#x9;")
		.replace(/\n/g, "&#xA;")
		.replace(/\r/g, "&#xD;");
}

export { XML_NS };
