/**
 * A namespace-aware XML reader, written for one job: holding a SAML document
 * still enough that a signature over part of it can be checked.
 *
 * It refuses more than it parses, and that is the point.
 *
 *   - **No DOCTYPE.** One rule, and it closes external entities (XXE) and the
 *     billion-laughs expansion at the same time. A signed assertion has no
 *     legitimate reason to carry one.
 *   - **No entity references** beyond the five XML defines and numeric ones,
 *     for the same reason.
 *   - Anything malformed throws rather than being repaired. A parser that
 *     guesses at broken input hands a verifier a document the sender never
 *     wrote, and the two then disagree about what was signed.
 *
 * The tree keeps the parent link and the namespace declarations exactly where
 * they appeared, because canonicalization needs both.
 */

/** The prefix bound by the XML specification itself; never declared. */
export const XML_NS = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS = "http://www.w3.org/2000/xmlns/";

export interface XmlNamespace {
	/** `""` for the default namespace. */
	prefix: string;
	uri: string;
}

export interface XmlAttribute {
	prefix: string;
	local: string;
	qname: string;
	/** `""` for an unprefixed attribute, which is in no namespace. */
	namespaceUri: string;
	value: string;
}

export interface XmlElement {
	type: "element";
	prefix: string;
	local: string;
	qname: string;
	namespaceUri: string;
	/** Declarations that appear ON this element, not the ones in scope. */
	namespaces: XmlNamespace[];
	attributes: XmlAttribute[];
	children: XmlNode[];
	parent: XmlElement | undefined;
}

export interface XmlText {
	type: "text";
	value: string;
}

export interface XmlComment {
	type: "comment";
	value: string;
}

export interface XmlInstruction {
	type: "instruction";
	target: string;
	data: string;
}

export type XmlNode = XmlElement | XmlText | XmlComment | XmlInstruction;

class XmlError extends Error {
	constructor(message: string) {
		super(`[transit] ${message}`);
		this.name = "XmlError";
	}
}

/** Parse a document and return its root element. */
export function parseXml(source: string): XmlElement {
	// Line endings are normalised before parsing, as the canonicalization
	// specification requires — otherwise the same document signed on one
	// platform digests differently on another.
	const input = source.replace(/\r\n?/g, "\n");
	const parser = new Parser(input);
	return parser.document();
}

/** The URI a prefix resolves to at this element, or `undefined`. */
export function resolvePrefix(
	element: XmlElement,
	prefix: string,
): string | undefined {
	if (prefix === "xml") return XML_NS;
	for (
		let node: XmlElement | undefined = element;
		node !== undefined;
		node = node.parent
	) {
		const found = node.namespaces.find((ns) => ns.prefix === prefix);
		if (found) return found.uri;
	}
	return prefix === "" ? "" : undefined;
}

/** Every element under `element`, including it, in document order. */
export function* walk(element: XmlElement): Generator<XmlElement> {
	yield element;
	for (const child of element.children) {
		if (child.type === "element") yield* walk(child);
	}
}

/** The first element carrying `attribute` with `value`, searched in order. */
export function findByAttribute(
	root: XmlElement,
	attribute: string,
	value: string,
): XmlElement | undefined {
	for (const element of walk(root)) {
		if (
			element.attributes.some((a) => a.local === attribute && a.value === value)
		) {
			return element;
		}
	}
	return undefined;
}

/** Direct element children named `local` in `namespaceUri`. */
export function childrenNamed(
	element: XmlElement,
	namespaceUri: string,
	local: string,
): XmlElement[] {
	return element.children.filter(
		(child): child is XmlElement =>
			child.type === "element" &&
			child.local === local &&
			child.namespaceUri === namespaceUri,
	);
}

/** The concatenated text of an element, descendants included. */
export function textOf(element: XmlElement): string {
	let out = "";
	for (const child of element.children) {
		if (child.type === "text") out += child.value;
		else if (child.type === "element") out += textOf(child);
	}
	return out;
}

class Parser {
	#at = 0;
	constructor(private readonly source: string) {}

	document(): XmlElement {
		let root: XmlElement | undefined;
		while (this.#at < this.source.length) {
			this.#skipSpace();
			if (this.#at >= this.source.length) break;
			if (this.#peek("<?xml")) {
				this.#skipTo("?>");
				continue;
			}
			if (this.#peek("<!DOCTYPE") || this.#peek("<!ENTITY")) {
				throw new XmlError(
					"the document carries a DOCTYPE, which this refuses: it is how external entities and expansion bombs get in.",
				);
			}
			if (this.#peek("<!--")) {
				this.#skipTo("-->");
				continue;
			}
			if (this.#peek("<?")) {
				this.#skipTo("?>");
				continue;
			}
			if (root !== undefined) {
				throw new XmlError("the document has more than one root element");
			}
			root = this.#element(undefined);
		}
		if (root === undefined) throw new XmlError("the document has no element");
		return root;
	}

	#element(parent: XmlElement | undefined): XmlElement {
		this.#expect("<");
		const qname = this.#name();
		const element: XmlElement = {
			type: "element",
			prefix: "",
			local: "",
			qname,
			namespaceUri: "",
			namespaces: [],
			attributes: [],
			children: [],
			parent,
		};

		// Attributes are read before anything is resolved: a declaration on this
		// element binds the element's own prefix too.
		const raw: Array<{ qname: string; value: string }> = [];
		for (;;) {
			this.#skipSpace();
			if (this.#peek("/>") || this.#peek(">")) break;
			const name = this.#name();
			this.#skipSpace();
			this.#expect("=");
			this.#skipSpace();
			raw.push({ qname: name, value: this.#attributeValue() });
		}

		for (const { qname: name, value } of raw) {
			if (name === "xmlns") {
				element.namespaces.push({ prefix: "", uri: value });
			} else if (name.startsWith("xmlns:")) {
				const prefix = name.slice(6);
				if (prefix === "") throw new XmlError("empty namespace prefix");
				element.namespaces.push({ prefix, uri: value });
			}
		}
		if (
			new Set(element.namespaces.map((n) => n.prefix)).size !==
			element.namespaces.length
		) {
			throw new XmlError(`element <${qname}> declares a prefix twice`);
		}

		const [prefix, local] = split(qname);
		element.prefix = prefix;
		element.local = local;
		const uri = resolvePrefix(element, prefix);
		if (uri === undefined) {
			throw new XmlError(
				`element <${qname}> uses the unbound prefix '${prefix}'`,
			);
		}
		element.namespaceUri = uri;

		for (const { qname: name, value } of raw) {
			if (name === "xmlns" || name.startsWith("xmlns:")) continue;
			const [attrPrefix, attrLocal] = split(name);
			// An unprefixed attribute is in NO namespace — it does not pick up the
			// default one. Getting this wrong changes canonical output.
			let attrUri = "";
			if (attrPrefix !== "") {
				const resolved = resolvePrefix(element, attrPrefix);
				if (resolved === undefined) {
					throw new XmlError(
						`attribute '${name}' uses the unbound prefix '${attrPrefix}'`,
					);
				}
				attrUri = resolved;
			}
			element.attributes.push({
				prefix: attrPrefix,
				local: attrLocal,
				qname: name,
				namespaceUri: attrUri === XMLNS_NS ? "" : attrUri,
				value,
			});
		}
		if (
			new Set(element.attributes.map((a) => `${a.namespaceUri}|${a.local}`))
				.size !== element.attributes.length
		) {
			throw new XmlError(`element <${qname}> carries the same attribute twice`);
		}

		if (this.#take("/>")) return element;
		this.#expect(">");

		for (;;) {
			if (this.#at >= this.source.length) {
				throw new XmlError(`<${qname}> is never closed`);
			}
			if (this.#peek("</")) {
				this.#expect("</");
				const closing = this.#name();
				if (closing !== qname) {
					throw new XmlError(`<${qname}> is closed by </${closing}>`);
				}
				this.#skipSpace();
				this.#expect(">");
				return element;
			}
			if (this.#peek("<!--")) {
				const end = this.source.indexOf("-->", this.#at);
				if (end === -1) throw new XmlError("a comment is never closed");
				element.children.push({
					type: "comment",
					value: this.source.slice(this.#at + 4, end),
				});
				this.#at = end + 3;
				continue;
			}
			if (this.#peek("<![CDATA[")) {
				const end = this.source.indexOf("]]>", this.#at);
				if (end === -1) throw new XmlError("a CDATA section is never closed");
				element.children.push({
					type: "text",
					value: this.source.slice(this.#at + 9, end),
				});
				this.#at = end + 3;
				continue;
			}
			if (this.#peek("<!")) {
				throw new XmlError("the document carries a declaration this refuses");
			}
			if (this.#peek("<?")) {
				const end = this.source.indexOf("?>", this.#at);
				if (end === -1)
					throw new XmlError("a processing instruction is never closed");
				const body = this.source.slice(this.#at + 2, end);
				const space = body.search(/\s/);
				element.children.push({
					type: "instruction",
					target: space === -1 ? body : body.slice(0, space),
					data: space === -1 ? "" : body.slice(space + 1),
				});
				this.#at = end + 2;
				continue;
			}
			if (this.#peek("<")) {
				element.children.push(this.#element(element));
				continue;
			}
			const next = this.source.indexOf("<", this.#at);
			const end = next === -1 ? this.source.length : next;
			element.children.push({
				type: "text",
				value: resolveEntities(this.source.slice(this.#at, end)),
			});
			this.#at = end;
		}
	}

	#attributeValue(): string {
		const quote = this.source[this.#at];
		if (quote !== '"' && quote !== "'") {
			throw new XmlError("an attribute value is not quoted");
		}
		this.#at += 1;
		const end = this.source.indexOf(quote, this.#at);
		if (end === -1) throw new XmlError("an attribute value is never closed");
		const raw = this.source.slice(this.#at, end);
		this.#at = end + 1;
		if (raw.includes("<")) {
			throw new XmlError("an attribute value contains '<'");
		}
		// Attribute-value normalisation, and the order matters: a LITERAL tab or
		// newline becomes a space, while `&#x9;` stays a tab. Unescaping first
		// would flatten the reference too, and the canonical form would then
		// differ from the signer's by exactly that byte.
		return resolveEntities(raw.replace(/[\t\n]/g, " "));
	}

	#name(): string {
		const match = /^[A-Za-z_:][\w.\-:]*/.exec(this.source.slice(this.#at));
		if (!match) throw new XmlError(`expected a name at offset ${this.#at}`);
		this.#at += match[0].length;
		return match[0];
	}

	#skipSpace(): void {
		while (
			this.#at < this.source.length &&
			/\s/.test(this.source[this.#at] as string)
		) {
			this.#at += 1;
		}
	}

	#skipTo(marker: string): void {
		const end = this.source.indexOf(marker, this.#at);
		if (end === -1) throw new XmlError(`'${marker}' is missing`);
		this.#at = end + marker.length;
	}

	#peek(text: string): boolean {
		return this.source.startsWith(text, this.#at);
	}

	#take(text: string): boolean {
		if (!this.#peek(text)) return false;
		this.#at += text.length;
		return true;
	}

	#expect(text: string): void {
		if (!this.#take(text)) {
			throw new XmlError(`expected '${text}' at offset ${this.#at}`);
		}
	}
}

function split(qname: string): [prefix: string, local: string] {
	const colon = qname.indexOf(":");
	return colon === -1
		? ["", qname]
		: [qname.slice(0, colon), qname.slice(colon + 1)];
}

/**
 * Resolve the five entities XML defines, and numeric references. Anything else
 * is refused rather than passed through: an unknown entity in a signed document
 * means the sender expected a declaration this parser will not read.
 */
function resolveEntities(text: string): string {
	return text.replace(
		/&(#x?[0-9A-Fa-f]+|[A-Za-z]+);/g,
		(whole, body: string) => {
			switch (body) {
				case "amp":
					return "&";
				case "lt":
					return "<";
				case "gt":
					return ">";
				case "quot":
					return '"';
				case "apos":
					return "'";
				default:
					break;
			}
			if (body.startsWith("#x") || body.startsWith("#X")) {
				return String.fromCodePoint(Number.parseInt(body.slice(2), 16));
			}
			if (body.startsWith("#")) {
				return String.fromCodePoint(Number.parseInt(body.slice(1), 10));
			}
			throw new XmlError(`unknown entity '${whole}'`);
		},
	);
}
