/**
 * The XML reader.
 *
 * It exists to hold a SAML document still enough that a signature over part of
 * it can be checked, so what it REFUSES matters as much as what it parses.
 */
import { describe, expect, it } from "vitest";
import {
	childrenNamed,
	findByAttribute,
	parseXml,
	resolvePrefix,
	textOf,
	XML_NS,
} from "../../src/xml.js";

describe("transit > xml > what it refuses", () => {
	it("refuses a DOCTYPE outright", () => {
		// One rule closing external entities and expansion bombs together. A
		// signed assertion has no legitimate reason to carry one.
		expect(() => parseXml('<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>')).toThrow(
			/DOCTYPE/,
		);
	});

	it("refuses an entity it does not define", () => {
		expect(() => parseXml("<r>&whoKnows;</r>")).toThrow(/unknown entity/);
	});

	it("refuses a document with two roots", () => {
		expect(() => parseXml("<a/><b/>")).toThrow(/more than one root/);
	});

	it("refuses a mismatched closing tag", () => {
		expect(() => parseXml("<a></b>")).toThrow(/closed by/);
	});

	it("refuses an unclosed element", () => {
		expect(() => parseXml("<a><b></b>")).toThrow(/never closed/);
	});

	it("refuses an unbound prefix", () => {
		// A parser that shrugged here would resolve two different documents to
		// the same tree.
		expect(() => parseXml("<p:a/>")).toThrow(/unbound prefix 'p'/);
		expect(() => parseXml('<a p:x="1"/>')).toThrow(/unbound prefix 'p'/);
	});

	it("refuses a repeated attribute or prefix", () => {
		expect(() => parseXml('<a x="1" x="2"/>')).toThrow(/same attribute twice/);
		expect(() => parseXml('<a xmlns:p="u" xmlns:p="v"/>')).toThrow(
			/prefix twice/,
		);
	});

	it("refuses an unquoted attribute value", () => {
		expect(() => parseXml("<a x=1/>")).toThrow(/not quoted/);
	});
});

describe("transit > xml > namespaces", () => {
	it("resolves a prefix from the nearest declaration", () => {
		const root = parseXml(
			'<r xmlns:p="urn:one"><c xmlns:p="urn:two"><d p:x="1"/></c></r>',
		);
		const c = root
			.children[0] as never as import("../../src/xml.js").XmlElement;
		const d = c.children[0] as never as import("../../src/xml.js").XmlElement;

		expect(resolvePrefix(root, "p")).toBe("urn:one");
		expect(resolvePrefix(d, "p")).toBe("urn:two");
	});

	it("binds the xml prefix without a declaration", () => {
		const root = parseXml('<r xml:lang="en"/>');

		expect(resolvePrefix(root, "xml")).toBe(XML_NS);
		expect(root.attributes[0]?.namespaceUri).toBe(XML_NS);
	});

	it("leaves an unprefixed attribute in no namespace", () => {
		const root = parseXml('<r xmlns="urn:d" x="1"/>');

		// The default namespace applies to elements, never to attributes —
		// getting this wrong changes the canonical form.
		expect(root.namespaceUri).toBe("urn:d");
		expect(root.attributes[0]?.namespaceUri).toBe("");
	});

	it("lets a declaration on an element bind that element's own prefix", () => {
		const root = parseXml('<p:r xmlns:p="urn:x"/>');

		expect(root.namespaceUri).toBe("urn:x");
	});
});

describe("transit > xml > content", () => {
	it("normalises line endings before anything else", () => {
		// The canonicalization specification requires it; without it the same
		// document signed on Windows digests differently.
		expect(textOf(parseXml("<r>a\r\nb\rc</r>"))).toBe("a\nb\nc");
	});

	it("reads CDATA as text", () => {
		expect(textOf(parseXml("<r><![CDATA[a < b & c]]></r>"))).toBe("a < b & c");
	});

	it("resolves the five entities and numeric references", () => {
		expect(
			textOf(parseXml("<r>&lt;&amp;&gt;&quot;&apos;&#65;&#x42;</r>")),
		).toBe("<&>\"'AB");
	});

	it("normalises tabs and newlines inside an attribute value", () => {
		const root = parseXml('<r x="a\tb\nc"/>');

		expect(root.attributes[0]?.value).toBe("a b c");
	});

	it("keeps comments and processing instructions apart from text", () => {
		const root = parseXml("<r><!-- note --><?php echo ?>text</r>");

		expect(root.children.map((c) => c.type)).toEqual([
			"comment",
			"instruction",
			"text",
		]);
		expect(textOf(root)).toBe("text");
	});
});

describe("transit > xml > finding things", () => {
	const doc = parseXml(
		'<r xmlns="urn:s"><a ID="one"/><b ID="two"><a/></b></r>',
	);

	it("finds an element by attribute value", () => {
		expect(findByAttribute(doc, "ID", "two")?.local).toBe("b");
		expect(findByAttribute(doc, "ID", "nope")).toBeUndefined();
	});

	it("lists direct children by name and namespace", () => {
		// The nested <a> is not a direct child, and must not be counted.
		expect(childrenNamed(doc, "urn:s", "a")).toHaveLength(1);
		expect(childrenNamed(doc, "urn:other", "a")).toHaveLength(0);
	});
});
