/**
 * Exclusive canonicalization.
 *
 * A signature is over bytes, so this either produces exactly what the signer
 * produced or every signature fails. The rules asserted here are the
 * specification's, and the awkward ones are the ones that decide it.
 */
import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/c14n.js";
import { parseXml, walk } from "../../src/xml.js";

/** Canonicalize the element carrying `ID`, as a signature reference does. */
function c14nOf(
	xml: string,
	id?: string,
	inclusivePrefixes?: string[],
): string {
	const root = parseXml(xml);
	const target = id
		? [...walk(root)].find((e) =>
				e.attributes.some((a) => a.local === "ID" && a.value === id),
			)
		: root;
	if (!target) throw new Error(`no element with ID '${id}'`);
	return canonicalize(target, { inclusivePrefixes });
}

describe("transit > c14n > the shape of the output", () => {
	it("writes an empty element as a start and end pair", () => {
		expect(c14nOf("<a/>")).toBe("<a></a>");
	});

	it("drops the XML declaration", () => {
		expect(c14nOf('<?xml version="1.0" encoding="UTF-8"?><a/>')).toBe(
			"<a></a>",
		);
	});

	it("drops comments", () => {
		expect(c14nOf("<a><!-- gone -->text</a>")).toBe("<a>text</a>");
	});

	it("keeps processing instructions", () => {
		expect(c14nOf("<a><?target data?></a>")).toBe("<a><?target data?></a>");
	});
});

describe("transit > c14n > ordering", () => {
	it("puts namespace declarations before attributes", () => {
		expect(c14nOf('<p:a z="1" xmlns:p="urn:p"/>')).toBe(
			'<p:a xmlns:p="urn:p" z="1"></p:a>',
		);
	});

	it("sorts declarations by prefix, the default one first", () => {
		expect(
			c14nOf(
				'<a xmlns:z="urn:z" xmlns:b="urn:b" xmlns="urn:d" b:x="1" z:y="2"/>',
			),
		).toBe(
			'<a xmlns="urn:d" xmlns:b="urn:b" xmlns:z="urn:z" b:x="1" z:y="2"></a>',
		);
	});

	it("sorts attributes by namespace URI, then by local name", () => {
		// An unprefixed attribute has an empty URI, which sorts least — so `zz`
		// comes before a namespaced `aa`.
		expect(c14nOf('<a xmlns:p="urn:p" p:aa="1" zz="2" bb="3"/>')).toBe(
			'<a xmlns:p="urn:p" bb="3" zz="2" p:aa="1"></a>',
		);
	});
});

describe("transit > c14n > escaping", () => {
	it("escaves the three characters text needs, and a carriage return", () => {
		expect(c14nOf("<a>&amp; &lt; &gt; &#xD;</a>")).toBe(
			"<a>&amp; &lt; &gt; &#xD;</a>",
		);
	});

	it("escapes quotes and whitespace inside an attribute value", () => {
		// A raw tab or newline in an attribute would change meaning on re-parse,
		// so the canonical form spells them out.
		const out = c14nOf('<a x="&quot;&amp;&#x9;&#xD;"/>');
		expect(out).toBe('<a x="&quot;&amp;&#x9;&#xD;"></a>');
	});

	it("does not escape an apostrophe or a closing bracket in an attribute", () => {
		expect(c14nOf('<a x="it\'s > that"/>')).toBe('<a x="it\'s > that"></a>');
	});
});

describe("transit > c14n > which namespaces are written", () => {
	it("writes a declaration where it is used, not where it was declared", () => {
		// `<a>` uses neither prefix, so it carries neither — the declaration
		// travels down to the element that actually uses it, and `urn:unused`
		// disappears entirely. That relocation is the whole reason exclusive
		// exists: the fragment stays verifiable wherever it is moved.
		expect(
			c14nOf('<a xmlns:p="urn:p" xmlns:unused="urn:unused"><p:b/></a>'),
		).toBe('<a><p:b xmlns:p="urn:p"></p:b></a>');
	});

	it("does not repeat a declaration an output ancestor already wrote", () => {
		expect(c14nOf('<p:a xmlns:p="urn:p"><p:b/></p:a>')).toBe(
			'<p:a xmlns:p="urn:p"><p:b></p:b></p:a>',
		);
	});

	it("rewrites a prefix an ancestor bound to another value", () => {
		expect(
			c14nOf('<p:a xmlns:p="urn:one"><p:b xmlns:p="urn:two"/></p:a>'),
		).toBe('<p:a xmlns:p="urn:one"><p:b xmlns:p="urn:two"></p:b></p:a>');
	});

	it("carries the declaration a signed fragment needs, wherever it sat", () => {
		// The declaration lives on the root; the canonical form of the fragment
		// must still carry it, which is what lets the fragment be verified after
		// being moved into another document.
		expect(c14nOf('<r xmlns:p="urn:p"><p:a ID="x"><p:b/></p:a></r>', "x")).toBe(
			'<p:a xmlns:p="urn:p" ID="x"><p:b></p:b></p:a>',
		);
	});

	it("leaves the default namespace out when only attributes are unprefixed", () => {
		// An unprefixed attribute is in NO namespace, so it never makes the
		// default namespace visibly utilized.
		expect(c14nOf('<p:a xmlns="urn:d" xmlns:p="urn:p" x="1"/>')).toBe(
			'<p:a xmlns:p="urn:p" x="1"></p:a>',
		);
	});

	it('writes xmlns="" only to undo an ancestor\'s default namespace', () => {
		const undone = c14nOf(
			'<r xmlns="urn:d"><a ID="x"><b xmlns=""/></a></r>',
			"x",
		);
		expect(undone).toBe('<a xmlns="urn:d" ID="x"><b xmlns=""></b></a>');

		// With no default namespace in scope there is nothing to undo.
		expect(c14nOf("<a><b/></a>")).toBe("<a><b></b></a>");
	});

	it("never declares the xml prefix, which the specification binds", () => {
		expect(c14nOf('<a xml:lang="en"/>')).toBe('<a xml:lang="en"></a>');
	});

	it("does not inherit xml:lang from an ancestor, unlike inclusive", () => {
		// This is the difference that lets a fragment travel: exclusive takes
		// the element as it is, not as its old parent left it.
		expect(c14nOf('<r xml:lang="en"><a ID="x"/></r>', "x")).toBe(
			'<a ID="x"></a>',
		);
	});

	it("writes a listed prefix even when nothing uses it", () => {
		// InclusiveNamespaces PrefixList asks for exactly that.
		expect(c14nOf('<r xmlns:keep="urn:k"><a ID="x"/></r>', "x", ["keep"])).toBe(
			'<a xmlns:keep="urn:k" ID="x"></a>',
		);
	});
});

describe("transit > c14n > the specification's own example", () => {
	it("renders the worked example unchanged", () => {
		const xml =
			'<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">' +
			'<n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2>';

		expect(canonicalize(parseXml(xml))).toBe(
			'<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">' +
				'<n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>',
		);
	});
});
