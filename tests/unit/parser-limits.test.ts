import { describe, expect, it } from "vitest";
import { MAX_MESSAGE_BYTES, messageLength } from "../../src/ber.js";
import { parseXml } from "../../src/xml.js";

/**
 * What an unauthenticated caller can make these parsers spend.
 *
 * A SAML response is parsed BEFORE its signature is checked — it has to be,
 * the signature is inside it — so every byte here was chosen by whoever sent
 * the POST. An LDAP length header is worse: it declares how much is coming
 * before any of it arrives, so five bytes could ask the client to hold four
 * gigabytes.
 */

/** `<a><a>…</a></a>` nested `depth` deep. */
function nested(depth: number): string {
	return `${"<a>".repeat(depth)}x${"</a>".repeat(depth)}`;
}

describe("transit > xml parser limits", () => {
	it("refuses a document that nests deeper than the limit", () => {
		// The parser recurses once per level, so this is a stack overflow — and
		// the stack it overflows is the one that has not verified anything yet.
		expect(() => parseXml(nested(200))).toThrow(/nests deeper/);
	});

	it("accepts a document at a realistic depth", () => {
		expect(parseXml(nested(50)).local).toBe("a");
	});

	it("refuses a document longer than the limit, before copying it", () => {
		// Checked ahead of the line-ending normalisation, which duplicates the
		// whole string: a 300 MB body used to cost 600 MB before its size was
		// ever looked at.
		const huge = `<a>${"x".repeat(2 * 1024 * 1024)}</a>`;
		expect(() => parseXml(huge)).toThrow(/over the/);
	});

	it("refuses a document with too many nodes", () => {
		const many = `<a>${"<b/>".repeat(60_000)}</a>`;
		expect(() => parseXml(many)).toThrow(/more than .* nodes/);
	});

	it("refuses an element carrying too many attributes", () => {
		const attrs = Array.from({ length: 300 }, (_, i) => `a${i}="v"`).join(" ");
		expect(() => parseXml(`<a ${attrs}/>`)).toThrow(/attributes/);
	});

	it("lets a caller tighten the limits", () => {
		expect(() => parseXml(nested(20), { maxDepth: 5 })).toThrow(/nests deeper/);
	});
});

describe("transit > ldap message length", () => {
	it("refuses a length header that declares more than the cap", () => {
		// 0x84 = four length bytes follow. This declares ~4 GiB, in five bytes.
		const header = Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]);
		expect(() => messageLength(header)).toThrow(/over the/);
	});

	it("still reads a normal message length", () => {
		const header = Buffer.from([0x30, 0x84, 0x00, 0x00, 0x10, 0x00]);
		expect(messageLength(header)).toBe(6 + 0x1000);
	});

	it("caps well under what a four-byte header can express", () => {
		expect(MAX_MESSAGE_BYTES).toBeLessThan(0xffffffff);
	});
});
