/**
 * The encoding LDAP speaks.
 *
 * The point of encoding a filter rather than writing one is that a value can
 * never become syntax — so the tests that matter most are the ones showing a
 * hostile username coming back out as itself.
 */
import { describe, expect, it } from "vitest";
import {
	BerError,
	context,
	decode,
	decodeInteger,
	decodeSequence,
	decodeString,
	encode,
	encodeInteger,
	encodeSequence,
	encodeString,
	INTEGER,
	messageLength,
	OCTET_STRING,
} from "../../src/ber.js";

describe("transit > ber > lengths", () => {
	it("writes a short length in one byte", () => {
		expect([...encode(OCTET_STRING, Buffer.alloc(5))].slice(0, 2)).toEqual([
			OCTET_STRING,
			5,
		]);
	});

	it("writes a long length with its own byte count first", () => {
		const encoded = encode(OCTET_STRING, Buffer.alloc(300));

		// 0x82 = long form, two bytes of length; then 300 as 0x01 0x2C.
		expect([...encoded].slice(0, 4)).toEqual([OCTET_STRING, 0x82, 0x01, 0x2c]);
	});

	it("reads back what it wrote, at any size", () => {
		for (const size of [0, 1, 127, 128, 300, 70_000]) {
			const value = Buffer.alloc(size, 0xab);
			expect(decode(encode(OCTET_STRING, value)).value.length).toBe(size);
		}
	});

	it("refuses an indefinite length, which LDAP does not use", () => {
		// Accepting it would mean scanning for a terminator the other side
		// chooses.
		expect(() => decode(Buffer.from([0x30, 0x80, 0x00, 0x00]))).toThrow(
			BerError,
		);
	});

	it("refuses an element claiming more bytes than arrived", () => {
		expect(() => decode(Buffer.from([0x04, 0x10, 0x01]))).toThrow(/claims 16/);
	});
});

describe("transit > ber > integers", () => {
	it("round-trips the values LDAP uses", () => {
		for (const value of [0, 1, 3, 49, 127, 128, 255, 256, 65_535, 1_000_000]) {
			expect(decodeInteger(decode(encodeInteger(value)).value)).toBe(value);
		}
	});

	it("keeps a positive number positive", () => {
		// Without a leading zero, 128 encodes as 0x80 and reads back as -128.
		expect(decodeInteger(decode(encodeInteger(128)).value)).toBe(128);
		expect(decodeInteger(decode(encodeInteger(255)).value)).toBe(255);
	});

	it("round-trips a negative one", () => {
		expect(decodeInteger(decode(encodeInteger(-1)).value)).toBe(-1);
		expect(decodeInteger(decode(encodeInteger(-128)).value)).toBe(-128);
	});
});

describe("transit > ber > strings and sequences", () => {
	it("round-trips text, whatever is in it", () => {
		for (const value of ["", "ada", "Ada Lovelace", "üñî", "a\0b"]) {
			expect(decodeString(decode(encodeString(value)).value)).toBe(value);
		}
	});

	it("keeps a hostile username as a username", () => {
		// The characters that would end a filter in a text-built one are just
		// bytes here, counted and copied.
		const hostile = "*)(uid=admin)(|(uid=*";
		const round = decodeString(decode(encodeString(hostile)).value);

		expect(round).toBe(hostile);
	});

	it("reads back every element of a sequence", () => {
		const encoded = encodeSequence([
			encodeInteger(1),
			encodeString("ada"),
			encodeSequence([encodeString("nested")]),
		]);
		const parts = decodeSequence(decode(encoded).value);

		expect(parts).toHaveLength(3);
		expect(decodeInteger((parts[0] as { value: Buffer }).value)).toBe(1);
		expect(decodeString((parts[1] as { value: Buffer }).value)).toBe("ada");
	});

	it("keeps the tag it was given", () => {
		expect(decode(encodeString("x", context(3))).tag).toBe(context(3));
		expect(decode(encodeInteger(1, INTEGER)).tag).toBe(INTEGER);
	});
});

describe("transit > ber > messages arriving in pieces", () => {
	it("says how long a message will be", () => {
		const message = encodeSequence([encodeInteger(1), encodeString("x")]);

		expect(messageLength(message)).toBe(message.length);
	});

	it("waits while a message is still arriving", () => {
		// A payload past 255 bytes needs two length bytes, so the total is not
		// known until four have arrived. LDAP runs over a stream, and a read can
		// stop anywhere.
		const message = encodeSequence([
			encodeInteger(1),
			encodeString("x".repeat(300)),
		]);

		expect(messageLength(message.subarray(0, 1))).toBeUndefined();
		expect(messageLength(message.subarray(0, 3))).toBeUndefined();
		expect(messageLength(message.subarray(0, 4))).toBe(message.length);
		expect(messageLength(message)).toBe(message.length);
	});

	it("knows the length as soon as a short one has arrived", () => {
		const message = encodeSequence([encodeInteger(1), encodeString("x")]);

		expect(messageLength(message.subarray(0, 2))).toBe(message.length);
	});
});
