/**
 * The encoding LDAP speaks: BER, the subset of it LDAP actually uses.
 *
 * This exists so that nothing an application passes ever becomes part of a
 * string that a server then parses. A search filter here is a structure, not
 * text — its values are written as length-prefixed octets, so a username
 * containing `)(uid=*` is a username containing those characters and cannot
 * become syntax. LDAP injection is not escaped away here; it is unrepresentable.
 */

/** Universal tags, and the two LDAP builds everything else from. */
export const BOOLEAN = 0x01;
export const INTEGER = 0x02;
export const OCTET_STRING = 0x04;
export const ENUMERATED = 0x0a;
export const SEQUENCE = 0x30;

/** `[APPLICATION n]`, constructed. */
export const application = (n: number): number => 0x60 | n;
/** `[APPLICATION n]`, primitive — which a couple of LDAP operations are. */
export const applicationPrimitive = (n: number): number => 0x40 | n;
/** `[n]` context-specific, constructed. */
export const context = (n: number): number => 0xa0 | n;
/** `[n]` context-specific, primitive. */
export const contextPrimitive = (n: number): number => 0x80 | n;

export class BerError extends Error {
	constructor(message: string) {
		super(`[transit] ${message}`);
		this.name = "BerError";
	}
}

/** One tag-length-value element. */
export function encode(tag: number, value: Buffer): Buffer {
	return Buffer.concat([Buffer.from([tag]), encodeLength(value.length), value]);
}

export function encodeInteger(value: number, tag = INTEGER): Buffer {
	if (!Number.isSafeInteger(value)) {
		throw new BerError(`cannot encode ${value} as an integer`);
	}
	const bytes: number[] = [];
	let remaining = value;
	do {
		bytes.unshift(remaining & 0xff);
		remaining >>= 8;
	} while (remaining !== 0 && remaining !== -1);
	// A leading bit set on a positive number would read as negative.
	if (value >= 0 && (bytes[0] as number) & 0x80) bytes.unshift(0);
	if (value < 0 && !((bytes[0] as number) & 0x80)) bytes.unshift(0xff);
	return encode(tag, Buffer.from(bytes));
}

export function encodeString(value: string, tag = OCTET_STRING): Buffer {
	// The value is written as length-prefixed bytes, never interpolated. That
	// is what makes injection impossible rather than merely escaped.
	return encode(tag, Buffer.from(value, "utf8"));
}

export function encodeBoolean(value: boolean, tag = BOOLEAN): Buffer {
	return encode(tag, Buffer.from([value ? 0xff : 0x00]));
}

export function encodeSequence(parts: Buffer[], tag = SEQUENCE): Buffer {
	return encode(tag, Buffer.concat(parts));
}

/** A decoded element: its tag, its contents, and where it ended. */
export interface BerElement {
	tag: number;
	value: Buffer;
	end: number;
}

/** Read one element at `offset`. */
export function decode(buffer: Buffer, offset = 0): BerElement {
	if (offset >= buffer.length) {
		throw new BerError("the message ends where an element was expected");
	}
	const tag = buffer[offset] as number;
	const { length, at } = decodeLength(buffer, offset + 1);
	const end = at + length;
	if (end > buffer.length) {
		throw new BerError(
			`an element claims ${length} bytes and the message holds ${buffer.length - at}`,
		);
	}
	return { tag, value: buffer.subarray(at, end), end };
}

/** Every element inside a constructed one. */
export function decodeSequence(value: Buffer): BerElement[] {
	const out: BerElement[] = [];
	let offset = 0;
	while (offset < value.length) {
		const element = decode(value, offset);
		out.push(element);
		offset = element.end;
	}
	return out;
}

export function decodeInteger(value: Buffer): number {
	if (value.length === 0) throw new BerError("an integer has no bytes");
	if (value.length > 6) {
		// Beyond this a result code or message id is not something this reads.
		throw new BerError(`an integer of ${value.length} bytes is out of range`);
	}
	let out = (value[0] as number) & 0x80 ? -1 : 0;
	for (const byte of value) out = out * 256 + byte;
	return out;
}

export function decodeString(value: Buffer): string {
	return value.toString("utf8");
}

/**
 * How many bytes a whole message occupies, or `undefined` while it is still
 * arriving. LDAP runs over a stream, so a read can stop anywhere.
 */
export function messageLength(buffer: Buffer): number | undefined {
	if (buffer.length < 2) return undefined;
	const first = buffer[1] as number;
	if (first < 0x80) return 2 + first;
	const count = first & 0x7f;
	if (count === 0 || count > 4) {
		throw new BerError("a message declares a length this refuses to read");
	}
	if (buffer.length < 2 + count) return undefined;
	let length = 0;
	for (let i = 0; i < count; i += 1) {
		length = length * 256 + (buffer[2 + i] as number);
	}
	return 2 + count + length;
}

function encodeLength(length: number): Buffer {
	if (length < 0x80) return Buffer.from([length]);
	const bytes: number[] = [];
	let remaining = length;
	while (remaining > 0) {
		bytes.unshift(remaining & 0xff);
		remaining = Math.floor(remaining / 256);
	}
	return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function decodeLength(
	buffer: Buffer,
	offset: number,
): { length: number; at: number } {
	if (offset >= buffer.length) {
		throw new BerError("an element has no length");
	}
	const first = buffer[offset] as number;
	if (first < 0x80) return { length: first, at: offset + 1 };
	const count = first & 0x7f;
	if (count === 0) {
		// Indefinite length is legal BER and not legal LDAP; accepting it would
		// mean scanning for a terminator supplied by the other side.
		throw new BerError(
			"an element uses an indefinite length, which LDAP does not",
		);
	}
	if (count > 4 || offset + 1 + count > buffer.length) {
		throw new BerError("an element declares a length this refuses to read");
	}
	let length = 0;
	for (let i = 0; i < count; i += 1) {
		length = length * 256 + (buffer[offset + 1 + i] as number);
	}
	return { length, at: offset + 1 + count };
}
