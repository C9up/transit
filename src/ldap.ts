/**
 * The slice of LDAP an application needs to sign somebody in: connect, bind,
 * search, close.
 *
 * Three things here are the difference between an LDAP sign-in that works and
 * one that lets anybody through:
 *
 *   - **An empty password is refused before the socket is touched.** A simple
 *     bind with no password is an ANONYMOUS bind, and the server answers
 *     success. A login form that passes a blank password straight through
 *     therefore authenticates as whoever was named. It is the oldest bug in
 *     LDAP authentication and it is one `if`.
 *   - **Filters are structures, not text.** Values are written as
 *     length-prefixed octets, so a username cannot become syntax.
 *   - **TLS unless told otherwise.** A simple bind sends the password as it
 *     was typed.
 */

import { connect as connectTcp, type Socket } from "node:net";
import { connect as connectTls } from "node:tls";
import {
	application,
	applicationPrimitive,
	BOOLEAN,
	context,
	contextPrimitive,
	decode,
	decodeInteger,
	decodeSequence,
	decodeString,
	ENUMERATED,
	encodeBoolean,
	encodeInteger,
	encodeSequence,
	encodeString,
	messageLength,
	OCTET_STRING,
} from "./ber.js";

const BIND_REQUEST = application(0);
const BIND_RESPONSE = application(1);
const UNBIND_REQUEST = applicationPrimitive(2);
const SEARCH_REQUEST = application(3);
const SEARCH_ENTRY = application(4);
const SEARCH_DONE = application(5);

export class LdapError extends Error {
	readonly code: number | undefined;
	constructor(message: string, code?: number) {
		super(`[transit] ${message}`);
		this.name = "LdapError";
		this.code = code;
	}
}

/** A filter, as a shape. There is no filter string, on purpose. */
export type LdapFilter =
	| { equals: [attribute: string, value: string] }
	| { present: string }
	| { and: LdapFilter[] }
	| { or: LdapFilter[] }
	| { not: LdapFilter };

export interface LdapEntry {
	dn: string;
	attributes: Record<string, string[]>;
}

export interface LdapOptions {
	/** `ldaps://host:636` or `ldap://host:389`. */
	url: string;
	/**
	 * Allow a plaintext connection. A simple bind sends the password as typed,
	 * so this has to be asked for.
	 */
	allowInsecure?: boolean;
	/** How long to wait for the server, in milliseconds. Default 10 000. */
	timeoutMs?: number;
	/** Refuse a server certificate that does not check out. Default true. */
	rejectUnauthorized?: boolean;
}

/**
 * One connection, for one exchange.
 *
 * A connection carries the identity of whatever last bound on it, so this is
 * deliberately short-lived: verifying a password means binding as that person,
 * and nothing else may run on the connection afterwards.
 */
export class LdapConnection {
	#socket: Socket | undefined;
	#buffer = Buffer.alloc(0);
	#nextMessage = 1;
	#pending = new Map<
		number,
		{
			resolve: (value: Buffer[]) => void;
			reject: (error: Error) => void;
			parts: Buffer[];
		}
	>();
	readonly #options: LdapOptions;

	constructor(options: LdapOptions) {
		this.#options = options;
	}

	async connect(): Promise<void> {
		const url = new URL(this.#options.url);
		const secure = url.protocol === "ldaps:";
		if (!secure && this.#options.allowInsecure !== true) {
			throw new LdapError(
				`'${this.#options.url}' is not encrypted, and a simple bind sends the password as it was typed. Use ldaps://, or set allowInsecure when the link is already protected.`,
			);
		}
		const port = Number(url.port || (secure ? 636 : 389));
		const host = url.hostname;

		await new Promise<void>((resolve, reject) => {
			const socket = secure
				? connectTls({
						host,
						port,
						servername: host,
						rejectUnauthorized: this.#options.rejectUnauthorized !== false,
					})
				: connectTcp({ host, port });

			const onError = (error: Error) => {
				this.#failAll(error);
				reject(
					new LdapError(`could not reach ${host}:${port} — ${error.message}`),
				);
			};
			socket.once("error", onError);
			socket.once(secure ? "secureConnect" : "connect", () => {
				socket.setTimeout(this.#options.timeoutMs ?? 10_000);
				socket.on("data", (chunk) => this.#receive(chunk));
				socket.on("timeout", () =>
					this.#failAll(new LdapError("the directory stopped answering")),
				);
				socket.on("close", () =>
					this.#failAll(new LdapError("the directory closed the connection")),
				);
				this.#socket = socket;
				resolve();
			});
		});
	}

	/**
	 * Bind as `dn` with `password`.
	 *
	 * An empty password is refused here, before anything is sent. The server
	 * would answer success: a simple bind with no password is an anonymous
	 * bind, and a login form that passes one through authenticates as whoever
	 * was named.
	 */
	async bind(dn: string, password: string): Promise<void> {
		if (password === "") {
			throw new LdapError(
				"an empty password is an anonymous bind, which the directory accepts — refused here instead",
			);
		}
		const body = encodeSequence(
			[
				encodeInteger(3),
				encodeString(dn),
				encodeString(password, contextPrimitive(0)),
			],
			BIND_REQUEST,
		);
		const [response] = await this.#exchange(body, [BIND_RESPONSE]);
		if (!response) throw new LdapError("the directory sent no bind response");
		assertSuccess(response, "bind");
	}

	/** Search under `base`, and read the entries it answers with. */
	async search(options: {
		base: string;
		filter: LdapFilter;
		attributes?: string[];
		scope?: "base" | "one" | "sub";
		sizeLimit?: number;
	}): Promise<LdapEntry[]> {
		const scope = { base: 0, one: 1, sub: 2 }[options.scope ?? "sub"];
		const body = encodeSequence(
			[
				encodeString(options.base),
				encodeInteger(scope, ENUMERATED),
				encodeInteger(0, ENUMERATED),
				encodeInteger(options.sizeLimit ?? 2),
				encodeInteger(0),
				encodeBoolean(false, BOOLEAN),
				encodeFilter(options.filter),
				encodeSequence((options.attributes ?? []).map((a) => encodeString(a))),
			],
			SEARCH_REQUEST,
		);

		const parts = await this.#exchange(body, [SEARCH_ENTRY], SEARCH_DONE);
		const done = parts.at(-1);
		if (done) assertSuccess(done, "search");
		return parts.slice(0, -1).map(readEntry);
	}

	/** Say goodbye and close. Never throws: this runs in a finally. */
	async close(): Promise<void> {
		const socket = this.#socket;
		if (!socket) return;
		this.#socket = undefined;
		try {
			socket.write(
				encodeSequence([
					encodeInteger(this.#nextMessage),
					encodeSequence([], UNBIND_REQUEST),
				]),
			);
		} catch {
			// The point is to end the connection; failing to be polite about it
			// changes nothing.
		}
		socket.destroy();
		this.#failAll(new LdapError("the connection was closed"));
	}

	/** Send one request and collect the replies that carry its message id. */
	async #exchange(
		body: Buffer,
		collect: number[],
		until?: number,
	): Promise<Buffer[]> {
		const socket = this.#socket;
		if (!socket) throw new LdapError("the connection is not open");
		const id = this.#nextMessage++;

		return new Promise<Buffer[]>((resolve, reject) => {
			this.#pending.set(id, { resolve, reject, parts: [] });
			this.#expect.set(id, { collect, until });
			socket.write(encodeSequence([encodeInteger(id), body]), (error) => {
				if (error) {
					this.#pending.delete(id);
					reject(
						new LdapError(`the request could not be sent — ${error.message}`),
					);
				}
			});
		});
	}

	readonly #expect = new Map<
		number,
		{ collect: number[]; until: number | undefined }
	>();

	#receive(chunk: Buffer): void {
		this.#buffer = Buffer.concat([this.#buffer, chunk]);
		for (;;) {
			const length = messageLength(this.#buffer);
			if (length === undefined || this.#buffer.length < length) return;
			const message = this.#buffer.subarray(0, length);
			this.#buffer = this.#buffer.subarray(length);
			this.#dispatch(message);
		}
	}

	#dispatch(message: Buffer): void {
		const [idElement, op] = decodeSequence(decode(message).value);
		if (!idElement || !op) return;
		const id = decodeInteger(idElement.value);
		const waiting = this.#pending.get(id);
		const expected = this.#expect.get(id);
		if (!waiting || !expected) return;

		if (expected.until === undefined) {
			// A single-reply operation: this is the answer.
			this.#finish(id, [op.value]);
			return;
		}
		waiting.parts.push(op.value);
		if (op.tag === expected.until) this.#finish(id, waiting.parts);
	}

	#finish(id: number, parts: Buffer[]): void {
		const waiting = this.#pending.get(id);
		this.#pending.delete(id);
		this.#expect.delete(id);
		waiting?.resolve(parts);
	}

	#failAll(error: Error): void {
		for (const [id, waiting] of this.#pending) {
			this.#pending.delete(id);
			this.#expect.delete(id);
			waiting.reject(error);
		}
	}
}

/** A filter, encoded. Values become octets, never syntax. */
function encodeFilter(filter: LdapFilter): Buffer {
	if ("equals" in filter) {
		const [attribute, value] = filter.equals;
		return encodeSequence(
			[encodeString(attribute), encodeString(value)],
			context(3),
		);
	}
	if ("present" in filter) {
		return encodeString(filter.present, contextPrimitive(7));
	}
	if ("and" in filter) {
		return encodeSequence(filter.and.map(encodeFilter), context(0));
	}
	if ("or" in filter) {
		return encodeSequence(filter.or.map(encodeFilter), context(1));
	}
	return encodeSequence([encodeFilter(filter.not)], context(2));
}

function readEntry(value: Buffer): LdapEntry {
	const [dnElement, attributesElement] = decodeSequence(value);
	const attributes: Record<string, string[]> = {};
	for (const attribute of attributesElement
		? decodeSequence(attributesElement.value)
		: []) {
		const [nameElement, valuesElement] = decodeSequence(attribute.value);
		if (!nameElement) continue;
		attributes[decodeString(nameElement.value)] = valuesElement
			? decodeSequence(valuesElement.value).map((v) => decodeString(v.value))
			: [];
	}
	return {
		dn: dnElement ? decodeString(dnElement.value) : "",
		attributes,
	};
}

/** LDAP answers a code; anything but zero is a refusal worth reporting. */
function assertSuccess(response: Buffer, what: string): void {
	const [codeElement, , messageElement] = decodeSequence(response);
	if (!codeElement)
		throw new LdapError(`the ${what} response has no result code`);
	const code = decodeInteger(codeElement.value);
	if (code === 0) return;
	const detail =
		messageElement && messageElement.tag === OCTET_STRING
			? decodeString(messageElement.value)
			: "";
	throw new LdapError(
		`the directory refused the ${what}: ${describe(code)}${detail ? ` — ${detail}` : ""}`,
		code,
	);
}

/** The result codes worth naming; the rest are reported by number. */
function describe(code: number): string {
	switch (code) {
		case 32:
			return "no such object";
		case 34:
			return "invalid DN syntax";
		case 48:
			return "authentication is not allowed";
		case 49:
			return "invalid credentials";
		case 50:
			return "insufficient rights";
		case 53:
			return "the server is unwilling to perform this";
		default:
			return `result code ${code}`;
	}
}
