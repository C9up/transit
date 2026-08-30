/**
 * A directory, in process, speaking just enough LDAP to answer a sign-in.
 *
 * Real sockets and real BER on both sides: what the client encodes is what
 * this decodes, so a mistake in the wire format shows up here rather than
 * against a live directory.
 */

import { createServer, type Server } from "node:net";
import {
	application,
	applicationPrimitive,
	decode,
	decodeInteger,
	decodeSequence,
	decodeString,
	encodeInteger,
	encodeSequence,
	encodeString,
	messageLength,
} from "../../src/ber.js";

const BIND_REQUEST = application(0);
const BIND_RESPONSE = application(1);
const UNBIND_REQUEST = applicationPrimitive(2);
const SEARCH_REQUEST = application(3);
const SEARCH_ENTRY = application(4);
const SEARCH_DONE = application(5);

export interface FakeEntry {
	dn: string;
	password: string;
	attributes: Record<string, string[]>;
}

export interface FakeLdap {
	url: string;
	close(): Promise<void>;
	/** Every filter value the client searched for, in order. */
	searched: string[];
	/** Every DN that was bound, with the password offered. */
	binds: Array<{ dn: string; password: string }>;
}

export async function startFakeLdap(
	entries: FakeEntry[],
	options: { loginAttribute?: string } = {},
): Promise<FakeLdap> {
	const loginAttribute = options.loginAttribute ?? "uid";
	const searched: string[] = [];
	const binds: Array<{ dn: string; password: string }> = [];

	const server: Server = createServer((socket) => {
		let buffer = Buffer.alloc(0);
		socket.on("data", (chunk) => {
			buffer = Buffer.concat([buffer, chunk]);
			for (;;) {
				const length = messageLength(buffer);
				if (length === undefined || buffer.length < length) return;
				const message = buffer.subarray(0, length);
				buffer = buffer.subarray(length);

				const [idElement, op] = decodeSequence(decode(message).value);
				if (!idElement || !op) return;
				const id = decodeInteger(idElement.value);

				if (op.tag === UNBIND_REQUEST) {
					socket.end();
					return;
				}
				if (op.tag === BIND_REQUEST) {
					const [, dnElement, passwordElement] = decodeSequence(op.value);
					const dn = dnElement ? decodeString(dnElement.value) : "";
					const password = passwordElement
						? decodeString(passwordElement.value)
						: "";
					binds.push({ dn, password });
					const known = entries.find((entry) => entry.dn === dn);
					const ok =
						dn === "" ||
						(known ? known.password === password : dn.startsWith("cn=reader"));
					socket.write(reply(id, BIND_RESPONSE, ok ? 0 : 49));
					continue;
				}
				if (op.tag === SEARCH_REQUEST) {
					const parts = decodeSequence(op.value);
					const filter = parts[6];
					const wanted = filter ? filterValue(filter.value) : "";
					searched.push(wanted);
					for (const entry of entries) {
						if (!entry.attributes[loginAttribute]?.includes(wanted)) continue;
						socket.write(entryMessage(id, entry));
					}
					socket.write(reply(id, SEARCH_DONE, 0));
				}
			}
		});
	});

	const port = await new Promise<number>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			resolve(typeof address === "object" && address ? address.port : 0);
		});
	});

	return {
		url: `ldap://127.0.0.1:${port}`,
		searched,
		binds,
		close: () =>
			new Promise<void>((resolve) => {
				server.close(() => resolve());
			}),
	};
}

/** The assertion value of the equality filter, however it is nested. */
function filterValue(filter: Buffer): string {
	const parts = decodeSequence(filter);
	// An `and` wraps other filters; the login one is the last.
	const last = parts.at(-1);
	if (parts.length >= 2 && last && last.tag >= 0xa0) {
		return filterValue(last.value);
	}
	return last ? decodeString(last.value) : "";
}

function reply(id: number, tag: number, code: number): Buffer {
	return encodeSequence([
		encodeInteger(id),
		encodeSequence(
			[encodeInteger(code, 0x0a), encodeString(""), encodeString("")],
			tag,
		),
	]);
}

function entryMessage(id: number, entry: FakeEntry): Buffer {
	return encodeSequence([
		encodeInteger(id),
		encodeSequence(
			[
				encodeString(entry.dn),
				encodeSequence(
					Object.entries(entry.attributes).map(([name, values]) =>
						encodeSequence([
							encodeString(name),
							encodeSequence(
								values.map((value) => encodeString(value)),
								0x31,
							),
						]),
					),
				),
			],
			SEARCH_ENTRY,
		),
	]);
}
