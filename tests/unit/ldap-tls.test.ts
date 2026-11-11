/**
 * Reaching a directory over TLS by its IP address.
 *
 * An Active Directory controller is often configured as `ldaps://10.0.0.5`.
 * TLS has no server name for an address: the certificate is checked against
 * the address itself (its IP SANs), never skipped.
 */
import { readFileSync } from "node:fs";
import type { AddressInfo, Socket } from "node:net";
import { createServer, type Server } from "node:tls";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LdapConnection } from "../../src/ldap.js";

const tlsCalls = vi.hoisted((): Record<string, unknown>[] => []);

vi.mock("node:tls", async (importOriginal) => {
	const original = await importOriginal<typeof import("node:tls")>();
	return {
		...original,
		connect: (options: Record<string, unknown>) => {
			tlsCalls.push(options);
			return original.connect(options);
		},
	};
});

const fixture = (name: string) =>
	readFileSync(new URL(`../fixtures/${name}`, import.meta.url));

let server: Server | undefined;
const accepted = new Set<Socket>();

afterEach(async () => {
	tlsCalls.length = 0;
	for (const socket of accepted) socket.destroy();
	accepted.clear();
	const open = server;
	server = undefined;
	if (open) await new Promise<void>((resolve) => open.close(() => resolve()));
});

async function startTls(): Promise<number> {
	const tls = createServer({
		key: fixture("key.pem"),
		cert: fixture("cert.pem"),
	});
	tls.on("connection", (socket) => {
		accepted.add(socket);
		socket.on("error", () => {});
	});
	tls.on("tlsClientError", () => {});
	server = tls;
	await new Promise<void>((resolve) => tls.listen(0, "127.0.0.1", resolve));
	const address = tls.address();
	return typeof address === "object" && address !== null
		? (address satisfies AddressInfo).port
		: 0;
}

describe("transit > ldap > ldaps:// to an IP address", () => {
	it("connects, sending no server name for the address", async () => {
		const port = await startTls();
		const connection = new LdapConnection({
			url: `ldaps://127.0.0.1:${port}`,
			// The fixture is self-signed; the identity check is the next test.
			rejectUnauthorized: false,
		});

		await connection.connect();
		await connection.close();

		expect(tlsCalls).toHaveLength(1);
		expect(tlsCalls[0]?.host).toBe("127.0.0.1");
		expect(tlsCalls[0]).not.toHaveProperty("servername");
	});

	it("still checks the certificate of a directory reached by address", async () => {
		const port = await startTls();
		const connection = new LdapConnection({
			url: `ldaps://127.0.0.1:${port}`,
		});

		// Verification stays on: the self-signed fixture is refused for what
		// it is, not waved through because there was no name to check.
		await expect(connection.connect()).rejects.toThrow(/certificate/);
		expect(tlsCalls[0]?.rejectUnauthorized).toBe(true);
		expect(tlsCalls[0]).not.toHaveProperty("checkServerIdentity");
	});

	it("unwraps an IPv6 literal before connecting to it", async () => {
		const connection = new LdapConnection({
			url: "ldaps://[::1]:1",
			timeoutMs: 1_000,
		});

		await expect(connection.connect()).rejects.toThrow(/could not reach/);
		expect(tlsCalls[0]?.host).toBe("::1");
		expect(tlsCalls[0]).not.toHaveProperty("servername");
	});

	it("keeps the server name for a host name", async () => {
		const connection = new LdapConnection({
			url: "ldaps://localhost:1",
			timeoutMs: 1_000,
		});

		await expect(connection.connect()).rejects.toThrow(/could not reach/);
		expect(tlsCalls[0]?.servername).toBe("localhost");
	});
});
