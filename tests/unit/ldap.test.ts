/**
 * Signing in against a directory.
 *
 * The exchanges below run over real sockets, against a directory that decodes
 * what this package encodes — so a mistake in the wire format shows up here
 * rather than against a live server.
 */
import { createServer, type Socket } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ldap } from "../../src/config.js";
import { LdapDirectory } from "../../src/drivers/LdapDirectory.js";
import { TransitManager } from "../../src/TransitManager.js";
import { type FakeLdap, startFakeLdap } from "../helpers/fake-ldap.js";

const BASE = "dc=acme,dc=test";
const ada = {
	dn: `uid=ada,${BASE}`,
	password: "correct horse",
	attributes: {
		uid: ["ada"],
		mail: ["ada@acme.test"],
		displayName: ["Ada Lovelace"],
		memberOf: ["cn=staff,dc=acme,dc=test", "cn=admin,dc=acme,dc=test"],
	},
};

let server: FakeLdap | undefined;

afterEach(async () => {
	await server?.close();
	server = undefined;
});

async function directory(
	entries = [ada],
	over: Partial<Parameters<typeof ldap>[0]> = {},
	serverOptions: Parameters<typeof startFakeLdap>[1] = {},
) {
	server = await startFakeLdap(entries, serverOptions);
	return new LdapDirectory({
		url: server.url,
		baseDn: BASE,
		loginAttribute: "uid",
		bindDn: `cn=reader,${BASE}`,
		bindPassword: "reader-password",
		allowInsecure: true,
		...over,
	});
}

describe("transit > ldap > signing in", () => {
	it("answers with who the directory says this is", async () => {
		const user = await (await directory()).authenticate("ada", "correct horse");

		// The DN is the only value guaranteed unique and stable.
		expect(user.id).toBe(`uid=ada,${BASE}`);
		expect(user.email).toBe("ada@acme.test");
		expect(user.name).toBe("Ada Lovelace");
		expect(user.nickName).toBe("ada");
		// A directory that holds an address has vouched for it.
		expect(user.emailVerificationState).toBe("verified");
		expect(user.raw.attributes).toMatchObject({
			memberOf: ["cn=staff,dc=acme,dc=test", "cn=admin,dc=acme,dc=test"],
		});
	});

	it("binds as the person, which is what verifies the password", async () => {
		const subject = await directory();
		await subject.authenticate("ada", "correct horse");

		// Two connections: one to find the entry, one to bind as them.
		expect(server?.binds).toEqual([
			{ dn: `cn=reader,${BASE}`, password: "reader-password" },
			{ dn: `uid=ada,${BASE}`, password: "correct horse" },
		]);
	});

	it("refuses a wrong password", async () => {
		await expect(
			(await directory()).authenticate("ada", "wrong"),
		).rejects.toThrow(/invalid credentials/);
	});

	it("says the same thing for an unknown user as for a wrong password", async () => {
		// Which of the two it was is not something a sign-in form discloses.
		await expect(
			(await directory()).authenticate("nobody", "whatever"),
		).rejects.toThrow(/invalid credentials/);
	});

	it("refuses a login that matches more than one entry", async () => {
		const twin = { ...ada, dn: `uid=ada,ou=other,${BASE}` };

		await expect(
			(await directory([ada, twin])).authenticate("ada", "correct horse"),
		).rejects.toThrow(/matches 2 entries/);
	});
});

describe("transit > ldap > continuation references", () => {
	const references = [
		`ldap://DomainDnsZones.acme.test/DC=DomainDnsZones,${BASE}`,
		`ldap://ForestDnsZones.acme.test/DC=ForestDnsZones,${BASE}`,
	];

	it("signs in when the search also answers references, as Active Directory does", async () => {
		const subject = await directory([ada], {}, { references });

		const user = await subject.authenticate("ada", "correct horse");

		// A reference is not an entry: counting it would have made this login
		// "match 3 entries".
		expect(user.id).toBe(`uid=ada,${BASE}`);
		// And it is not chased: the only binds are the reader and the person.
		expect(server?.binds.map((bind) => bind.dn)).toEqual([
			`cn=reader,${BASE}`,
			`uid=ada,${BASE}`,
		]);
	});

	it("treats a search that answers only references as no match", async () => {
		const subject = await directory([], {}, { references });

		await expect(subject.authenticate("ada", "correct horse")).rejects.toThrow(
			/invalid credentials/,
		);
		// The referral URL never became a DN to bind as.
		expect(server?.binds.map((bind) => bind.dn)).toEqual([`cn=reader,${BASE}`]);
	});

	it("rejects a bind answered with anything but a bind response", async () => {
		// A search-done in place of the bind response, result code 0: read as a
		// bind result it would have said "success".
		const subject = await directory([ada], {}, { bindReplyTag: 0x65 });

		await expect(subject.authenticate("ada", "correct horse")).rejects.toThrow(
			/unexpected reply/,
		);
	});
});

describe("transit > ldap > the empty password", () => {
	it("is refused before the directory is asked", async () => {
		const subject = await directory();

		// A simple bind with no password is an ANONYMOUS bind, and the server
		// answers success — a form that passes one through would sign in as
		// whoever was named.
		await expect(subject.authenticate("ada", "")).rejects.toThrow(
			/anonymous bind/,
		);
		expect(server?.binds).toEqual([]);
	});

	it("is refused for an empty username too", async () => {
		await expect((await directory()).authenticate("", "x")).rejects.toThrow(
			/username is required/,
		);
	});
});

describe("transit > ldap > what a username cannot become", () => {
	it("searches for a hostile login as a login", async () => {
		const subject = await directory();

		await expect(
			subject.authenticate("*)(uid=admin", "whatever"),
		).rejects.toThrow(/invalid credentials/);

		// The filter is a structure, so those characters were searched for
		// literally. In a filter built as text they would have been syntax.
		expect(server?.searched).toEqual(["*)(uid=admin"]);
	});

	it("keeps an extra condition alongside the login", async () => {
		const subject = await directory([ada], {
			filter: { equals: ["objectClass", "person"] },
		});

		await subject.authenticate("ada", "correct horse");

		expect(server?.searched).toEqual(["ada"]);
	});
});

describe("transit > ldap > the connection", () => {
	it("refuses a plaintext directory unless asked", async () => {
		server = await startFakeLdap([ada]);
		const subject = new LdapDirectory({
			url: server.url,
			baseDn: BASE,
			loginAttribute: "uid",
		});

		// A simple bind sends the password as it was typed.
		await expect(subject.authenticate("ada", "correct horse")).rejects.toThrow(
			/not encrypted/,
		);
	});

	it("says so when the directory cannot be reached", async () => {
		const subject = new LdapDirectory({
			url: "ldap://127.0.0.1:1",
			baseDn: BASE,
			loginAttribute: "uid",
			allowInsecure: true,
		});

		await expect(subject.authenticate("ada", "x")).rejects.toThrow(
			/could not reach/,
		);
	});
});

describe("transit > ldap > timeoutMs", () => {
	it("bounds a TLS handshake the directory never completes", async () => {
		// Accepts the connection, then says nothing: no handshake ever ends.
		const accepted: Socket[] = [];
		const silent = createServer((socket) => {
			accepted.push(socket);
			// Read, so the client's close is seen as an end.
			socket.resume();
			socket.on("error", () => {});
		});
		await new Promise<void>((resolve) =>
			silent.listen(0, "127.0.0.1", resolve),
		);
		const address = silent.address();
		const port =
			typeof address === "object" && address !== null ? address.port : 0;
		try {
			const subject = new LdapDirectory({
				url: `ldaps://127.0.0.1:${port}`,
				baseDn: BASE,
				loginAttribute: "uid",
				timeoutMs: 200,
			});
			const started = Date.now();
			await expect(subject.authenticate("ada", "x")).rejects.toThrow(
				/did not answer within 200 ms/,
			);
			expect(Date.now() - started).toBeLessThan(2_000);
			// The socket is not left open behind the refusal.
			await vi.waitFor(() =>
				expect(accepted.every((socket) => socket.destroyed)).toBe(true),
			);
		} finally {
			for (const socket of accepted) socket.destroy();
			await new Promise<void>((resolve) => silent.close(() => resolve()));
		}
	});
});

describe("transit > ldap > through the manager", () => {
	it("is reached with authenticate, not with begin", async () => {
		const manager = new TransitManager();
		manager.register("staff", await directory());

		const user = await manager.authenticate("staff", "ada", "correct horse");
		expect(user.email).toBe("ada@acme.test");

		// A directory has nothing to redirect to, and saying so is more useful
		// than an error about a missing method.
		expect(() => manager.use("staff")).toThrow(/is a directory/);
	});

	it("refuses to treat a redirect provider as a directory", async () => {
		const manager = new TransitManager();
		manager.register("google", {
			redirectUrl: () => "https://accounts.google.test",
			callback: async () => {
				throw new Error("not used");
			},
		});

		expect(() => manager.directory("google")).toThrow(/not a directory/);
	});

	it("builds the driver the helper names", async () => {
		server = await startFakeLdap([ada]);

		expect(
			ldap({ url: server.url, baseDn: BASE, loginAttribute: "uid" })(),
		).toBeInstanceOf(LdapDirectory);
	});
});
