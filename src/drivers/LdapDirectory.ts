/**
 * An LDAP or Active Directory directory.
 *
 * Nothing is redirected: the application already holds the credentials, and the
 * directory is the authority that says whether they are right. Verifying them
 * means binding AS that person — a bind that succeeds is the answer, and there
 * is no other one.
 *
 * The flow is two connections on purpose. The first finds the person's DN,
 * bound as whatever the application is allowed to search with. The second binds
 * as the person, and is closed immediately: a connection carries the identity
 * of whatever last bound on it, so nothing else may run on that one.
 */

import { randomUUID } from "node:crypto";
import { E_TRANSIT_LDAP_ERROR } from "../errors.js";
import { LdapConnection, type LdapEntry, type LdapFilter } from "../ldap.js";
import type { DirectoryDriver, TransitUser } from "../types.js";

/**
 * The one refusal for a wrong password and an unknown login: which of the two
 * it was is not something a sign-in form should disclose.
 */
function invalidCredentials(): E_TRANSIT_LDAP_ERROR {
	return new E_TRANSIT_LDAP_ERROR(
		"the directory refused the bind: invalid credentials",
		49,
	);
}

/**
 * Whether a credential is something a person typed: a string, of at least one
 * byte once encoded.
 *
 * The signature says `string`, and nothing holds a request body to it: a body
 * parser answers `[""]` for `password[]=`, `{ length: "1" }` for
 * `password[length]=1`, and a JSON body carries whatever it carries. None of
 * those is `""`, and every one of them encodes to an empty password.
 */
function isCredential(value: unknown): value is string {
	return typeof value === "string" && Buffer.byteLength(value, "utf8") > 0;
}

export interface LdapConfig {
	/** `ldaps://directory.acme.test:636`. */
	url: string;
	/** Where to search from — `dc=acme,dc=test`. */
	baseDn: string;
	/**
	 * The attribute a person types. `uid` on OpenLDAP,
	 * `sAMAccountName` or `userPrincipalName` on Active Directory.
	 */
	loginAttribute: string;
	/** The account the search runs as. Omitted means an anonymous search. */
	bindDn?: string;
	bindPassword?: string;
	/** Extra conditions on the search, ANDed with the login attribute. */
	filter?: LdapFilter;
	/** Attributes to read. Defaults to the ones the mapping below uses. */
	attributes?: string[];
	/** The attribute names this directory uses, when they are not the usual ones. */
	claims?: { email?: string; name?: string; nickName?: string };
	/** Allow a plaintext connection — see the note on `LdapOptions`. */
	allowInsecure?: boolean;
	/** Refuse a server certificate that does not check out. Default true. */
	rejectUnauthorized?: boolean;
	/**
	 * How long to wait for the directory, in milliseconds: for the connection
	 * and its TLS handshake, then for each reply. Default 10 000.
	 */
	timeoutMs?: number;
}

const EMAIL_ATTRS = ["mail", "userPrincipalName", "email"];
const NAME_ATTRS = ["displayName", "cn", "name"];
const NICK_ATTRS = ["uid", "sAMAccountName", "givenName"];

export class LdapDirectory implements DirectoryDriver {
	readonly #config: LdapConfig;

	constructor(config: LdapConfig) {
		this.#config = config;
	}

	async authenticate(username: string, password: string): Promise<TransitUser> {
		// Refused here as well as in the bind: a form that submits an empty
		// password must not reach the directory, which would answer success to
		// an anonymous bind.
		if (password === "") {
			throw new E_TRANSIT_LDAP_ERROR(
				"a password is required — an empty one is an anonymous bind, which the directory would accept",
				undefined,
				{
					status: 400,
				},
			);
		}
		if (username === "") {
			throw new E_TRANSIT_LDAP_ERROR("a username is required", undefined, {
				status: 400,
			});
		}
		// Anything else that is not text is refused before the directory is
		// reached, and as a wrong password: there is nothing to tell whoever
		// sent it. A login is held to the same rule — it would otherwise be
		// encoded into the search filter at a size the request chose.
		if (!isCredential(username) || !isCredential(password)) {
			throw invalidCredentials();
		}

		const entry = await this.#find(username);
		if (entry === undefined) {
			// An unknown login does the work a known one does — a second
			// connection and a bind with the offered password — against a DN
			// that names nobody, so the duration does not tell the two apart.
			// Whatever that bind answers, the sign-in is refused.
			await this.#bindAs(this.#decoyDn(), password).catch(() => undefined);
			throw invalidCredentials();
		}
		try {
			await this.#bindAs(entry.dn, password);
		} catch (error) {
			// The refusal of a wrong password reads exactly like an unknown one.
			if (error instanceof E_TRANSIT_LDAP_ERROR && error.resultCode === 49) {
				throw invalidCredentials();
			}
			throw error;
		}
		return this.#mapUser(entry);
	}

	/** A DN under the base that no entry has: random, so none can be made to. */
	#decoyDn(): string {
		return `cn=transit-decoy-${randomUUID()},${this.#config.baseDn}`;
	}

	/** Find the person, bound as whatever may search. Undefined when unknown. */
	async #find(username: string): Promise<LdapEntry | undefined> {
		const connection = this.#open();
		await connection.connect();
		try {
			if (this.#config.bindDn) {
				await connection.bind(
					this.#config.bindDn,
					this.#config.bindPassword ?? "",
				);
			}

			// The username is a VALUE in a structure, never text in a filter, so
			// a login of `*)(uid=admin` is a login containing those characters.
			const login: LdapFilter = {
				equals: [this.#config.loginAttribute, username],
			};
			const filter: LdapFilter = this.#config.filter
				? { and: [this.#config.filter, login] }
				: login;

			const entries = await connection.search({
				base: this.#config.baseDn,
				filter,
				attributes: this.#config.attributes ?? [
					...EMAIL_ATTRS,
					...NAME_ATTRS,
					...NICK_ATTRS,
				],
				// Two, so an ambiguous login is seen rather than silently
				// resolved to whichever the directory returned first.
				sizeLimit: 2,
			});

			const [entry, ...others] = entries;
			if (others.length > 0) {
				throw new E_TRANSIT_LDAP_ERROR(
					`'${username}' matches ${entries.length} entries, and this signs in one person`,
				);
			}
			return entry;
		} finally {
			await connection.close();
		}
	}

	/** Bind as the person. A bind that succeeds IS the verification. */
	async #bindAs(dn: string, password: string): Promise<void> {
		const connection = this.#open();
		await connection.connect();
		try {
			await connection.bind(dn, password);
		} finally {
			// The connection now carries this person's identity; it is closed
			// rather than reused.
			await connection.close();
		}
	}

	#open(): LdapConnection {
		return new LdapConnection({
			url: this.#config.url,
			allowInsecure: this.#config.allowInsecure,
			rejectUnauthorized: this.#config.rejectUnauthorized,
			timeoutMs: this.#config.timeoutMs,
		});
	}

	#mapUser(entry: LdapEntry): TransitUser {
		const claims = this.#config.claims ?? {};
		const email = pick(entry, claims.email, EMAIL_ATTRS);
		const name = pick(entry, claims.name, NAME_ATTRS);
		const nickName = pick(entry, claims.nickName, NICK_ATTRS);

		return {
			// The DN is what the directory calls this entry, and the only value
			// guaranteed to be unique and stable.
			id: entry.dn,
			email: email ?? "",
			name: name ?? nickName ?? entry.dn,
			nickName,
			// A directory that holds an address has vouched for it: that is what
			// a directory is. Unlike a SAML provider, the directory is the one
			// the operator configured and runs — if it is a customer's, its
			// addresses are that customer's say-so (see the README).
			emailVerificationState: email === undefined ? "unsupported" : "verified",
			raw: { dn: entry.dn, attributes: entry.attributes },
		};
	}
}

function pick(
	entry: LdapEntry,
	configured: string | undefined,
	candidates: string[],
): string | undefined {
	for (const name of configured ? [configured] : candidates) {
		const value = entry.attributes[name]?.[0];
		if (value !== undefined && value !== "") return value;
	}
	return undefined;
}
