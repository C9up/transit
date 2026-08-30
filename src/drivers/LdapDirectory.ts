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

import {
	LdapConnection,
	type LdapEntry,
	LdapError,
	type LdapFilter,
} from "../ldap.js";
import type { DirectoryDriver, TransitUser } from "../types.js";

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
	/** How long to wait for the directory, in milliseconds. Default 10 000. */
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
			throw new LdapError(
				"a password is required — an empty one is an anonymous bind, which the directory would accept",
			);
		}
		if (username === "") {
			throw new LdapError("a username is required");
		}

		const entry = await this.#find(username);
		await this.#bindAs(entry.dn, password);
		return this.#mapUser(entry);
	}

	/** Find the person, bound as whatever may search. */
	async #find(username: string): Promise<LdapEntry> {
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

			if (entries.length === 0) {
				// The same message as a wrong password: which of the two it was
				// is not something a sign-in form should disclose.
				throw new LdapError(
					"the directory refused the bind: invalid credentials",
					49,
				);
			}
			if (entries.length > 1) {
				throw new LdapError(
					`'${username}' matches ${entries.length} entries, and this signs in one person`,
				);
			}
			return entries[0] as LdapEntry;
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
			// a directory is.
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
