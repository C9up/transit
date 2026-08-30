/**
 * Refusing an assertion that has already been used.
 *
 * A SAML assertion is a bearer token: whoever holds it is who it says they
 * are, until it expires. A signature does not change that, and neither does
 * any condition on it — a response captured once and posted twice is valid
 * both times. Remembering the id until the assertion expires is what makes the
 * second time fail.
 *
 * The window is short, so what is stored stays small: an id is forgotten as
 * soon as the assertion it names could no longer have been accepted anyway.
 */

import { quasarConnection } from "./quasar.js";

export interface AssertionReplayStore {
	/**
	 * Remember `assertionId` until `expiresAt` (epoch seconds).
	 *
	 * Answers `true` when this is the first time, `false` when the assertion
	 * has already been used. Implementations must decide that atomically:
	 * checking and then storing lets two concurrent posts of the same response
	 * both win.
	 */
	remember(assertionId: string, expiresAt: number): Promise<boolean>;
}

/**
 * Remembers in this process's memory.
 *
 * Correct while the application runs in one process, and only then: two
 * replicas each keep their own table, so the same assertion is accepted once
 * per replica. Reach for the Redis store the moment a second one exists.
 */
export class MemoryAssertionReplayStore implements AssertionReplayStore {
	readonly #seen = new Map<string, number>();

	async remember(assertionId: string, expiresAt: number): Promise<boolean> {
		const now = Math.floor(Date.now() / 1000);
		// An opportunistic sweep, bounded by the map's own size: the window is
		// minutes, so nothing accumulates.
		for (const [id, expiry] of this.#seen) {
			if (expiry <= now) this.#seen.delete(id);
		}
		if (this.#seen.has(assertionId)) return false;
		this.#seen.set(assertionId, expiresAt);
		return true;
	}
}

/** The commands the Redis store issues. */
export interface ReplayRedisClient {
	/** `SET key value EX <ttl> NX` — answers null when the key already exists. */
	set(key: string, value: string, ...args: unknown[]): Promise<unknown>;
}

export type ReplayRedisResolver =
	| ReplayRedisClient
	| (() => ReplayRedisClient | Promise<ReplayRedisClient>);

export interface RedisReplayOptions {
	/** Key prefix. Default `"transit:saml:assertion:"`. */
	prefix?: string;
}

/**
 * Remembers in Redis, so every replica refuses the assertion the first one
 * accepted.
 *
 * `SET … NX` decides in one round trip, atomically on the server, which is
 * what stops two concurrent posts of the same response from both winning.
 */
export class RedisAssertionReplayStore implements AssertionReplayStore {
	readonly #source: ReplayRedisResolver;
	readonly #prefix: string;
	#resolved: Promise<ReplayRedisClient> | undefined;

	constructor(client: ReplayRedisResolver, options: RedisReplayOptions = {}) {
		this.#source = client;
		this.#prefix = options.prefix ?? "transit:saml:assertion:";
	}

	async remember(assertionId: string, expiresAt: number): Promise<boolean> {
		const client = await this.#client();
		// The key outlives the assertion by a minute, so an assertion accepted
		// at the edge of its window cannot be replayed just after it.
		const ttl = Math.max(
			1,
			Math.ceil(expiresAt - Math.floor(Date.now() / 1000)) + 60,
		);
		const stored = await client.set(
			`${this.#prefix}${assertionId}`,
			"1",
			"EX",
			ttl,
			"NX",
		);
		return stored !== null && stored !== undefined;
	}

	#client(): Promise<ReplayRedisClient> {
		this.#resolved ??= Promise.resolve(
			typeof this.#source === "function" ? this.#source() : this.#source,
		);
		return this.#resolved;
	}
}

/** The replay stores a config names. */
export const replayStores = {
	/** In this process's memory. Bounds nothing across replicas. */
	memory(): () => AssertionReplayStore {
		return () => new MemoryAssertionReplayStore();
	},

	/**
	 * Redis. `connection` takes a client, a function answering one, or the NAME
	 * of a `@c9up/quasar` connection.
	 */
	redis(options: {
		connection: ReplayRedisResolver | string;
		prefix?: string;
	}): () => AssertionReplayStore {
		const client: ReplayRedisResolver =
			typeof options.connection === "string"
				? () =>
						quasarConnection<ReplayRedisClient>(
							options.connection as string,
							["set"],
							"the assertion replay store",
						)
				: options.connection;
		return () =>
			new RedisAssertionReplayStore(client, { prefix: options.prefix });
	},
};
