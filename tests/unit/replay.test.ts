/**
 * Refusing an assertion that has already been used.
 *
 * A SAML assertion is a bearer token: a signature does not stop a captured
 * response from being posted twice, and every condition on it passes both
 * times. Remembering the id is what makes the second one fail.
 */
import { describe, expect, it, vi } from "vitest";
import {
	MemoryAssertionReplayStore,
	RedisAssertionReplayStore,
	type ReplayRedisClient,
	replayStores,
} from "../../src/replay.js";

const inFiveMinutes = () => Math.floor(Date.now() / 1000) + 300;

/** A Redis double honouring `SET … EX … NX`. */
function fakeRedis() {
	const store = new Map<string, number>();
	const calls: unknown[][] = [];
	const client: ReplayRedisClient & { calls: unknown[][] } = {
		calls,
		async set(key, _value, ...args) {
			calls.push(["set", key, ...args]);
			const live = store.get(key);
			if (args.includes("NX") && live !== undefined && live > Date.now()) {
				return null;
			}
			const ttl = Number(args[args.indexOf("EX") + 1]);
			store.set(key, Date.now() + ttl * 1000);
			return "OK";
		},
	};
	return client;
}

describe("transit > replay > in memory", () => {
	it("accepts an assertion once", async () => {
		const store = new MemoryAssertionReplayStore();

		expect(await store.remember("a-1", inFiveMinutes())).toBe(true);
		expect(await store.remember("a-1", inFiveMinutes())).toBe(false);
	});

	it("keeps assertions apart", async () => {
		const store = new MemoryAssertionReplayStore();

		expect(await store.remember("a-1", inFiveMinutes())).toBe(true);
		expect(await store.remember("a-2", inFiveMinutes())).toBe(true);
	});

	it("forgets an assertion that could no longer be accepted anyway", async () => {
		const store = new MemoryAssertionReplayStore();
		const past = Math.floor(Date.now() / 1000) - 1;

		await store.remember("a-1", past);
		// Nothing accumulates: the window is minutes, and an id outside it is
		// swept on the next call.
		expect(await store.remember("a-1", inFiveMinutes())).toBe(true);
	});
});

describe("transit > replay > in Redis", () => {
	it("accepts an assertion once, across replicas", async () => {
		const redis = fakeRedis();
		const first = new RedisAssertionReplayStore(redis);
		const second = new RedisAssertionReplayStore(redis);

		expect(await first.remember("a-1", inFiveMinutes())).toBe(true);
		// The second replica must refuse what the first accepted.
		expect(await second.remember("a-1", inFiveMinutes())).toBe(false);
	});

	it("decides in one atomic round trip", async () => {
		const redis = fakeRedis();

		await new RedisAssertionReplayStore(redis).remember("a-1", inFiveMinutes());

		// Checking and then storing lets two concurrent posts of the same
		// response both win.
		expect(redis.calls[0]).toContain("NX");
		expect(redis.calls[0]).toContain("EX");
	});

	it("outlives the assertion, so the edge of the window is covered", async () => {
		const redis = fakeRedis();
		const expiresAt = Math.floor(Date.now() / 1000) + 300;

		await new RedisAssertionReplayStore(redis).remember("a-1", expiresAt);

		const ttl = Number(redis.calls[0]?.[redis.calls[0].indexOf("EX") + 1]);
		expect(ttl).toBeGreaterThan(300);
	});

	it("honours a key prefix", async () => {
		const redis = fakeRedis();

		await new RedisAssertionReplayStore(redis, { prefix: "acme:" }).remember(
			"a-1",
			inFiveMinutes(),
		);

		expect(redis.calls[0]?.[1]).toBe("acme:a-1");
	});

	it("resolves the client once, however many assertions arrive", async () => {
		const redis = fakeRedis();
		const resolve = vi.fn(() => redis);
		const store = new RedisAssertionReplayStore(resolve);

		await store.remember("a-1", inFiveMinutes());
		await store.remember("a-2", inFiveMinutes());

		expect(resolve).toHaveBeenCalledTimes(1);
	});
});

describe("transit > replay > the helpers", () => {
	it("builds the store each one names", async () => {
		expect(replayStores.memory()()).toBeInstanceOf(MemoryAssertionReplayStore);
		expect(replayStores.redis({ connection: fakeRedis() })()).toBeInstanceOf(
			RedisAssertionReplayStore,
		);
	});

	it("says what is missing when a connection name resolves to nothing", async () => {
		const store = replayStores.redis({ connection: "main" })();

		await expect(store.remember("a-1", inFiveMinutes())).rejects.toThrow(
			/quasar|redis/i,
		);
	});
});
