/**
 * The container service accessor.
 *
 * It is a proxy that can be imported before the provider has booted, and the
 * subtle part is what it must answer to a question it cannot answer yet: a
 * module namespace is probed for `then` when it is imported, and a proxy that
 * threw there would crash the import itself rather than the first use.
 */
import { afterEach, describe, expect, it } from "vitest";
import transit, { clearTransit, setTransit } from "../../src/services/main.js";
import { TransitManager } from "../../src/TransitManager.js";
import { FakeTransit } from "../../src/testing/FakeTransit.js";

afterEach(() => {
	clearTransit();
});

describe("transit > services/main", () => {
	it("answers undefined to `then`, so importing it does not crash", async () => {
		// `await import(...)` probes the namespace for `then`. Throwing there
		// takes down the import, not the call that forgot to boot.
		expect((transit as unknown as { then?: unknown }).then).toBeUndefined();
		await expect(Promise.resolve(transit)).resolves.toBeDefined();
	});

	it("answers undefined to a symbol, for the same reason", () => {
		expect(
			(transit as unknown as Record<symbol, unknown>)[Symbol.toStringTag],
		).toBeUndefined();
		expect(() => `${String(Symbol.iterator in Object(transit))}`).not.toThrow();
	});

	it("says what to register when it is read before the provider booted", () => {
		// Answering with an empty manager would fail on the first sign-in
		// instead, far from the cause.
		expect(() => transit.registeredDrivers).toThrow(
			/accessed before initialization/,
		);
	});

	it("reaches the manager once one is set", async () => {
		const manager = new FakeTransit().willReturn("google");
		setTransit(manager);

		expect(transit.registeredDrivers).toEqual([]);
		const started = await transit.begin("google");
		expect(started.state).toBeTruthy();
	});

	it("keeps a method bound to the manager", async () => {
		const manager = new FakeTransit().willReturn("google");
		setTransit(manager);

		// Pulled off the proxy and called loose, as a callback would be.
		const begin = transit.begin;
		await expect(begin("google")).resolves.toHaveProperty("state");
	});

	it("follows a manager that is replaced", () => {
		setTransit(new TransitManager());
		expect(transit.registeredDrivers).toEqual([]);

		const second = new FakeTransit();
		second.register("x", {
			redirectUrl: () => "https://x.test",
			callback: async () => {
				throw new Error("not used");
			},
		});
		setTransit(second);

		expect(transit.registeredDrivers).toEqual(["x"]);
	});

	it("forgets on clear, which is what a test between cases needs", () => {
		setTransit(new TransitManager());
		clearTransit();

		expect(() => transit.registeredDrivers).toThrow(
			/accessed before initialization/,
		);
	});
});
