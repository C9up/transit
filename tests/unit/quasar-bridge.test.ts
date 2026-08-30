/**
 * The bridge to `@c9up/quasar`.
 *
 * Quasar is an optional peer, so this never imports it statically — the
 * specifier is built at runtime. What matters is that every way it can go wrong
 * says which thing is missing, rather than surfacing as a module error on the
 * first sign-in.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

const SPECIFIER = "@c9up/quasar/services/main";

/**
 * Load the bridge with the quasar module standing in for the real one.
 *
 * Both keys are always declared: a mocked module namespace throws on an export
 * it was not told about, where a real one answers undefined.
 */
async function withQuasar(module: { default?: unknown; connection?: unknown }) {
	vi.resetModules();
	vi.doMock(SPECIFIER, () => ({
		default: undefined,
		connection: undefined,
		...module,
	}));
	return (await import("../../src/quasar.js")).quasarConnection;
}

afterEach(() => {
	vi.doUnmock(SPECIFIER);
	vi.resetModules();
});

describe("transit > the quasar bridge", () => {
	it("says which commands a connection is missing", async () => {
		const quasarConnection = await withQuasar({
			default: { connection: () => ({ set: () => {} }) },
		});

		await expect(
			quasarConnection("main", ["set", "eval", "publish"], "the replay store"),
		).rejects.toThrow(/missing eval, publish/);
	});

	it("names the connection in that message", async () => {
		const quasarConnection = await withQuasar({
			default: { connection: () => ({}) },
		});

		await expect(
			quasarConnection("cache", ["set"], "the replay store"),
		).rejects.toThrow(/connection 'cache' is missing set/);
	});

	it("hands over the named connection when it answers everything", async () => {
		const quasarConnection = await withQuasar({
			default: {
				connection: (name?: string) => ({
					name,
					set: () => {},
					eval: () => {},
				}),
			},
		});

		const resolved = await quasarConnection<{ name?: string }>(
			"main",
			["set", "eval"],
			"the test",
		);

		// The named connection, not the default one.
		expect(resolved.name).toBe("main");
	});

	it("takes the manager off `default`, as a module namespace carries it", async () => {
		const quasarConnection = await withQuasar({
			default: { connection: () => ({ set: () => {} }) },
		});

		await expect(
			quasarConnection(undefined, ["set"], "the test"),
		).resolves.toBeDefined();
	});

	it("takes a manager the module exposes directly", async () => {
		const quasarConnection = await withQuasar({
			connection: () => ({ set: () => {} }),
		});

		await expect(
			quasarConnection("main", ["set"], "the test"),
		).resolves.toBeDefined();
	});

	it("refuses a module that is not a connection manager", async () => {
		const quasarConnection = await withQuasar({ default: { nope: true } });

		await expect(quasarConnection("main", ["set"], "the test")).rejects.toThrow(
			/did not expose a connection\(\)/,
		);
	});

	it("says the package is missing when the import fails", async () => {
		vi.resetModules();
		vi.doMock(SPECIFIER, () => {
			throw new Error("Cannot find module");
		});
		const { quasarConnection } = await import("../../src/quasar.js");

		// The useful message names the package to install, not the module id.
		await expect(quasarConnection("main", ["set"], "the test")).rejects.toThrow(
			/pnpm add @c9up\/quasar/,
		);
	});
});
