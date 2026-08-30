/**
 * `config/transit.ts` reaching the container.
 *
 * The point of the package having its own config file: an application declares
 * its providers there and resolves a manager, instead of assembling one.
 */
import { describe, expect, it, vi } from "vitest";
import { socials, type TransitConfig } from "../../src/config.js";
import { GoogleDriver } from "../../src/drivers/GoogleDriver.js";
import { TransitManager } from "../../src/TransitManager.js";
import TransitProvider, {
	type TransitAppContext,
} from "../../src/TransitProvider.js";
import type { TransitDriver } from "../../src/types.js";

/** A container stub that caches, because `singleton` is the whole point. */
function makeApp(config?: TransitConfig): {
	registry: Map<unknown, () => unknown>;
	app: TransitAppContext;
} {
	const registry = new Map<unknown, () => unknown>();
	const built = new Map<unknown, unknown>();
	return {
		registry,
		app: {
			container: {
				singleton(token: unknown, factory: () => unknown) {
					registry.set(token, factory);
				},
				async resolve<T>(token: unknown) {
					if (!built.has(token))
						built.set(token, await registry.get(token)?.());
					return built.get(token) as T;
				},
			},
			config: {
				get<T>(key: string): T | undefined {
					return key === "transit" ? (config as T) : undefined;
				},
			},
		},
	};
}

const credentials = {
	clientId: "id",
	clientSecret: "secret",
	callbackUrl: "https://acme.test/cb",
};

describe("transit > provider", () => {
	it("registers the manager under its class and the `transit` alias", async () => {
		const { app } = makeApp({ google: socials.google(credentials) });

		const provider = new TransitProvider(app);
		provider.register();

		const manager = await app.container.resolve(TransitManager);
		expect(manager).toBeInstanceOf(TransitManager);
		// The alias has to reach the SAME manager, not a second one.
		expect(await app.container.resolve("transit")).toBe(manager);
	});

	it("keys each provider by the name the config chose, not by its kind", () => {
		const { registry, app } = makeApp({
			staff: socials.google(credentials),
			customers: socials.google({ ...credentials, clientId: "other" }),
		});

		new TransitProvider(app).register();
		const manager = registry.get(TransitManager)?.() as TransitManager;

		expect(manager.registeredDrivers).toEqual(["staff", "customers"]);
		expect(manager.use("staff")).not.toBe(manager.use("customers"));
	});

	it("takes a driver given directly", () => {
		const driver: TransitDriver = {
			redirectUrl: () => "https://acme.test/go",
			callback: async () => {
				throw new Error("not used");
			},
		};
		const { registry, app } = makeApp({ custom: driver });

		new TransitProvider(app).register();
		const manager = registry.get(TransitManager)?.() as TransitManager;

		expect(manager.use("custom")).toBe(driver);
	});

	it("builds each provider only when the manager is resolved", () => {
		const built = vi.fn(() => socials.google(credentials)());
		const { registry, app } = makeApp({ google: built });

		new TransitProvider(app).register();
		expect(built).not.toHaveBeenCalled();

		// A config may name providers this deployment never selects; building
		// them all at registration would be work nobody asked for.
		registry.get(TransitManager)?.();
		expect(built).toHaveBeenCalledTimes(1);
	});

	it("registers an empty manager when nothing is configured", () => {
		const { registry, app } = makeApp();

		new TransitProvider(app).register();
		const manager = registry.get(TransitManager)?.() as TransitManager;

		expect(manager.registeredDrivers).toEqual([]);
		// Asking for a provider that was never declared names what exists.
		expect(() => manager.use("google")).toThrow(/not registered/);
	});

	it("builds the driver each helper names", () => {
		expect(socials.google(credentials)()).toBeInstanceOf(GoogleDriver);
	});
});
