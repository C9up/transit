/**
 * Wires `config/transit.ts` into the container.
 *
 * Transit does not import `@c9up/ream`: the slice of the host it needs is
 * duck-typed below, which is what keeps the package publishable on its own and
 * usable from a host that is not Ream.
 */

import "./augmentations.js";
import type { TransitConfig } from "./config.js";
import { clearTransit, getTransit, setTransit } from "./services/main.js";
import { TransitManager } from "./TransitManager.js";

interface TransitContainer {
	singleton(token: unknown, factory: () => unknown): void;
	resolve<T = unknown>(token: unknown): Promise<T>;
}

interface TransitConfigStore {
	get<T = unknown>(key: string): T | undefined;
}

export interface TransitAppContext {
	container: TransitContainer;
	config: TransitConfigStore;
}

export default class TransitProvider {
	/** The manager this provider seated, so shutdown only clears its own. */
	#manager: TransitManager | undefined;

	constructor(protected app: TransitAppContext) {}

	register(): void {
		this.app.container.singleton(TransitManager, () => {
			const config = this.app.config.get<TransitConfig>("transit") ?? {};
			const manager = new TransitManager();
			for (const [name, entry] of Object.entries(config)) {
				manager.register(name, typeof entry === "function" ? entry() : entry);
			}
			return manager;
		});
		// String alias, so a consumer that cannot import Transit still resolves
		// it — the same convention the other providers follow.
		this.app.container.singleton("transit", () =>
			this.app.container.resolve<TransitManager>(TransitManager),
		);
	}

	async boot(): Promise<void> {
		const manager =
			await this.app.container.resolve<TransitManager>(TransitManager);
		this.#manager = manager;
		setTransit(manager);
	}

	async shutdown(): Promise<void> {
		// Release the module-level singleton, while it is still ours. A stopped
		// application left a dead TransitManager reachable through
		// `services/main` — and this one holds the SSO providers, so a stale one
		// answers sign-ins for an application that no longer exists.
		if (this.#manager !== undefined && getTransit() === this.#manager) {
			clearTransit();
		}
		this.#manager = undefined;
	}
}
