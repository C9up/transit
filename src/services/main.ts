/**
 * Container service accessor — `import transit from '@c9up/transit/services/main'`.
 *
 * Populated by `TransitProvider.boot()`. Reading it before the provider has
 * booted throws rather than answering with an empty manager, because a manager
 * with no providers fails on the first sign-in instead of at startup.
 */

import type { TransitManager } from "../TransitManager.js";

let instance: TransitManager | undefined;

/** @internal Called by the provider once the manager exists. */
export function setTransit(manager: TransitManager): void {
	instance = manager;
}

/** @internal Test helper — forget the manager between cases. */
export function clearTransit(): void {
	instance = undefined;
}

function resolve(): TransitManager {
	if (!instance) {
		throw new Error(
			"[transit] accessed before initialization — register TransitProvider, or call setTransit() yourself.",
		);
	}
	return instance;
}

/**
 * A proxy so the import can be held before the provider boots.
 *
 * Symbols and `then` answer undefined: a module namespace is probed for
 * `then` when it is imported, and a proxy that threw there would crash the
 * import itself.
 */
const transit = new Proxy({} as TransitManager, {
	get(_target, property) {
		if (typeof property === "symbol" || property === "then") return undefined;
		const value = Reflect.get(resolve(), property);
		return typeof value === "function" ? value.bind(resolve()) : value;
	},
}) as TransitManager;

export default transit;
