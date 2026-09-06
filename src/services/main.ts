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

/** @internal Read the seated manager, if there is one. */
export function getTransit(): TransitManager | undefined {
	return instance;
}

/**
 * @internal Forget the manager — called by the provider on shutdown, and by
 * tests between cases.
 *
 * The caller checks ownership first (`getTransit() === mine`): two applications
 * share this module in one process, and the one shutting down must not clear a
 * manager the other has since seated.
 */
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
