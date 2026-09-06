/**
 * Resolving a Redis connection by name, from `@c9up/quasar`.
 *
 * The loading, the shape check and the messages are the same in every package
 * that offers a Redis-backed option, so they are vendored rather than written
 * again: `src/vendor/quasarConnection.ts`, generated from one source. What is
 * specific stays at the call site — transit has several stores, each issuing
 * its own commands, so unlike its siblings it passes them per call rather than
 * fixing one list here.
 */

import { quasarConnection as loadQuasarConnection } from "./vendor/quasarConnection.js";

/** The named connection, checked for the commands the caller will issue. */
export async function quasarConnection<T>(
	name: string | undefined,
	required: readonly string[],
	what: string,
): Promise<T> {
	return loadQuasarConnection<T>({
		pkg: "transit",
		name,
		required,
		what,
		raise: (_reason, message, cause) => new Error(message, { cause }),
	});
}
