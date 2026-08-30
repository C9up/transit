/**
 * Resolving a Redis connection by name, from `@c9up/quasar`.
 *
 * Transit does not depend on quasar: it is an optional peer, and this module
 * never imports it statically — the specifier is built at runtime so the
 * TypeScript build stays free of it too.
 */

interface ConnectionSource {
	connection(name?: string): unknown;
}

function isConnectionSource(value: unknown): value is ConnectionSource {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "connection") === "function"
	);
}

/**
 * The named connection, checked for the commands the caller needs before it is
 * handed over — a connection missing one would fail on the first sign-in, far
 * from the cause.
 */
export async function quasarConnection<T>(
	name: string | undefined,
	required: readonly string[],
	what: string,
): Promise<T> {
	const specifier = "@c9up/quasar/services/main";
	let loaded: unknown;
	try {
		loaded = await import(/* @vite-ignore */ specifier);
	} catch (cause) {
		throw new Error(
			`[transit] naming a Redis connection needs @c9up/quasar, which is not installed.\n  pnpm add @c9up/quasar`,
			{ cause },
		);
	}

	const manager = isConnectionSource(loaded)
		? loaded
		: Reflect.get(Object(loaded), "default");
	if (!isConnectionSource(manager)) {
		throw new Error(
			"[transit] @c9up/quasar/services/main did not expose a connection() manager",
		);
	}

	const connection = manager.connection(name);
	const missing = required.filter(
		(command) =>
			typeof connection !== "object" ||
			connection === null ||
			typeof Reflect.get(connection, command) !== "function",
	);
	if (missing.length > 0) {
		throw new Error(
			`[transit] the quasar connection${name ? ` '${name}'` : ""} is missing ${missing.join(", ")}, which ${what} issues`,
		);
	}
	return connection as T;
}
