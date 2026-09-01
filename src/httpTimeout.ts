/**
 * Every outbound call this package makes, with a deadline on it.
 *
 * None of them had one. A provider that accepts the connection and then never
 * answers held a request open indefinitely — discovery, JWKS, the token
 * exchange, the callback — and the only thing that eventually freed it was the
 * caller's own infrastructure, if it had any. An identity provider is the one
 * dependency an application cannot route around, so it is the one that most
 * needs a bound.
 *
 * Ten seconds, matching what the LDAP client already used, so the package has
 * one answer rather than two.
 */
export const DEFAULT_TIMEOUT_MS = 10_000;

/** `fetch`, refusing to wait forever. */
export async function fetchWithTimeout(
	input: string | URL,
	init: RequestInit = {},
	timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
	const deadline = AbortSignal.timeout(timeoutMs);
	// A caller's own signal still cancels: the deadline is added to it, never
	// substituted for it.
	const signal =
		init.signal === null || init.signal === undefined
			? deadline
			: AbortSignal.any([init.signal, deadline]);
	return fetch(input, { ...init, signal });
}
