/**
 * Helpers shared by transit's tests.
 */

/**
 * The form body a recorded request carried, proven present.
 *
 * `(call?.init?.body as URLSearchParams).get(...)` was the shape here: an
 * optional chain that yields `undefined`, an assertion claiming it is a
 * `URLSearchParams`, and a method call on it. The chain protects nothing — the
 * call throws exactly as it would without it — and the assertion is what kept
 * the compiler from saying so.
 */
export function formBody(
	call: { init?: { body?: unknown } } | undefined,
): URLSearchParams {
	const body = call?.init?.body;
	if (!(body instanceof URLSearchParams)) {
		throw new Error("the recorded request carried no form body");
	}
	return body;
}
