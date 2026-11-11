/**
 * Reading what a provider sends back.
 *
 * A token endpoint, a discovery document or a profile is JSON from another
 * party: its shape is checked here, never asserted, so `null`, a list or a
 * string answers with a refusal rather than a TypeError deep in a sign-in.
 */

/** A plain JSON object: not `null`, not a list. */
export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The body of `response`, which has to be a JSON object. */
export async function readJsonObject(
	response: Response,
	what: string,
): Promise<Record<string, unknown>> {
	let body: unknown;
	try {
		body = await response.json();
	} catch {
		throw new Error(`[transit] ${what} is not JSON`);
	}
	if (!isRecord(body)) {
		throw new Error(`[transit] ${what} is not a JSON object`);
	}
	return body;
}
