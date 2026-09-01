/**
 * Every outbound call carries a deadline.
 *
 * None of them did. A provider that accepts the connection and then never
 * answers held discovery, JWKS, the token exchange or the callback open for as
 * long as the socket lived — and an identity provider is the one dependency an
 * application cannot route around.
 */
import { describe, expect, it, vi } from "vitest";
import { DEFAULT_TIMEOUT_MS, fetchWithTimeout } from "../../src/httpTimeout.js";

describe("transit > fetchWithTimeout", () => {
	it("aborts a call that never answers", async () => {
		const original = globalThis.fetch;
		// A server that accepts and says nothing — the shape that used to hang.
		globalThis.fetch = ((_input: unknown, init?: RequestInit) =>
			new Promise((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () => {
					reject(new Error("aborted"));
				});
			})) as typeof fetch;
		try {
			await expect(
				fetchWithTimeout("https://idp.test/token", {}, 20),
			).rejects.toThrow(/abort/i);
		} finally {
			globalThis.fetch = original;
		}
	});

	it("passes a signal that is already aborted straight through", async () => {
		const seen: (AbortSignal | null | undefined)[] = [];
		const original = globalThis.fetch;
		globalThis.fetch = ((_input: unknown, init?: RequestInit) => {
			seen.push(init?.signal);
			return Promise.resolve(new Response("ok"));
		}) as typeof fetch;
		try {
			await fetchWithTimeout("https://idp.test/keys");
			expect(seen[0]).toBeInstanceOf(AbortSignal);
		} finally {
			globalThis.fetch = original;
		}
	});

	it("keeps the caller's own signal working alongside the deadline", async () => {
		const controller = new AbortController();
		const original = globalThis.fetch;
		globalThis.fetch = ((_input: unknown, init?: RequestInit) =>
			new Promise((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () => {
					reject(new Error("aborted"));
				});
			})) as typeof fetch;
		try {
			const pending = fetchWithTimeout(
				"https://idp.test/token",
				{ signal: controller.signal },
				60_000,
			);
			controller.abort();
			// The deadline is ADDED to the caller's signal, never substituted for
			// it — a caller that cancels must still cancel.
			await expect(pending).rejects.toThrow(/abort/i);
		} finally {
			globalThis.fetch = original;
		}
	});

	it("uses one default across the package", () => {
		// The LDAP client already waited ten seconds; two answers would be one
		// too many.
		expect(DEFAULT_TIMEOUT_MS).toBe(10_000);
	});
});
