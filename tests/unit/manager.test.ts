/**
 * The manager's CSRF gate, and the GitHub / Google flows end to end.
 *
 * The drivers were at 0% coverage. These exercise the security-relevant
 * paths: the `state` (CSRF) check, token-exchange / user-API failure modes,
 * and the user/token mapping. `fetch` is stubbed per test.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { GitHubDriver } from "../../src/drivers/GitHubDriver.js";
import { GoogleDriver } from "../../src/drivers/GoogleDriver.js";
import { TransitManager } from "../../src/TransitManager.js";
import type { OAuthConfig, TransitDriver } from "../../src/types.js";

const config: OAuthConfig = {
	clientId: "cid",
	clientSecret: "secret",
	callbackUrl: "https://app.test/cb",
};

/** Build a minimal fetch Response stand-in. */
function res(ok: boolean, status: number, body: unknown) {
	return { ok, status, json: async () => body };
}

/** Stub global fetch with a queue of responses (one per call, in order). */
function stubFetch(...responses: Array<ReturnType<typeof res>>) {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	let i = 0;
	vi.stubGlobal("fetch", (url: string, init?: RequestInit) => {
		calls.push({ url, init });
		return Promise.resolve(responses[i++] ?? res(false, 500, {}));
	});
	return calls;
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("transit > TransitManager", () => {
	it("use() refuses an unregistered driver and names only the one asked for", () => {
		const m = new TransitManager();
		m.register("google", new GoogleDriver(config));
		// A 404 reaches the client: the message must not list the registered providers.
		expect(() => m.use("github")).toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_UNKNOWN_PROVIDER",
				status: 404,
				message: 'Unknown authentication provider "github"',
			}),
		);
	});

	it("refuses begin() and userFromToken() on a driver that has neither", async () => {
		// A driver of the application's own may implement only the required
		// surface; asking it for more says so instead of calling undefined.
		const bare: TransitDriver = {
			redirectUrl: () => "https://provider.test/authorize",
			callback: async () => {
				throw new Error("not reached");
			},
		};
		const m = new TransitManager();
		m.register("bare", bare);
		await expect(m.begin("bare")).rejects.toMatchObject({
			code: "E_TRANSIT_BEGIN_UNSUPPORTED",
		});
		await expect(m.userFromToken("bare", "at")).rejects.toMatchObject({
			code: "E_TRANSIT_TOKEN_PROFILE_UNSUPPORTED",
		});
	});

	it("callback() refuses to run without expectedState (CSRF requirement)", async () => {
		const m = new TransitManager();
		m.register("github", new GitHubDriver(config));
		await expect(m.callback("github", "code", "s", undefined)).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_STATE_REQUIRED",
				message: expect.stringMatching(/requires expectedState/),
			}),
		);
	});

	it("redirect() delegates to the driver and registeredDrivers lists names", () => {
		const m = new TransitManager();
		m.register("github", new GitHubDriver(config));
		expect(m.redirect("github", "xyz")).toContain(
			"github.com/login/oauth/authorize",
		);
		expect(m.registeredDrivers).toEqual(["github"]);
	});
});

describe("transit > GitHubDriver", () => {
	it("builds an authorize URL with client_id, redirect_uri, default scope and state", () => {
		const url = new URL(new GitHubDriver(config).redirectUrl("st8"));
		expect(url.searchParams.get("client_id")).toBe("cid");
		expect(url.searchParams.get("redirect_uri")).toBe("https://app.test/cb");
		expect(url.searchParams.get("scope")).toBe("read:user user:email");
		expect(url.searchParams.get("state")).toBe("st8");
	});

	it("omits state when none is supplied", () => {
		const url = new URL(new GitHubDriver(config).redirectUrl());
		expect(url.searchParams.has("state")).toBe(false);
	});

	it("rejects a mismatched state (CSRF)", async () => {
		await expect(
			new GitHubDriver(config).callback("code", "evil", "expected"),
		).rejects.toThrow(/Unable to verify re-redirect state/);
	});

	it("throws when the token exchange returns a non-2xx", async () => {
		stubFetch(res(false, 401, {}));
		await expect(
			new GitHubDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_TOKEN_EXCHANGE_FAILED",
				message: expect.stringMatching(/token exchange failed.*401/),
			}),
		);
	});

	it("throws when the token response carries no access_token", async () => {
		stubFetch(res(true, 200, { scope: "read:user" }));
		await expect(
			new GitHubDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_NO_ACCESS_TOKEN",
				message: expect.stringMatching(/no access_token/),
			}),
		);
	});

	it("throws when the user API fails", async () => {
		stubFetch(res(true, 200, { access_token: "tok" }), res(false, 403, {}));
		await expect(
			new GitHubDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_PROFILE_REQUEST_FAILED",
				message: expect.stringMatching(/profile request failed.*403/),
			}),
		);
	});

	it("maps the user and token on success (falls back login→name, id→string)", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: 42, login: "kaen", avatar_url: "http://a/x.png" }),
		);
		const out = await new GitHubDriver(config).callback("code", "s", "s");
		expect(out.user).toMatchObject({
			id: "42",
			name: "kaen",
			avatarUrl: "http://a/x.png",
		});
		expect(out.token.accessToken).toBe("tok");
	});
});

describe("transit > GoogleDriver", () => {
	it("builds an authorize URL with response_type=code and access_type=offline", () => {
		const url = new URL(new GoogleDriver(config).redirectUrl("st8"));
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("access_type")).toBe("offline");
		expect(url.searchParams.get("scope")).toBe("openid email profile");
		expect(url.searchParams.get("state")).toBe("st8");
	});

	it("rejects a mismatched state (CSRF)", async () => {
		await expect(
			new GoogleDriver(config).callback("code", "evil", "expected"),
		).rejects.toThrow(/Unable to verify re-redirect state/);
	});

	it("maps user + token (refreshToken, expiresIn) on success", async () => {
		stubFetch(
			res(true, 200, {
				access_token: "tok",
				refresh_token: "ref",
				expires_in: 3600,
			}),
			res(true, 200, {
				id: "g1",
				email: "k@g.com",
				name: "Kaen",
				picture: "http://a/p",
			}),
		);
		const out = await new GoogleDriver(config).callback("code", "s", "s");
		expect(out.user).toMatchObject({
			id: "g1",
			email: "k@g.com",
			avatarUrl: "http://a/p",
		});
		expect(out.token).toEqual({
			accessToken: "tok",
			refreshToken: "ref",
			expiresIn: 3600,
		});
	});

	it("throws when the token exchange returns a non-2xx", async () => {
		stubFetch(res(false, 400, {}));
		await expect(
			new GoogleDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(/token exchange failed.*400/);
	});

	it("throws when the token response carries no access_token", async () => {
		stubFetch(res(true, 200, {}));
		await expect(
			new GoogleDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(/no access_token/);
	});

	it("throws when userinfo fails", async () => {
		stubFetch(res(true, 200, { access_token: "tok" }), res(false, 500, {}));
		await expect(
			new GoogleDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(/profile request failed.*500/);
	});
});
