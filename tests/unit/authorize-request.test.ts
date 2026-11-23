/**
 * Bug 016: per-request scopes and authorize parameters on begin()/redirect(),
 * the way upstream's redirect takes a request builder callback.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthorizeRequest } from "../../src/AuthorizeRequest.js";
import { oidc, socials } from "../../src/config.js";
import { GitHubDriver } from "../../src/drivers/GitHubDriver.js";
import { GoogleDriver } from "../../src/drivers/GoogleDriver.js";
import { OidcDriver } from "../../src/drivers/OidcDriver.js";
import { SamlDriver } from "../../src/drivers/SamlDriver.js";
import { TwitterXDriver } from "../../src/drivers/TwitterXDriver.js";
import { E_TRANSIT_PROTECTED_PARAMETER } from "../../src/errors.js";
import { TransitManager } from "../../src/TransitManager.js";
import { FakeTransit } from "../../src/testing/FakeTransit.js";

const oauth = {
	clientId: "cid",
	clientSecret: "secret",
	callbackUrl: "https://app.test/cb",
};

const query = (url: string) => new URL(url).searchParams;

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("transit > AuthorizeRequest", () => {
	it("replaces, merges, clears and transforms scopes", () => {
		const request = new AuthorizeRequest(["user:email"]);
		expect(request.mergeScopes(["read:org", "user:email"]).getScopes()).toEqual(
			["user:email", "read:org"],
		);
		expect(request.scopes(["repo"]).getScopes()).toEqual(["repo"]);
		expect(request.clearScopes().getScopes()).toEqual([]);
		request
			.transformScopes((scopes) => scopes.map((s) => `https://x.test/${s}`))
			.mergeScopes(["drive"]);
		expect(request.getScopes()).toEqual(["https://x.test/drive"]);
	});

	it("sets and clears parameters, configured ones included", () => {
		const request = new AuthorizeRequest([], { access_type: "offline" });
		request
			.param("prompt", "consent")
			.param("max_age", 0)
			.clearParam("access_type");
		expect(request.getParams()).toEqual({ prompt: "consent", max_age: "0" });
	});

	it("refuses the parameters the flow's security rests on", () => {
		const request = new AuthorizeRequest([]);
		for (const key of [
			"state",
			"nonce",
			"code_challenge",
			"code_challenge_method",
			"client_id",
			"redirect_uri",
			"response_type",
			"scope",
		]) {
			expect(() => request.param(key, "x")).toThrow(
				E_TRANSIT_PROTECTED_PARAMETER,
			);
			expect(() => request.clearParam(key)).toThrow(
				E_TRANSIT_PROTECTED_PARAMETER,
			);
		}
	});
});

describe("transit > per-request scopes and parameters on OAuth2", () => {
	it("asks for a scope only on the redirect that needs it", async () => {
		const transit = new TransitManager();
		transit.register("github", new GitHubDriver(oauth));

		const plain = await transit.begin("github");
		const upgraded = await transit.begin("github", (request) => {
			request.mergeScopes(["repo"]).param("login", "ada");
		});

		expect(query(plain.url).get("scope")).toBe("read:user user:email");
		expect(query(upgraded.url).get("scope")).toBe("read:user user:email repo");
		expect(query(upgraded.url).get("login")).toBe("ada");
		// The state is still minted and still on the URL.
		expect(query(upgraded.url).get("state")).toBe(upgraded.state);
	});

	it("takes a state and the callback together, and on redirect() too", async () => {
		const transit = new TransitManager();
		transit.register("google", new GoogleDriver(oauth));

		const started = await transit.begin("google", "s-1", (request) =>
			request.scopes(["email"]).clearParam("access_type"),
		);
		expect(started.state).toBe("s-1");
		expect(query(started.url).get("scope")).toBe("email");
		expect(query(started.url).has("access_type")).toBe(false);

		const url = transit.redirect("google", "s-2", undefined, (request) =>
			request.param("prompt", "consent"),
		);
		expect(query(url).get("prompt")).toBe("consent");
		expect(query(url).get("state")).toBe("s-2");
	});

	it("keeps the PKCE challenge whatever the callback does", async () => {
		const driver = new TwitterXDriver(oauth);
		const started = await driver.begin(undefined, (request) =>
			request.param("prompt", "consent"),
		);
		expect(query(started.url).get("code_challenge_method")).toBe("S256");
		expect(query(started.url).get("code_challenge")).toBeTruthy();
		await expect(
			driver.begin(undefined, (request) => {
				request.param("code_challenge", "attacker-known");
			}),
		).rejects.toThrow(E_TRANSIT_PROTECTED_PARAMETER);
	});

	it("builds a fresh request every time: nothing leaks into the next redirect", async () => {
		const driver = new GitHubDriver(oauth);
		await driver.begin(undefined, (request) => request.scopes(["repo"]));
		const next = await driver.begin();
		expect(query(next.url).get("scope")).toBe("read:user user:email");
	});
});

describe("transit > per-request scopes on OpenID Connect", () => {
	const ISSUER = "https://id.acme.test";

	function stubDiscovery() {
		vi.stubGlobal("fetch", (url: string) =>
			Promise.resolve({
				ok: url.startsWith(`${ISSUER}/.well-known`),
				status: 200,
				json: async () => ({
					issuer: ISSUER,
					authorization_endpoint: `${ISSUER}/authorize`,
					token_endpoint: `${ISSUER}/token`,
					jwks_uri: `${ISSUER}/jwks`,
					code_challenge_methods_supported: ["S256"],
				}),
			}),
		);
	}

	it("keeps `openid` even when the callback clears the scopes", async () => {
		stubDiscovery();
		const driver = new OidcDriver({ issuer: ISSUER, ...oauth });
		const started = await driver.begin(undefined, (request) =>
			request
				.clearScopes()
				.mergeScopes(["offline_access"])
				.param("prompt", "login"),
		);
		expect(query(started.url).get("scope")).toBe("openid offline_access");
		expect(query(started.url).get("prompt")).toBe("login");
		expect(query(started.url).get("nonce")).toBeTruthy();
	});

	it("refuses a callback that tries to choose the nonce", async () => {
		stubDiscovery();
		const driver = new OidcDriver({ issuer: ISSUER, ...oauth });
		await expect(
			driver.begin(undefined, (request) => {
				request.param("nonce", "fixed");
			}),
		).rejects.toThrow(E_TRANSIT_PROTECTED_PARAMETER);
	});

	it("is reached through the manager, built from the config helpers", async () => {
		stubDiscovery();
		const transit = new TransitManager();
		transit.register("corp", oidc({ issuer: ISSUER, ...oauth })());
		transit.register("gh", socials.github(oauth)());
		const started = await transit.begin("corp", (request) =>
			request.mergeScopes(["groups"]),
		);
		expect(query(started.url).get("scope")).toBe("openid profile email groups");
	});
});

describe("transit > providers without per-request parameters", () => {
	it("refuses a callback on SAML rather than ignoring it", async () => {
		const driver = new SamlDriver({
			entityId: "https://app.test/saml",
			callbackUrl: "https://app.test/saml/acs",
			signOnUrl: "https://idp.test/sso",
			issuer: "https://idp.test",
			certificates: ["MIIB"],
		});
		await expect(
			driver.begin(undefined, (request) => request.mergeScopes(["x"])),
		).rejects.toThrow(
			expect.objectContaining({
				code: "E_TRANSIT_NO_AUTHORIZE_PARAMS",
				message: expect.stringMatching(/no scopes or authorize parameters/),
			}),
		);
	});
});

describe("transit > FakeTransit records what a redirect asked for", () => {
	it("keeps the scopes and parameters of the callback", async () => {
		const transit = new FakeTransit();
		await transit.begin("github", (request) =>
			request.mergeScopes(["repo"]).param("prompt", "consent"),
		);
		expect(transit.begun[0]?.authorize).toEqual({
			scopes: ["repo"],
			params: { prompt: "consent" },
		});
	});
});
