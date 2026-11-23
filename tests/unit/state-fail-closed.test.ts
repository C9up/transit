/**
 * The state check was `if (expectedState && state !== expectedState)`, so a
 * caller that passed no expected state got NO CSRF protection and no sign that
 * it was missing. The manager already refused; a driver used directly did not.
 */
import { describe, expect, it } from "vitest";
import { GitHubDriver } from "../../src/drivers/GitHubDriver.js";
import { GoogleDriver } from "../../src/drivers/GoogleDriver.js";

const config = {
	clientId: "id",
	clientSecret: "secret",
	callbackUrl: "https://app.test/callback",
};

describe("transit > OAuth state is verified, not optional", () => {
	for (const [name, make] of [
		["google", () => new GoogleDriver(config)],
		["github", () => new GitHubDriver(config)],
	] as const) {
		it(`${name}: refuses a callback with no expected state`, async () => {
			await expect(make().callback("code", "some-state")).rejects.toThrow(
				expect.objectContaining({
					code: "E_TRANSIT_STATE_REQUIRED",
					message: expect.stringMatching(/requires expectedState/),
				}),
			);
		});

		it(`${name}: refuses a state that does not match`, async () => {
			await expect(make().callback("code", "attacker", "ours")).rejects.toThrow(
				expect.objectContaining({
					code: "E_OAUTH_STATE_MISMATCH",
					message: expect.stringMatching(/Unable to verify re-redirect state/),
				}),
			);
		});

		it(`${name}: refuses a callback without its code before the exchange`, async () => {
			// No request reaches the provider: the refusal names the parameter.
			await expect(make().callback("", "ours", "ours")).rejects.toThrow(
				expect.objectContaining({
					code: "E_OAUTH_MISSING_CODE",
					status: 500,
					message:
						'Cannot request access token. Redirect request is missing the "code" param',
				}),
			);
		});

		it(`${name}: refuses a missing state against an expected one`, async () => {
			await expect(make().callback("code", undefined, "ours")).rejects.toThrow(
				expect.objectContaining({
					code: "E_OAUTH_STATE_MISMATCH",
					message: expect.stringMatching(/Unable to verify re-redirect state/),
				}),
			);
		});
	}

	it("still puts the state on the redirect URL", () => {
		const url = new GoogleDriver(config).redirectUrl("abc123");
		expect(url).toContain("state=abc123");
	});
});
