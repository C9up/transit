/**
 * The test double.
 *
 * What matters most here is what it REFUSES: a fake that is lenient where the
 * real drivers are strict teaches applications to ship a controller that never
 * checks the state.
 */
import { describe, expect, it } from "vitest";
import { FakeTransit } from "../../src/testing/FakeTransit.js";

async function signIn(transit: FakeTransit, name: string) {
	const { state, secret } = await transit.begin(name);
	return transit.callback(name, "code", state, state, secret);
}

describe("transit > FakeTransit", () => {
	it("hands back the user a test declared", async () => {
		const transit = new FakeTransit().willReturn("google", {
			id: "42",
			email: "ada@acme.test",
			name: "Ada Lovelace",
		});

		const { user, token } = await signIn(transit, "google");

		expect(user.id).toBe("42");
		expect(user.email).toBe("ada@acme.test");
		expect(token.accessToken).toBeTruthy();
	});

	it("fills in what a test did not say", async () => {
		const transit = new FakeTransit().willReturn("github");

		const { user } = await signIn(transit, "github");

		// A test about roles should not have to invent an avatar.
		expect(user.id).toBe("fake-github-user");
		expect(user.email).toBe("github@example.test");
		expect(user.emailVerificationState).toBe("verified");
	});

	it("refuses a callback whose state was not round-tripped", async () => {
		const transit = new FakeTransit().willReturn("google");
		const { state, secret } = await transit.begin("google");

		// A controller that forgets to store the state passes nothing here. In
		// production that is a session fixation; here it is a failing test.
		await expect(
			transit.callback("google", "code", state, undefined, secret),
		).rejects.toThrow(/requires expectedState/);
		transit.assertNobodySignedIn();
	});

	it("refuses a state that does not match", async () => {
		const transit = new FakeTransit().willReturn("google");
		const { state, secret } = await transit.begin("google");

		await expect(
			transit.callback("google", "code", "attacker", state, secret),
		).rejects.toThrow(/state mismatch/);
	});

	it("refuses a callback that dropped the value begin() returned", async () => {
		const transit = new FakeTransit().willReturn("google");
		const { state } = await transit.begin("google");

		// PKCE verifiers and OAuth1 token secrets travel that way; a controller
		// that stores only the state works with some providers and not others.
		await expect(
			transit.callback("google", "code", state, state),
		).rejects.toThrow(/returned as `secret`/);
	});

	it("says what to call when nothing was declared", async () => {
		const transit = new FakeTransit();
		const { state, secret } = await transit.begin("google");

		await expect(
			transit.callback("google", "code", state, state, secret),
		).rejects.toThrow(/willReturn\('google'/);
	});

	it("records what began and what completed", async () => {
		const transit = new FakeTransit().willReturn("google").willReturn("github");

		await signIn(transit, "google");
		await transit.begin("github");

		transit.assertBegan("google");
		transit.assertBegan("github");
		transit.assertSignedIn("google");
		expect(() => transit.assertSignedIn("github")).toThrow(
			/Expected a sign-in to complete through 'github'/,
		);
	});

	it("lists what it did see when an assertion fails", () => {
		const transit = new FakeTransit();

		expect(() => transit.assertBegan("google")).toThrow(/Nothing was recorded/);
	});

	it("hands back the last user, and forgets on reset", async () => {
		const transit = new FakeTransit().willReturn("google", { id: "42" });

		await signIn(transit, "google");
		expect(transit.lastUser()?.id).toBe("42");

		transit.reset();
		transit.assertNobodySignedIn();
		// What was declared survives — only the recording is cleared.
		await signIn(transit, "google");
		expect(transit.lastUser()?.id).toBe("42");
	});

	it("reads a profile from a token already held", async () => {
		const transit = new FakeTransit().willReturn("google", { id: "42" });

		expect((await transit.userFromToken("google")).id).toBe("42");
		await expect(transit.userFromToken("unknown")).rejects.toThrow(
			/willReturn\('unknown'/,
		);
	});

	it("stands in for the real manager wherever one is expected", async () => {
		const transit = new FakeTransit().willReturn("google");

		// It IS a TransitManager, so a container binding needs no cast.
		const resolve = async (): Promise<
			import("../../src/TransitManager.js").TransitManager
		> => transit;
		const resolved = await resolve();

		expect(await resolved.begin("google")).toHaveProperty("state");
	});
});

describe("transit > FakeTransit > a directory", () => {
	it("signs someone in without any redirect", async () => {
		const transit = new FakeTransit().willReturn("staff", {
			email: "ada@acme.test",
		});

		const user = await transit.authenticate("staff", "ada", "any password");

		expect(user.email).toBe("ada@acme.test");
		transit.assertSignedIn("staff");
	});

	it("refuses an empty password, as the real one does", async () => {
		const transit = new FakeTransit().willReturn("staff");

		// A bind with no password is an anonymous bind the directory accepts.
		// A fake that let it through would teach an application to submit one.
		await expect(transit.authenticate("staff", "ada", "")).rejects.toThrow(
			/anonymous bind/,
		);
		transit.assertNobodySignedIn();
	});

	it("refuses an empty username", async () => {
		const transit = new FakeTransit().willReturn("staff");

		await expect(transit.authenticate("staff", "", "x")).rejects.toThrow(
			/username is required/,
		);
	});

	it("checks the credentials a test declared", async () => {
		const transit = new FakeTransit()
			.willReturn("staff")
			.willAccept("staff", "ada", "correct horse");

		await expect(
			transit.authenticate("staff", "ada", "correct horse"),
		).resolves.toBeDefined();
		await expect(transit.authenticate("staff", "ada", "wrong")).rejects.toThrow(
			/invalid credentials/,
		);
	});

	it("says what to call when nothing was declared", async () => {
		await expect(
			new FakeTransit().authenticate("staff", "ada", "x"),
		).rejects.toThrow(/willReturn\('staff'/);
	});
});
