/**
 * FakeTransit — a test double for `TransitManager`.
 *
 * A sign-in cannot be exercised against a real provider in a test, so this
 * stands in for one: it hands back a redirect, and answers the callback with
 * whatever user the test declared.
 *
 * It is deliberately NOT lenient. The state round trip and the value `begin()`
 * asked to keep are enforced here exactly as the real drivers enforce them,
 * because a fake that lets a forgetful controller pass is a fake that teaches
 * applications to ship one. A test that fails here would have been a session
 * fixation in production.
 *
 *   import { FakeTransit } from '@c9up/transit/testing'
 *
 *   const transit = new FakeTransit()
 *   transit.willReturn('google', { email: 'ada@acme.test' })
 *   container.singleton(TransitManager, () => transit)
 *
 *   // ... the code under test runs its sign-in
 *   transit.assertSignedIn('google')
 */

import { randomUUID } from "node:crypto";
import { TransitManager } from "../TransitManager.js";
import type { OAuthToken, RedirectRequest, TransitUser } from "../types.js";
import { assertOAuthState } from "../types.js";

/** What a test declares a provider will answer with. */
export interface FakeIdentity extends Partial<TransitUser> {
	email?: string;
}

export interface BegunSignIn {
	name: string;
	state: string;
	secret: string;
}

export interface CompletedSignIn {
	name: string;
	user: TransitUser;
}

const DEFAULT_TOKEN: OAuthToken = { accessToken: "fake-access-token" };

export class FakeTransit extends TransitManager {
	readonly #identities = new Map<string, TransitUser>();
	readonly #tokens = new Map<string, OAuthToken>();
	/** Every `begin()` this saw, oldest first. */
	readonly begun: BegunSignIn[] = [];
	/** Every sign-in that completed, oldest first. */
	readonly signedIn: CompletedSignIn[] = [];

	/**
	 * Declare who comes back from `name`. Anything left out is filled in, so a
	 * test states only what it is about.
	 */
	willReturn(
		name: string,
		identity: FakeIdentity = {},
		token?: OAuthToken,
	): this {
		this.#identities.set(name, {
			id: identity.id ?? `fake-${name}-user`,
			email: identity.email ?? `${name}@example.test`,
			name: identity.name ?? "Fake User",
			nickName: identity.nickName,
			avatarUrl: identity.avatarUrl,
			emailVerificationState: identity.emailVerificationState ?? "verified",
			raw: identity.raw ?? {},
		});
		if (token) this.#tokens.set(name, token);
		return this;
	}

	override async begin(
		name: string,
		state: string = randomUUID(),
	): Promise<RedirectRequest> {
		const secret = randomUUID();
		this.begun.push({ name, state, secret });
		return {
			url: `https://transit.test/${encodeURIComponent(name)}?state=${encodeURIComponent(state)}`,
			state,
			secret,
		};
	}

	override redirect(name: string, state?: string): string {
		this.begun.push({ name, state: state ?? "", secret: "" });
		return `https://transit.test/${encodeURIComponent(name)}?state=${encodeURIComponent(state ?? "")}`;
	}

	override async callback(
		name: string,
		_code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: TransitUser; token: OAuthToken }> {
		// The same refusal the real drivers make. A controller that forgets to
		// store the state, or to hand it back, fails in the test rather than in
		// production.
		assertOAuthState(state, expectedState);

		const started = this.begun.find((entry) => entry.name === name);
		if (started?.secret && secret !== started.secret) {
			throw new Error(
				`[transit] the callback for '${name}' did not carry the value begin() returned as \`secret\` — store it with the state.`,
			);
		}

		const user = this.#identities.get(name);
		if (!user) {
			throw new Error(
				`[transit] nothing declared for '${name}'. Call willReturn('${name}', …) before the sign-in runs.`,
			);
		}
		this.signedIn.push({ name, user });
		return { user, token: this.#tokens.get(name) ?? DEFAULT_TOKEN };
	}

	override async userFromToken(name: string): Promise<TransitUser> {
		const user = this.#identities.get(name);
		if (!user) {
			throw new Error(
				`[transit] nothing declared for '${name}'. Call willReturn('${name}', …) first.`,
			);
		}
		return user;
	}

	/** A sign-in through `name` was started. */
	assertBegan(name: string): void {
		if (!this.begun.some((entry) => entry.name === name)) {
			throw new Error(
				`Expected a sign-in to begin through '${name}'. ${this.#saw(this.begun.map((e) => e.name))}`,
			);
		}
	}

	/** A sign-in through `name` completed. */
	assertSignedIn(name: string): void {
		if (!this.signedIn.some((entry) => entry.name === name)) {
			throw new Error(
				`Expected a sign-in to complete through '${name}'. ${this.#saw(this.signedIn.map((e) => e.name))}`,
			);
		}
	}

	/** Nobody was signed in — what a rejected callback should leave behind. */
	assertNobodySignedIn(): void {
		if (this.signedIn.length > 0) {
			throw new Error(
				`Expected nobody to be signed in, and ${this.signedIn.length} was: ${this.signedIn.map((e) => e.name).join(", ")}`,
			);
		}
	}

	/** The user handed back by the last completed sign-in. */
	lastUser(): TransitUser | undefined {
		return this.signedIn.at(-1)?.user;
	}

	/** Forget everything recorded, keeping what was declared. */
	reset(): void {
		this.begun.length = 0;
		this.signedIn.length = 0;
	}

	#saw(names: string[]): string {
		return names.length === 0
			? "Nothing was recorded."
			: `Recorded: ${names.join(", ")}.`;
	}
}
