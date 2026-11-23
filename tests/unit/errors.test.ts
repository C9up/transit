import { Exception } from "@c9up/flare";
import { describe, expect, it, vi } from "vitest";
import { errors } from "../../src/index.js";

describe("transit > errors", () => {
	it("are exported as one namespace of flare exceptions", () => {
		const error = new errors.E_OAUTH_STATE_MISMATCH();
		expect(error).toBeInstanceOf(Exception);
		expect(error).toMatchObject({
			code: "E_OAUTH_STATE_MISMATCH",
			status: 400,
			message: "Unable to verify re-redirect state",
			identifier: "errors.E_OAUTH_STATE_MISMATCH",
		});
		expect(new errors.E_TRANSIT_INVALID_XML(["bad"])).toMatchObject({
			code: "E_TRANSIT_INVALID_XML",
			status: 500,
			message: "[transit] bad",
		});
	});

	it("keeps a directory's result code apart from the error code", () => {
		const refused = new errors.E_TRANSIT_LDAP_ERROR("refused", 49);
		expect(refused).toMatchObject({
			code: "E_TRANSIT_LDAP_ERROR",
			resultCode: 49,
			status: 400,
			message: "[transit] refused",
		});
		const unreachable = new errors.E_TRANSIT_LDAP_ERROR("down");
		expect(unreachable).toMatchObject({ status: 500, resultCode: undefined });
	});

	it("keep upstream's OAuth errors, with their identifiers", () => {
		expect(new errors.E_OAUTH_MISSING_CODE(["oauth_verifier"])).toMatchObject({
			code: "E_OAUTH_MISSING_CODE",
			status: 500,
			identifier: "errors.E_OAUTH_MISSING_CODE",
			message:
				'Cannot request access token. Redirect request is missing the "oauth_verifier" param',
		});
		const unknown = new errors.E_TRANSIT_UNKNOWN_PROVIDER(["gitlab"]);
		expect(unknown).toBeInstanceOf(errors.HttpResponseException);
		expect(unknown).toMatchObject({
			code: "E_TRANSIT_UNKNOWN_PROVIDER",
			status: 404,
			identifier: "errors.E_TRANSIT_UNKNOWN_PROVIDER",
			message: 'Unknown authentication provider "gitlab"',
		});
	});

	describe("render themselves", () => {
		function context(
			format: string | null,
			extra: Record<string, unknown> = {},
		) {
			const status = vi.fn();
			const send = vi.fn();
			const back = vi.fn();
			const ctx = {
				request: {
					accepts: <T extends string>(types: T[]): T | null =>
						types.find((type) => type === format) ?? null,
				},
				response: { status, send, redirect: () => ({ back }) },
				...extra,
			};
			return { ctx, status, send, back };
		}

		it("as { errors: [{ message }] } for JSON", async () => {
			const error = new errors.E_OAUTH_STATE_MISMATCH();
			const { ctx, status, send } = context("json");
			await error.handle(error, ctx);
			expect(status).toHaveBeenCalledWith(400);
			expect(send).toHaveBeenCalledWith({
				errors: [{ message: "Unable to verify re-redirect state" }],
			});
		});

		it("as a JSON:API error object", async () => {
			const error = new errors.E_TRANSIT_UNKNOWN_PROVIDER(["gitlab"]);
			const { ctx, status, send } = context("application/vnd.api+json");
			await error.handle(error, ctx);
			expect(status).toHaveBeenCalledWith(404);
			expect(send).toHaveBeenCalledWith({
				errors: [
					{
						code: "E_TRANSIT_UNKNOWN_PROVIDER",
						title: 'Unknown authentication provider "gitlab"',
					},
				],
			});
		});

		it("as a flash and a redirect back for a browser with a session", async () => {
			const error = new errors.E_OAUTH_STATE_MISMATCH();
			const session = { flash: vi.fn(), flashErrors: vi.fn() };
			const { ctx, send, back } = context("html", { session });
			await error.handle(error, ctx);
			expect(session.flash).toHaveBeenCalledWith(
				"error",
				"Unable to verify re-redirect state",
			);
			expect(session.flashErrors).toHaveBeenCalledWith({
				E_OAUTH_STATE_MISMATCH: "Unable to verify re-redirect state",
			});
			expect(back).toHaveBeenCalled();
			expect(send).not.toHaveBeenCalled();
		});

		it("as text without a session, translated through ctx.i18n", async () => {
			const error = new errors.E_OAUTH_STATE_MISMATCH();
			const t = vi.fn(() => "État de redirection invérifiable");
			const { ctx, status, send } = context(null, { i18n: { t } });
			await error.handle(error, ctx);
			expect(t).toHaveBeenCalledWith(
				"errors.E_OAUTH_STATE_MISMATCH",
				{},
				"Unable to verify re-redirect state",
			);
			expect(status).toHaveBeenCalledWith(400);
			expect(send).toHaveBeenCalledWith("État de redirection invérifiable");
		});
	});
});
