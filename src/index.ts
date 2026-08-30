/**
 * @c9up/transit — federated sign-in for the Ream framework.
 *
 * Everything that lets a person prove who they are through an authority the
 * application does not own. Today that is OAuth1 and OAuth2, and the providers
 * that speak them.
 */

export type {
	TransitConfig,
	TransitDriverFactory,
	TransitProviderEntry,
} from "./config.js";
export { defineConfig, socials } from "./config.js";
export { DiscordDriver } from "./drivers/DiscordDriver.js";
export { FacebookDriver } from "./drivers/FacebookDriver.js";
export { GitHubDriver } from "./drivers/GitHubDriver.js";
export { GoogleDriver } from "./drivers/GoogleDriver.js";
export { LinkedInDriver } from "./drivers/LinkedInDriver.js";
export { LinkedInOpenidConnectDriver } from "./drivers/LinkedInOpenidConnectDriver.js";
export { SpotifyDriver } from "./drivers/SpotifyDriver.js";
export { TwitterDriver } from "./drivers/TwitterDriver.js";
export { TwitterXDriver } from "./drivers/TwitterXDriver.js";
export { Oauth1Driver } from "./Oauth1Driver.js";
export { createCodeVerifier, Oauth2Driver } from "./Oauth2Driver.js";
export { TransitManager } from "./TransitManager.js";
export type { TransitAppContext } from "./TransitProvider.js";
export { default as TransitProvider } from "./TransitProvider.js";
export type {
	EmailVerificationState,
	OAuthConfig,
	OAuthToken,
	RedirectRequest,
	TransitDriver,
	TransitUser,
} from "./types.js";
export { assertOAuthState } from "./types.js";
