/**
 * Author-time config for `config/transit.ts`.
 *
 *   import { defineConfig, socials } from '@c9up/transit'
 *
 *   export default defineConfig({
 *     google: socials.google({
 *       clientId: env.get('GOOGLE_CLIENT_ID'),
 *       clientSecret: env.get('GOOGLE_CLIENT_SECRET'),
 *       callbackUrl: 'https://acme.test/auth/google/callback',
 *     }),
 *   })
 *
 * The keys are yours. Two entries may reach the same provider with different
 * credentials — a `staff` sign-in and a `customers` one, both on Google — and
 * `use(name)` asks for the key, not for the provider.
 */

import { type AppleConfig, AppleDriver } from "./drivers/AppleDriver.js";
import { DiscordDriver } from "./drivers/DiscordDriver.js";
import { FacebookDriver } from "./drivers/FacebookDriver.js";
import { GitHubDriver } from "./drivers/GitHubDriver.js";
import { GoogleDriver } from "./drivers/GoogleDriver.js";
import { type LdapConfig, LdapDirectory } from "./drivers/LdapDirectory.js";
import { LinkedInDriver } from "./drivers/LinkedInDriver.js";
import { LinkedInOpenidConnectDriver } from "./drivers/LinkedInOpenidConnectDriver.js";
import { type OidcConfig, OidcDriver } from "./drivers/OidcDriver.js";
import { type SamlConfig, SamlDriver } from "./drivers/SamlDriver.js";
import { SpotifyDriver } from "./drivers/SpotifyDriver.js";
import { TwitterDriver } from "./drivers/TwitterDriver.js";
import { TwitterXDriver } from "./drivers/TwitterXDriver.js";
import type { OAuthConfig, TransitEntry } from "./types.js";

/** A provider, built when the manager is. */
export type TransitDriverFactory = () => TransitEntry;

/** One declared provider: the driver itself, or a factory answering one. */
export type TransitProviderEntry = TransitEntry | TransitDriverFactory;

export type TransitConfig = Record<string, TransitProviderEntry>;

export function defineConfig<T extends TransitConfig>(config: T): T {
	return config;
}

/**
 * The social providers Transit speaks to.
 *
 * Factories are lazy, so a config naming a provider this environment never
 * selects costs nothing to declare.
 */
/**
 * Any provider that speaks OpenID Connect, from its issuer alone — Keycloak,
 * Auth0, Okta, Entra ID, Authentik, Zitadel, and the rest.
 *
 *   work: oidc({
 *     issuer: 'https://id.acme.com',
 *     clientId: env.get('OIDC_CLIENT_ID'),
 *     clientSecret: env.get('OIDC_CLIENT_SECRET'),
 *     callbackUrl: 'https://acme.test/auth/work/callback',
 *   })
 *
 * The endpoints, the signing keys and the algorithms come from what the
 * provider publishes, so there is nothing else to configure and nothing to
 * update when it rotates a key.
 */
export function oidc(config: OidcConfig): TransitDriverFactory {
	return () => new OidcDriver(config);
}

/**
 * A SAML 2.0 identity provider — the enterprise directories that speak it:
 * Okta, Entra ID, ADFS, OneLogin, Shibboleth.
 *
 *   corp: saml({
 *     entityId: 'https://acme.test/saml',
 *     callbackUrl: 'https://acme.test/saml/acs',
 *     issuer: 'https://idp.acme.test/metadata',
 *     signOnUrl: 'https://idp.acme.test/sso',
 *     certificates: [env.get('IDP_CERTIFICATE')],
 *   })
 *
 * The certificates come from the provider's metadata and nowhere else: a
 * response is never verified against a key it carries itself.
 */
export function saml(config: SamlConfig): TransitDriverFactory {
	return () => new SamlDriver(config);
}

/**
 * An LDAP or Active Directory directory.
 *
 *   staff: ldap({
 *     url: 'ldaps://directory.acme.test',
 *     baseDn: 'dc=acme,dc=test',
 *     loginAttribute: 'uid',
 *     bindDn: 'cn=reader,dc=acme,dc=test',
 *     bindPassword: env.get('LDAP_PASSWORD'),
 *   })
 *
 * Reached with `transit.authenticate(name, username, password)`: nothing is
 * redirected, so there is no `begin()` for it.
 */
export function ldap(config: LdapConfig): TransitDriverFactory {
	return () => new LdapDirectory(config);
}

export const socials = {
	/**
	 * Sign in with Apple. Required on iOS as soon as another social sign-in is
	 * offered.
	 *
	 * It takes a key rather than a secret — the Services ID, the Team ID, the
	 * Key ID and the contents of the `.p8` — and its callback arrives as a
	 * POST, because asking for a name forces `response_mode=form_post`. The
	 * name comes once, in that POST: read it with `parseAppleUser` and store
	 * it, because Apple never sends it again.
	 */
	apple(config: AppleConfig): TransitDriverFactory {
		return () => new AppleDriver(config);
	},
	discord(config: OAuthConfig): TransitDriverFactory {
		return () => new DiscordDriver(config);
	},
	facebook(config: OAuthConfig): TransitDriverFactory {
		return () => new FacebookDriver(config);
	},
	github(config: OAuthConfig): TransitDriverFactory {
		return () => new GitHubDriver(config);
	},
	google(config: OAuthConfig): TransitDriverFactory {
		return () => new GoogleDriver(config);
	},
	/**
	 * LinkedIn through the member API, for an application whose LinkedIn app
	 * holds `r_liteprofile` / `r_emailaddress`.
	 */
	linkedin(config: OAuthConfig): TransitDriverFactory {
		return () => new LinkedInDriver(config);
	},
	/** LinkedIn through OpenID Connect — what a new application is issued. */
	linkedinOpenidConnect(config: OAuthConfig): TransitDriverFactory {
		return () => new LinkedInOpenidConnectDriver(config);
	},
	spotify(config: OAuthConfig): TransitDriverFactory {
		return () => new SpotifyDriver(config);
	},
	/**
	 * X through OAuth1 — the older flow, and the one whose profile call returns
	 * the address. Its redirect needs a request token from X, so it is reached
	 * through `begin()` rather than `redirect()`.
	 */
	twitter(config: OAuthConfig): TransitDriverFactory {
		return () => new TwitterDriver(config);
	},
	/** X through OAuth2. It requires PKCE, which `begin()` handles. */
	twitterX(config: OAuthConfig): TransitDriverFactory {
		return () => new TwitterXDriver(config);
	},
};
