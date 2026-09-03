/**
 * @c9up/transit — federated sign-in for the Ream framework.
 *
 * Everything that lets a person prove who they are through an authority the
 * application does not own. Today that is OAuth1 and OAuth2, and the providers
 * that speak them.
 */

import "./augmentations.js";

export { type AppleKey, appleClientSecret, parseAppleUser } from "./apple.js";
export { type CanonicalizeOptions, canonicalize } from "./c14n.js";
export type {
	TransitConfig,
	TransitDriverFactory,
	TransitProviderEntry,
} from "./config.js";
export { defineConfig, ldap, oidc, saml, socials } from "./config.js";
export { type AppleConfig, AppleDriver } from "./drivers/AppleDriver.js";
export { DiscordDriver } from "./drivers/DiscordDriver.js";
export { FacebookDriver } from "./drivers/FacebookDriver.js";
export { GitHubDriver } from "./drivers/GitHubDriver.js";
export { GoogleDriver } from "./drivers/GoogleDriver.js";
export { type LdapConfig, LdapDirectory } from "./drivers/LdapDirectory.js";
export { LinkedInDriver } from "./drivers/LinkedInDriver.js";
export { LinkedInOpenidConnectDriver } from "./drivers/LinkedInOpenidConnectDriver.js";
export { type OidcConfig, OidcDriver } from "./drivers/OidcDriver.js";
export { type SamlConfig, SamlDriver } from "./drivers/SamlDriver.js";
export { SpotifyDriver } from "./drivers/SpotifyDriver.js";
export { TwitterDriver } from "./drivers/TwitterDriver.js";
export { TwitterXDriver } from "./drivers/TwitterXDriver.js";
export type { IdTokenClaims, Jwk, SupportedAlg } from "./jwt.js";
export {
	LdapConnection,
	type LdapEntry,
	LdapError,
	type LdapFilter,
	type LdapOptions,
} from "./ldap.js";
export { Oauth1Driver } from "./Oauth1Driver.js";
export { createCodeVerifier, Oauth2Driver } from "./Oauth2Driver.js";
export type { OidcMetadata, RemoteOptions } from "./oidc.js";
export {
	type AssertionReplayStore,
	MemoryAssertionReplayStore,
	RedisAssertionReplayStore,
	type ReplayRedisClient,
	type ReplayRedisResolver,
	replayStores,
} from "./replay.js";
export {
	assertionInside,
	assertResponseSucceeded,
	SAML_ASSERTION_NS,
	SAML_PROTOCOL_NS,
	SamlError,
	type SamlExpectations,
	type SamlIdentity,
	validateAssertion,
} from "./saml.js";
export { TransitManager } from "./TransitManager.js";
export type { TransitAppContext } from "./TransitProvider.js";
export { default as TransitProvider } from "./TransitProvider.js";
export type {
	DirectoryDriver,
	EmailVerificationState,
	OAuthConfig,
	OAuthToken,
	RedirectRequest,
	TransitDriver,
	TransitEntry,
	TransitUser,
} from "./types.js";
export { assertOAuthState, isDirectory } from "./types.js";
export {
	childrenNamed,
	findByAttribute,
	parseXml,
	resolvePrefix,
	textOf,
	walk,
	XML_NS,
	type XmlAttribute,
	type XmlElement,
	type XmlNamespace,
	type XmlNode,
} from "./xml.js";
