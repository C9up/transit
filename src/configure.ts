/**
 * `ream configure @c9up/transit` — wire federated sign-in in one command.
 *
 * The provider alone is not enough: it reads `config/transit.ts`, and a package
 * registered without one falls back to a default that is rarely the one an
 * application wants. Writing both together is what makes `ream add` mean
 * installed AND working.
 */

interface Codemods {
	addProvider(importPath: string): Promise<void>;
	writeFile(
		filePath: string,
		content: string,
		options?: { force?: boolean },
	): Promise<void>;
}

export async function configure(codemods: Codemods): Promise<void> {
	await codemods.addProvider("@c9up/transit/provider");
	await codemods.writeFile(
		"config/transit.ts",
		`import { defineConfig, socials } from '@c9up/transit'
import env from '#start/env'

export default defineConfig({
  // The key is yours: it is what \`transit.begin(name)\` asks for.
  google: socials.google({
    clientId: env.get('GOOGLE_CLIENT_ID', ''),
    clientSecret: env.get('GOOGLE_CLIENT_SECRET', ''),
    callbackUrl: 'http://localhost:3333/auth/google/callback',
  }),

  // An OpenID Connect provider needs only its issuer:
  // work: oidc({ issuer: env.get('OIDC_ISSUER'), clientId, clientSecret, callbackUrl }),
})`,
	);
}
