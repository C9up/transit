# @c9up/transit

> Federated sign-in for the Ream framework — everything that lets a person
> prove who they are through an authority your application does not own.

Today: generic OpenID Connect, OAuth1, OAuth2, and the providers that speak
them. The package exists so that SAML and directory lookups can join them
without inflating the authentication package.

Part of **[Ream](https://github.com/C9up/ream)**. Independent, publishable
package — it imports nothing from the rest of the framework.

## Installation

```bash
pnpm add @c9up/transit
```

```ts
// reamrc.ts
providers: [
  () => import('@c9up/transit/provider'),
]
```

## Configuration

```ts
// config/transit.ts
import { defineConfig, socials } from '@c9up/transit'

export default defineConfig({
  google: socials.google({
    clientId: env.get('GOOGLE_CLIENT_ID'),
    clientSecret: env.get('GOOGLE_CLIENT_SECRET'),
    callbackUrl: 'https://acme.test/auth/google/callback',
  }),
})
```

The keys are yours: two entries may reach the same provider with different
credentials, and `use(name)` asks for the key.

## The round trip

```ts
import transit from '@c9up/transit/services/main'

// Send the user off
const { url, state, secret } = await transit.begin('google')
ctx.session.put('transit_state', state)
ctx.session.put('transit_secret', secret)
return ctx.response.redirect(url)

// ... and receive them back
const { user, token } = await transit.callback(
  'google',
  ctx.request.input('code'),
  ctx.request.input('state'),
  ctx.session.pull('transit_state'),
  ctx.session.pull('transit_secret'),
)
```

`begin()` works for every provider. `secret` is `undefined` for a plain OAuth2
provider, the PKCE verifier for one that mandates it, and the request-token
secret for OAuth1 — storing and returning it unconditionally is what lets one
controller serve all three.

## Providers

`socials.apple`, `.discord`, `.facebook`, `.github`, `.google`, `.linkedin`,
`.linkedinOpenidConnect`, `.spotify`, `.twitter` (OAuth1), `.twitterX` (OAuth2).

Sign in with Apple takes a key rather than a secret, its callback arrives as a
POST, and it sends the user's name exactly once — read it with
`parseAppleUser(ctx.request.input('user'))` and store it.

## OpenID Connect

One driver for every conforming provider — Keycloak, Auth0, Okta, Entra ID,
Authentik, Zitadel. Give it an issuer; the endpoints, keys and algorithms come
from what the provider publishes.

```ts
export default defineConfig({
  work: oidc({
    issuer: 'https://id.acme.com',
    clientId: env.get('OIDC_CLIENT_ID'),
    clientSecret: env.get('OIDC_CLIENT_SECRET'),
    callbackUrl: 'https://acme.test/auth/work/callback',
  }),
})
```

The `id_token` is a signed statement about who the user is, so it is verified
before anyone is signed in: signature against the published key, algorithm
taken from what the provider **declared** rather than from the token's own
header, and every claim that binds it to this exchange — `iss`, `aud`, `exp`,
and the `nonce`. Only asymmetric signatures are accepted.

## Before linking an account by email

`user.emailVerificationState` is `verified`, `unverified` or `unsupported`.
Only the first may be trusted to match an existing account: `unverified` means
anyone able to type that address at the provider now holds it, and
`unsupported` means the provider says nothing either way.

## Testing

```ts
import { FakeTransit } from '@c9up/transit/testing'

const transit = new FakeTransit().willReturn('google', { email: 'ada@acme.test' })
container.singleton(TransitManager, () => transit)

transit.assertSignedIn('google')
```

The double still enforces the state round trip and the value `begin()` asked
you to keep. A fake that let a forgetful controller pass would teach
applications to ship one.

## Entry points

- `@c9up/transit` — main API
- `@c9up/transit/config` — `defineConfig`, `socials`, `oidc`
- `@c9up/transit/provider` — Ream IoC provider
- `@c9up/transit/services/main` — container service accessor
- `@c9up/transit/testing` — `FakeTransit`

## License

MIT
