# @c9up/transit

> Federated sign-in for the Ream framework — everything that lets a person
> prove who they are through an authority your application does not own.

Today: SAML 2.0, LDAP, generic OpenID Connect, OAuth1, OAuth2, and the
providers that speak them — written here, without a dependency, down to the XML
reader a signature is canonicalized over and the BER a directory is asked in.

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

`ream add @c9up/transit` installs it, registers the provider and writes
`config/transit.ts`. The rest of this page assumes that has run.

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

Some providers come back with a POST rather than a redirect: Sign in with Apple
(`form_post`) and SAML post a form, so `input()` reads from the request body.
Only ream's body parser fills that body, so the callback route must run behind
it — in the router middleware of `start/kernel.ts`:

```ts
router.use([() => import('@c9up/ream/bodyparser_middleware')])
```

It parses `application/x-www-form-urlencoded`, the form these providers post,
by default. Without it `input('code')` and `input('state')` are `undefined`,
and the callback fails on the state check rather than saying why.

`begin()` works for every provider. `secret` is `undefined` for a plain OAuth2
provider, the PKCE verifier for one that mandates it, and the request-token
secret for OAuth1 — storing and returning it unconditionally is what lets one
controller serve all three.

## Providers

`socials.apple`, `.discord`, `.facebook`, `.github`, `.google`, `.linkedin`,
`.linkedinOpenidConnect`, `.spotify`, `.twitter` (OAuth1), `.twitterX` (OAuth2).

Sign in with Apple takes a key rather than a secret, its callback arrives as a
POST, and it sends the user's name exactly once — read it with
`parseAppleUser(ctx.request.input('user'))` and store it. Being a POST, that
callback needs the body parser in front of it (see the round trip above).

## LDAP and Active Directory

```ts
export default defineConfig({
  staff: ldap({
    url: 'ldaps://directory.acme.test',
    baseDn: 'dc=acme,dc=test',
    loginAttribute: 'uid',
    bindDn: 'cn=reader,dc=acme,dc=test',
    bindPassword: env.get('LDAP_PASSWORD'),
  }),
})

const user = await transit.authenticate('staff', username, password)
```

An empty password is refused before a socket is opened: a simple bind with no
password is an anonymous bind, and the directory answers success. And there is
no filter string — a filter is a structure whose values are written as octets,
so a username cannot become syntax.

The search ignores continuation references (Active Directory answers some for
any search from a domain root) instead of counting them as entries, and never
follows them.

An address read from the directory is reported `verified`: the directory is
the one you configured and run. If it belongs to someone else — a customer's
directory — its addresses are that customer's say-so, and linking accounts by
email across tenants on that basis is not safe.

## SAML 2.0

```ts
export default defineConfig({
  corp: saml({
    entityId: 'https://acme.test/saml',
    callbackUrl: 'https://acme.test/saml/acs',
    issuer: 'https://idp.acme.test/metadata',
    signOnUrl: 'https://idp.acme.test/sso',
    certificates: [env.get('IDP_CERTIFICATE')],
    replayStore: replayStores.redis({ connection: 'main' }),
  }),
})
```

The provider posts its answer to `callbackUrl` as a form: pass
`ctx.request.input('SAMLResponse')` as the code and
`ctx.request.input('RelayState')` as the state to `transit.callback()`, from a
route behind the body parser (see the round trip above).

The certificates come from the provider's metadata and nowhere else. The
element the signature covers is the element that is read — nothing is looked up
in the document afterwards, which is what closes XML Signature Wrapping. An
assertion is a bearer token, so its id is remembered for as long as it could
still be accepted — its later expiry plus `clockSkewSeconds`.

That record has to be **shared by every replica**, because it is what stops the
same assertion being presented twice. The in-process default bounds replay
within one process and not beyond it, so in production the driver refuses to
choose it for you — say which store you want:

```ts
replayStore: replayStores.redis({ connection: 'main' })  // shared across replicas
replayStore: replayStores.memory()                       // a single process, deliberately
```

Outside production the in-process store remains the default: one dev process is
the case it is correct for.

Whoever administers a SAML provider can assert any address, so an asserted
address is reported `unsupported` unless the config says the provider is
authoritative for it:

```ts
trustEmail: true                        // your own provider: every address is verified
trustedEmailDomains: ['acme.test']      // a customer's: only acme.test addresses are verified, others unverified
```

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

The issuer is compared byte for byte with the discovery document's `issuer` and
with every token's `iss`, so write it exactly as the provider does — Auth0's
ends with a slash (`https://tenant.auth0.com/`).

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

The double still enforces the state round trip, the value `begin()` asked you
to keep, and — for a directory — the refusal of an empty password. A fake that
let a forgetful controller pass would teach applications to ship one.

## Entry points

- `@c9up/transit` — main API
- `@c9up/transit/config` — `defineConfig`, `socials`, `oidc`, `saml`, `ldap`
- `@c9up/transit/provider` — Ream IoC provider
- `@c9up/transit/services/main` — container service accessor
- `@c9up/transit/testing` — `FakeTransit`

## License

MIT
