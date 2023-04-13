import * as oauth from 'oauth4webapi'
import { merge } from "$lib/utils/merge"
import type { Override } from "$lib/utils/override"
import type { Awaitable } from "$lib/utils/promise"
import type { 
  Client,
  OAuth2TokenEndpointResponse,
  OpenIDTokenEndpointResponse
} from "oauth4webapi"

interface OAuthProviderButtonStyles {
  logo: string
  logoDark: string
  bg: string
  bgDark: string
  text: string
  textDark: string
}

interface Profile {
  sub?: string | null
  name?: string | null
  email?: string | null
  image?: string | null
}

interface User {
  id: string
  name?: string | null
  email?: string | null
  image?: string | null
}

function defaultProfile(profile: any): User {
  return {
    id: profile.sub ?? profile.id,
    name: profile.name ?? profile.nickname ?? profile.preferred_username ?? null,
    email: profile.email ?? null,
    image: profile.picture ?? null,
  }
}

// TODO:
type AuthorizationParameters = any

type IssuerMetadata = any

type OAuthCallbackChecks = any

type OpenIDCallbackChecks = any

type PartialIssuer = Partial<Pick<IssuerMetadata, "jwks_endpoint" | "issuer">>

type CallbackParamsType = any

type OAuthChecks = OpenIDCallbackChecks | OAuthCallbackChecks

type TokenSet = Partial<OAuth2TokenEndpointResponse | OpenIDTokenEndpointResponse>

type UrlParams = Record<string, unknown>

interface EndpointHandler<Profile extends UrlParams, Context = any, Result = any> {
  url?: URL
  params?: Profile
  conform?: (response: Response) => Awaitable<Response | undefined>
  request?: (
    context: Context & { provider: OAuthConfigInternal<Profile> }
  ) => Awaitable<Result>
}

type AuthorizationEndpointHandler = EndpointHandler<AuthorizationParameters>

type TokenEndpointHandler = EndpointHandler<
  UrlParams,
  {
    params: CallbackParamsType
    checks: OAuthChecks
  },
  {
    tokens: TokenSet
  }
>

type UserinfoEndpointHandler = EndpointHandler<UrlParams, { tokens: TokenSet }, Profile>

interface OAuthEndpoints {
  authorization?: AuthorizationEndpointHandler
  token?: TokenEndpointHandler
  userinfo?: UserinfoEndpointHandler
}

/**
 * Shared options for all providers.
 */
interface ProviderOptions {
  /**
   * Unique identifier for the provider. Can appear in the URL.
   */
  id: string

  /**
   * Provider name. Can be displayed on auth buttons.
   */
  name: string

  /**
   * @see {@link ProviderType}
   */
  type: ProviderType
}

/**
 * Base OAuth config.
 */
interface OAuth2Config<Profile> extends ProviderOptions, PartialIssuer {
  /**
   * Identifies the provider. Can be in URL, e.g. /auth/callback/:providerId
   */
  id: string

  /**
   * The name of the provider. Can be shown on auth buttons.
   */
  name: string

  /**
   * OpenID Connect (OIDC) compliant providers can configure this instead of {@link OAuthEndpoints}.
   * Can still manually configure {@link OAuthEndpoints} for advanced controls.
   *
   * [Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414#section-3)
   */
  issuer?: string

  /**
   * Manually configure OIDC provider discovery endpoint.
   */
  wellKnown?: string

  /**
   * 1. Initiate OAuth process by sending the user to this URL.
   *
   * [Authorization endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1)
   */
  authorization?: string | AuthorizationEndpointHandler

  /**
   * 2. After user authenticates and redirects, exchange the provided code for tokens.
   *
   * [Token endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2)
   */
  token?: string | TokenEndpointHandler

  /**
   * 3. After getting tokens, use the access token to authorize request for user info.
   *
   * [Userinfo endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
   */
  userinfo?: string | UserinfoEndpointHandler

  /**
   * Provider type.
   */
  type: "oauth"

  /**
   * Receives the profile object returned by the OAuth provider, and returns a user object.
   */
  profile?: (profile: Profile, tokens: TokenSet) => Awaitable<User>

   /**
   * The CSRF protection performed on the callback endpoint.
   * @default ["pkce"]
   *
   * [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients (PKCE)](https://www.rfc-editor.org/rfc/rfc7636.html#section-4) |
   * [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1) |
   * [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) |
   */
  checks?: ('pkce' | 'state' | 'none' | 'nonce')[]

  /**
   * The OAuth client ID.
   */
  clientId?: string

  /**
   * The OAuth client secret.
   */
  clientSecret?: string

  /**
   * A client object that can be used by `oauth4webapi` to make requests to the provider.
   */
  client?: Partial<Client>

  /**
   * @ignore Used by Auth.js for buttons.
   */
  style?: OAuthProviderButtonStyles

  /**
   * User-defined options. Will be deep-merged with the provider's default options.
   */
  options?: OAuthUserConfig<Profile>
}

/**
 * Any provider config.
 */
type AnyConfig<P = any> = OIDCConfig<P> | OAuth2Config<P>

/**
 * Internally generated OAuth config.
 */
type OAuthConfigInternal<Profile> = Override<
  OAuthConfig<Profile>, 
  Required<Pick<OAuthConfig<Profile>, "clientId" | "checks" | "profile">> & OAuthEndpoints
> 

/** 
 * @internal
 */
// prettier-ignore
export type InternalProvider<T extends ProviderType = ProviderType> = 
  T extends "oauth" ? OAuthConfigInternal<any> : 
  T extends "email" ? never /* ? EmailConfig */ :
  T extends "credentials" ? never /* ? CredentialsConfig */ : never

/**
 * OAuth provider types. Other provider types include "email" and "credentials".
 */
const OAuthTypes: ProviderType[] = ["oidc", "oauth"]

/*
 * Providers passed to Auth.js must define one of these types.
 *
 * @see [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3)
 * @see [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
 * @see [Email or Passwordless Authentication](https://authjs.dev/concepts/oauth)
 * @see [Credentials-based Authentication](https://authjs.dev/concepts/credentials)
 */
export type ProviderType = "oidc" | "oauth" | "email" | "credentials"

export type Provider<P extends Profile = Profile> = AnyConfig<P> & OAuthUserConfig<P>

export type OIDCConfig<Profile> = Override<OAuth2Config<Profile>, { type: "oidc" }>

export type OAuthConfig<Profile> = OIDCConfig<Profile> | OAuth2Config<Profile>

export type OAuthUserConfig<Profile> = Override<
  Partial<OAuthConfig<Profile>>,
  Required<Pick<OAuthConfig<Profile>, "clientId" | "clientSecret">>
>

export type OIDCUserConfig<Profile> =
  Omit<Partial<OIDCConfig<Profile>>, "options" | "type"> &
  Required<Pick<OIDCConfig<Profile>, "clientId" | "clientSecret">>

/**
 * Process an array of providers.
 */
export default function parseProviders(providers: Provider[]): InternalProvider[] {
  const internalProviders: InternalProvider[] = providers.map((provider) => {
    const { options, ...defaultOptions } = provider

    const mergedOptions = merge(defaultOptions, options)

    const internalProvider: InternalProvider = OAuthTypes.includes(mergedOptions.type)
      ? normalizeOAuth(mergedOptions) 
      : mergedOptions

    return internalProvider
  })

  return internalProviders
}

/**
 * Normalize OAuth providers to the common interface.
 */
async function normalizeOAuth(c: AnyConfig & OAuthUserConfig<any>): Promise<OAuthConfigInternal<any>> {
  const authorization = await normalizeEndpoint<'authorization'>(c.authorization, c.issuer)

  if (authorization?.url && !authorization.url?.searchParams.has("scope")) {
    authorization.url.searchParams.set("scope", "openid profile email")
  }

  const token = await normalizeEndpoint<'token'>(c.token, c.issuer)

  const userinfo = await normalizeEndpoint<'userinfo'>(c.userinfo, c.issuer)

  const wellKnown = c.issuer 
    ? c.wellKnown ?? `${c.issuer}/.well-known/openid-configuration`
    : c.wellKnown

  return {
    ...c,
    clientId: c.clientId ?? '',
    wellKnown,
    authorization,
    token,
    userinfo,
    checks: c.checks ?? ["pkce"],
    profile: c.profile ?? defaultProfile,
  }
}

/**
 * Normalize OAuth endpoints.
 */
async function normalizeEndpoint<T extends keyof OAuthConfig<any>>(
  e?: OAuthConfig<any>[T],
  issuer?: string
): Promise<OAuthConfigInternal<any>[T]> {
  if (e == null && issuer != null) {
    const i = new URL(issuer)
    const discoveryResponse = await oauth.discoveryRequest(i)
    const as = await oauth.processDiscoveryResponse(i, discoveryResponse)
    return { url: as.authorization_endpoint }
  }

  if (typeof e === "string") {
    return { url: new URL(e) }
  }

  const url = new URL(e?.url ?? "https://authjs.dev")

  if (e?.params != null) {
    Object.entries(e.params).forEach(([key, value]) => {
      url.searchParams.set(key, key === 'claims' ? JSON.stringify(value) : String(value))
    })
  }

  return { url, request: e?.request, conform: e?.conform }
}
