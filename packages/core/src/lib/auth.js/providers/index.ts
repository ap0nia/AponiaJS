import type { Client, OAuth2TokenEndpointResponse, OpenIDTokenEndpointResponse } from "oauth4webapi"

/**
 * Different tokens returned by OAuth Providers.
 * Some of them are available with different casing,
 * but they refer to the same value.
 */
export type TokenSet = Partial<OAuth2TokenEndpointResponse | OpenIDTokenEndpointResponse>


/** The OAuth profile returned from your provider */
export interface Profile {
  sub?: string | null
  name?: string | null
  email?: string | null
  image?: string | null
}

export interface User {
  id: string
  name?: string | null
  email?: string | null
  image?: string | null
}

export type Awaitable<T> = T | PromiseLike<T>

export type ProviderType = "oidc" | "oauth" | "email" | "credentials"

export interface CommonProviderOptions {
  id: string
  name: string
  type: ProviderType
}

// TODO:
type AuthorizationParameters = any
type CallbackParamsType = any
type IssuerMetadata = any
type OAuthCallbackChecks = any
type OpenIDCallbackChecks = any

type OAuthChecks = OpenIDCallbackChecks | OAuthCallbackChecks

type PartialIssuer = Partial<Pick<IssuerMetadata, "jwks_endpoint" | "issuer">>

type UrlParams = Record<string, unknown>

type EndpointRequest<C, R, P> = (
  context: C & {
    provider: OAuthConfigInternal<P> & {
      signinUrl: string
      callbackUrl: string
    }
  }
) => Awaitable<R>

/** 
 * Gives granular control of the request to the given endpoint
 */
interface AdvancedEndpointHandler<P extends UrlParams, C, R> {
  /** 
   * Endpoint URL. Can contain parameters. Optionally, you can use `params`
   */
  url?: string

  /** 
   * These will be prepended to the `url`
   */
  params?: P

  /**
   * Control the corresponding OAuth endpoint request completely.
   * Useful if your provider relies on some custom behaviour
   * or it diverges from the OAuth spec.
   *
   * - ⚠ **This is an advanced option.**
   * You should **try to avoid using advanced options** unless you are very comfortable using them.
   */
  request?: EndpointRequest<C, R, P>

  /** 
   * @internal
   */
  conform?: (response: Response) => Awaitable<Response | undefined>
}

/** 
 * Either an URL (containing all the parameters) or an object with more granular control.
 */
export type EndpointHandler<P extends UrlParams, C = any, R = any> = AdvancedEndpointHandler<P, C, R>

export type AuthorizationEndpointHandler = EndpointHandler<AuthorizationParameters>

export type TokenEndpointHandler = EndpointHandler<
  UrlParams,
  {
    /**
     * Parameters extracted from the request to the `/api/auth/callback/:providerId` endpoint.
     * Contains params like `state`.
     */
    params: CallbackParamsType

    /**
     * When using this custom flow, make sure to do all the necessary security checks.
     * This object contains parameters you have to match against the request to make sure it is valid.
     */
    checks: OAuthChecks
  },
  {
    tokens: TokenSet
  }
>

export type Check = 'pkce' | 'state' | 'none' | 'nonce'

export interface OAuthProviderButtonStyles {
  logo: string
  logoDark: string
  bg: string
  bgDark: string
  text: string
  textDark: string
}

export type UserinfoEndpointHandler = EndpointHandler<UrlParams, { tokens: TokenSet }, Profile>

/** 
 * TODO:
 */
export interface OAuth2Config<Profile> extends CommonProviderOptions, PartialIssuer {
  /**
   * Identifies the provider when you want to sign in to
   * a specific provider.
   *
   * @example
   * ```ts
   * signIn('github') // "github" is the provider ID
   * ```
   */
  id: string

  /** The name of the provider. shown on the default sign in page. */
  name: string

  /**
   * OpenID Connect (OIDC) compliant providers can configure
   * this instead of `authorize`/`token`/`userinfo` options
   * without further configuration needed in most cases.
   * You can still use the `authorize`/`token`/`userinfo`
   * options for advanced control.
   *
   * [Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414#section-3)
   */
  wellKnown?: string

  issuer?: string

  /**
   * The login process will be initiated by sending the user to this URL.
   *
   * [Authorization endpoint](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1)
   */
  authorization?: string | AuthorizationEndpointHandler

  token?: string | TokenEndpointHandler

  userinfo?: string | UserinfoEndpointHandler

  type: "oauth"

  /**
   * Receives the profile object returned by the OAuth provider, and returns the user object.
   * This will be used to create the user in the database.
   * Defaults to: `id`, `email`, `name`, `image`
   *
   * [Documentation](https://authjs.dev/reference/adapters/models#user)
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
  checks?: Check[]

  clientId?: string

  clientSecret?: string

  /**
   * Pass overrides to the underlying OAuth library.
   * See [`oauth4webapi` client](https://github.com/panva/oauth4webapi/blob/main/docs/interfaces/Client.md) for details.
   */
  client?: Partial<Client>

  style?: OAuthProviderButtonStyles

  /**
   * [Documentation](https://authjs.dev/reference/providers/oauth#allowdangerousemailaccountlinking-option)
   */
  allowDangerousEmailAccountLinking?: boolean

  /**
   * The options provided by the user.
   * We will perform a deep-merge of these values
   * with the default configuration.
   *
   * @internal
   */
  options?: OAuthUserConfig<Profile>
}

/** 
 * TODO:
 */
export interface OIDCConfig<Profile> extends Omit<OAuth2Config<Profile>, "type"> {
  type: "oidc"
}

export type OAuthConfig<Profile> = OIDCConfig<Profile> | OAuth2Config<Profile>

export type OAuthEndpointType = "authorization" | "token" | "userinfo"

/**
 * We parsed `authorization`, `token` and `userinfo`
 * to always contain a valid `URL`, with the params
 */
export type OAuthConfigInternal<Profile> = Omit<OAuthConfig<Profile>, OAuthEndpointType> & {
  authorization?: { url: URL }
  token?: {
    url: URL
    request?: TokenEndpointHandler["request"]
    /** @internal */
    conform?: TokenEndpointHandler["conform"]
  }
  userinfo?: { url: URL; request?: UserinfoEndpointHandler["request"] }
} & Pick<Required<OAuthConfig<Profile>>, "clientId" | "checks" | "profile">

export type OAuthUserConfig<Profile> = 
  Omit<Partial<OAuthConfig<Profile>>, "options" | "type"> &
  Required<Pick<OAuthConfig<Profile>, "clientId" | "clientSecret">>

export type OIDCUserConfig<Profile> =
  Omit<Partial<OIDCConfig<Profile>>, "options" | "type"> &
  Required<Pick<OIDCConfig<Profile>, "clientId" | "clientSecret">>


interface InternalProviderOptions {
  /** Used to deep merge user-provided config with the default config
   */
  options?: Record<string, unknown>
}


/**
 * Must be a supported authentication provider config:
 * - {@link OAuthConfig}
 * - {@link EmailConfigInternal}
 * - {@link CredentialsConfigInternal}
 *
 * For more information, see the guides:
 *
 * @see [OAuth/OIDC guide](https://authjs.dev/guides/providers/custom-provider)
 * @see [Email (Passwordless) guide](https://authjs.dev/guides/providers/email)
 * @see [Credentials guide](https://authjs.dev/guides/providers/credentials)
 */
export type Provider<P extends Profile = Profile> = (
  | ((OIDCConfig<P> | OAuth2Config<P> ) & InternalProviderOptions)
  | (( ...args: any) => (OAuth2Config<P> | OIDCConfig<P> ) & InternalProviderOptions)
) & InternalProviderOptions

let x: Provider[] = []

x.map(p => typeof p === "function" ? p() : p)

interface ParseProvidersParams {
  providers: Provider[]
  url: URL
}

/**
 * Adds `signinUrl` and `callbackUrl` to each provider
 * and deep merge user-defined options.
 */
export default function parseProviders(params: ParseProvidersParams): InternalProvider[] {
  const { url } = params

  const providers: InternalProvider[] = params.providers.map((providerConfig) => {
    const provider = typeof providerConfig === "function" ? providerConfig() : providerConfig

    const { options: userOptions, ...defaults } = provider

    const id = (userOptions?.id ?? defaults.id) as string

    const merged = merge(defaults, userOptions, {
      signinUrl: `${url}/signin/${id}`,
      callbackUrl: `${url}/callback/${id}`,
    })

    return provider.type === "oauth" || provider.type === "oidc" ? normalizeOAuth(merged) : merged
  })

  return providers
}


/** @internal */
export type InternalProvider<T = ProviderType> = (T extends "oauth"
  ? OAuthConfigInternal<any>
  // : T extends "email"
  // ? EmailConfig
  // : T extends "credentials"
  // ? CredentialsConfig
  : never) & {
  signinUrl: string
  callbackUrl: string
}

export type MergedConfig = (OIDCConfig<any> | OAuth2Config<any>) & InternalProviderOptions

/** 
 * TODO: Also add discovery here, if some endpoints/config are missing.
 * We should return both a client and authorization server config.
 */
function normalizeOAuth(c: MergedConfig): OAuthConfigInternal<any> {
  const authorization = normalizeEndpoint(c.authorization, c.issuer)

  const wellKnown = c.issuer 
    ? c.wellKnown ?? `${c.issuer}/.well-known/openid-configuration`
    : c.wellKnown

  if (authorization && !authorization.url?.searchParams.has("scope")) {
    authorization.url.searchParams.set("scope", "openid profile email")
  }

  const token = normalizeEndpoint<'token'>(c.token, c.issuer)

  const userinfo = normalizeEndpoint<'userinfo'>(c.userinfo, c.issuer)

  return {
    ...c,
    clientId: c.clientId ?? '',
    wellKnown,
    authorization,
    token,
    checks: c.checks ?? ["pkce"],
    userinfo,
    profile: c.profile ?? defaultProfile,
  }
}

function defaultProfile(profile: any) {
  return {
    id: profile.sub ?? profile.id,
    name: profile.name ?? profile.nickname ?? profile.preferred_username ?? null,
    email: profile.email ?? null,
    image: profile.picture ?? null,
  }
}
function normalizeEndpoint<T extends OAuthEndpointType>(
  e?: OAuthConfig<any>[T],
  issuer?: string
): OAuthConfigInternal<any>[T] {
  if (!e && issuer) return

  if (typeof e === "string") {
    return { url: new URL(e) }
  }

  /**
   * If e.url is undefined, it's because the provider config assumes that we will use the issuer endpoint.
   *
   * The existence of either e.url or provider.issuer is checked in assert.ts.
   * We fallback to "https://authjs.dev" to be able to pass around
   * a valid URL even if the user only provided params.
   *
   * NOTE: This need to be checked when constructing the URL 
   * for the authorization, token and userinfo endpoints.
   */
  const url = new URL(e?.url ?? "https://authjs.dev")

  if (e?.params != null) {
    Object.entries(e.params).forEach(([key, value]) => {
      url.searchParams.set(key, key === 'claims' ? JSON.stringify(value) : String(value))
    })
  }
  return { url, request: e?.request, conform: e?.conform } as OAuthConfigInternal<any>[T]
}

/** 
 * Simple object check
 */
function isObject(item: any): boolean {
  return item && typeof item === "object" && !Array.isArray(item)
}

/** 
 * Deep merge two objects
 * Source: https://stackoverflow.com/a/34749873/5364135
 */
export function merge(target: any, ...sources: any[]): any {
  if (!sources.length) return target
  const source = sources.shift()

  if (isObject(target) && isObject(source)) {
    for (const key in source) {
      if (isObject(source[key])) {
        if (!target[key]) Object.assign(target, { [key]: {} })
        merge(target[key], source[key])
      } else {
        Object.assign(target, { [key]: source[key] })
      }
    }
  }

  return merge(target, ...sources)
}
