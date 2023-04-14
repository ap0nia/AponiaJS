import type * as oauth from 'oauth4webapi'
import type { CookiesOptions, TokenSet, User } from '@auth/core/types'
import * as checks from '$lib/integrations/check'
import type { Cookie, InternalRequest, InternalResponse } from '$lib/integrations/response'
import type { Awaitable } from '$lib/utils/promise'
import type { JWTOptions } from '$lib/jwt'

export interface Provider<T extends AnyInternalConfig> {
  config: T

  signIn(request: InternalRequest): Promise<InternalResponse>

  callback(request: InternalRequest): Promise<InternalResponse>

  signOut(request: InternalRequest): Promise<InternalResponse>
}

/**
 * Common procedure for getting authorization URL for OAuth and OIDC providers.
 */
export async function handleOAuthUrl(
  request: InternalRequest,
  provider: InternalOAuthConfig | InternalOIDCConfig
) {
  const cookies: Cookie[] = []
  const { url } = provider.authorization

  if (provider.checks?.includes('state')) {
    const [state, stateCookie] = await checks.state.create(provider)
    url.searchParams.set('state', state)
    cookies.push(stateCookie)
  }

  if (provider.checks?.includes('pkce')) {
    if (provider.authorizationServer.code_challenge_methods_supported?.includes('S256')) {
      provider.checks = ['nonce']
    } else {
      const [pkce, pkceCookie] = await checks.pkce.create(provider)
      url.searchParams.set('code_challenge', pkce)
      url.searchParams.set('code_challenge_method', 'S256')
      cookies.push(pkceCookie)
    }
  }

  if (provider.checks?.includes('nonce')) {
    const [nonce, nonceCookie] = await checks.nonce.create(provider)
    url.searchParams.set('nonce', nonce)
    cookies.push(nonceCookie)
  }

  if (!url.searchParams.has('redirect_uri')) {
    url.searchParams.set('redirect_uri', `${request.url.origin}/callback/${provider.id}`)
  }

  if (provider.type === 'oidc' && !url.searchParams.has('scope')) {
    url.searchParams.set("scope", "openid profile email")
  }

  return { redirect: url.toString(), cookies }
}

/** 
 * The OAuth profile returned from your provider
 */
export interface Profile {
  sub?: string | null
  name?: string | null
  email?: string | null
  image?: string | null
}

/**
 * Providers passed to Auth.js must define one of these types.
 *
 * @see [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3)
 * @see [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
 * @see [Email or Passwordless Authentication](https://authjs.dev/concepts/oauth)
 * @see [Credentials-based Authentication](https://authjs.dev/concepts/credentials)
 */
export type ProviderType = "oidc" | "oauth" | "email" | "credentials"

/**
 * Any internally generated OAuth-based config.
 */
export type AnyInternalOAuthConfig = InternalOAuthConfig | InternalOIDCConfig

/**
 * Any internally generated config.
 */
export type AnyInternalConfig = 
  | InternalOAuthConfig 
  | InternalOIDCConfig 
  | InternalEmailConfig 
  | InternalCredentialsConfig


/**
 * Required config options for all providers.
 */
interface ProviderConfig {
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
 * Internally generated config for OAuth providers from Auth.js .
 */
export interface InternalOAuthConfig extends ProviderConfig {
  type: 'oauth'

  /**
   * OAuth Authorization Server.
   */
  authorizationServer: oauth.AuthorizationServer

  /**
   * Client to make requests.
   */
  client: oauth.Client

  cookies: CookiesOptions

  jwt: JWTOptions

  checks: Array<"pkce" | "state" | "none" | "nonce">

  /**
   * Receives the profile object returned by the OAuth provider, and returns a user object.
   */
  profile: (profile: Profile, tokens: TokenSet) => Awaitable<User>

  /**
   * Additional data about the authorization endpoint.
   */
  authorization: { 

    /**
     * Full URL to authorization endpoint with search params.
     */
    url: URL
  }

  /**
   * Additional data about the token endpoint.
   */
  token: {

    /**
     * Full URL to token endpoint.
     */
    url: URL

    /**
     * Process the response from the token endpoint.
     */
    conform: (response: Response) => Awaitable<Response>
  }

  /**
   * Additional data about the userinfo endpoint.
   */
  userinfo: {

    /**
     * Full URL to userinfo endpoint.
     */
    url: URL

    /**
     * Make a request to the userinfo endpoint.
     */
    request: (
      context: { tokens: TokenSet, provider: InternalOAuthConfig | InternalOIDCConfig }
    ) => Awaitable<Profile>
  }
}

/**
 * Internally generated config for OIDC providers from Auth.js .
 */
export interface InternalOIDCConfig extends ProviderConfig {
  type: 'oidc'

  /**
   * OAuth Authorization Server.
   */
  authorizationServer: oauth.AuthorizationServer

  /**
   * Client to make requests.
   */
  client: oauth.Client

  checks: Array<"pkce" | "state" | "none" | "nonce">

  cookies: CookiesOptions

  jwt: JWTOptions

  /**
   * Receives the profile object returned by the OAuth provider, and returns a user object.
   */
  profile: (profile: Profile, tokens: TokenSet) => Awaitable<User>

  /**
   * Additional data about the authorization endpoint.
   */
  authorization: { 

    /**
     * Full URL to authorization endpoint with search params.
     */
    url: URL
  }

  /**
   * Additional data about the token endpoint.
   */
  token: {

    /**
     * Full URL to token endpoint.
     */
    url: URL

    /**
     * Process the response from the token endpoint.
     */
    conform: (response: Response) => Awaitable<Response>
  }

  /**
   * Additional data about the userinfo endpoint.
   */
  userinfo: {

    /**
     * Full URL to userinfo endpoint.
     */
    url: URL

    /**
     * Make a request to the userinfo endpoint.
     */
    request: (
      context: { tokens: TokenSet, provider: InternalOAuthConfig | InternalOIDCConfig }
    ) => Awaitable<Profile>
  }
}

/**
 * Internally generated config for email authentication.
 */
export interface InternalEmailConfig extends ProviderConfig {
  type: 'email'
}

/**
 * Internally generated config for credentials authentication.
 */
export interface InternalCredentialsConfig extends ProviderConfig {
  type: 'credentials'
}

