import type * as oauth from 'oauth4webapi'
import type { CookiesOptions, Profile, TokenSet, User } from '@auth/core/types'
import type { InternalRequest, InternalResponse } from '$lib/integrations/response'
import type { JWTOptions } from '$lib/jwt'

type Awaitable<T> = T | PromiseLike<T>

/**
 * All providers have these methods.
 */
export interface Provider<T extends AnyInternalConfig> {
  config: T

  /**
   * Handle sign-in attempt with provider.
   */
  signIn(request: InternalRequest): Awaitable<InternalResponse>

  /**
   * Follow-up after sign-in. 
   * Only OAuth providers have this method. Ignore for other providers.
   */
  callback(request: InternalRequest): Awaitable<InternalResponse>

  /**
   * Handle sign-out attempt with provider.
   */
  signOut(request: InternalRequest): Awaitable<InternalResponse>
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

export type OAuthProviderType = "oidc" | "oauth"

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
 * General interface for OAuth providers, e.g. OAuth, OIDC.
 */
export interface AnyInternalOAuthConfig<T extends OAuthProviderType = OAuthProviderType> extends ProviderConfig {
  /**
   * OAuth type.
   */
  type: T

  /**
   * OAuth Authorization Server.
   */
  authorizationServer: oauth.AuthorizationServer

  /**
   * Client to make requests.
   */
  client: oauth.Client

  /**
   * Generate cookie options.
   */
  cookies: CookiesOptions

  /**
   * Override default JWT options.
   */
  jwt: JWTOptions

  /**
   * Which OAuth checks to perform.
   */
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
 * Internally generated config for OAuth providers from Auth.js .
 */
export interface InternalOAuthConfig extends AnyInternalOAuthConfig<"oauth"> {}

/**
 * Internally generated config for OIDC providers from Auth.js .
 */
export interface InternalOIDCConfig extends AnyInternalOAuthConfig<"oidc"> {}

/**
 * Internally generated config for email authentication.
 */
export interface InternalEmailConfig extends ProviderConfig { type: 'email' }

/**
 * Internally generated config for credentials authentication.
 */
export interface InternalCredentialsConfig extends ProviderConfig { type: 'credentials' }
