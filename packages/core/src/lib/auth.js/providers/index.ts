import type { Awaitable } from '$lib/utils/promise'
import type { Profile, TokenSet } from '@auth/core/types'
import type * as oauth from 'oauth4webapi'

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
  as: oauth.AuthorizationServer

  /**
   * Client to make requests.
   */
  client: oauth.Client

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
     * Process the response from the token endpoint.
     */
    conform: (response: Response) => Awaitable<Response | undefined>
  }

  /**
   * Additional data about the userinfo endpoint.
   */
  userinfo: {

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
  as: oauth.AuthorizationServer

  /**
   * Client to make requests.
   */
  client: oauth.Client

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
     * Process the response from the token endpoint.
     */
    conform: (response: Response) => Awaitable<Response | undefined>
  }

  /**
   * Additional data about the userinfo endpoint.
   */
  userinfo: {

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

/**
 * Any internally generated config.
 */
export type AnyInternalConfig = 
  | InternalOAuthConfig 
  | InternalOIDCConfig 
  | InternalEmailConfig 
  | InternalCredentialsConfig
