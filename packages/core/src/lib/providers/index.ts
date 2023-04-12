import type { MaybePromise } from "$lib/utils/promise"

export const STATE_COOKIE_NAME = 'aponia-state'

/**
 * @see [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3)
 * @see [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
 * @see [Email or Passwordless Authentication](https://authjs.dev/concepts/oauth)
 * @see [Credentials-based Authentication](https://authjs.dev/concepts/credentials)
 */
export type ProviderType = "oidc" | "oauth" | "email" | "credentials"

/**
 * @see [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3)
 */
export type Provider<T> = {
  /**
   * An identifier for this provider.
   */
  id: string,

  /**
   * The type of authentication flow this provider uses.
   */
  type: ProviderType,

  /**
   * The URL to the provider's authorization endpoint.
   */
  issuer?: string,

  /**
   * 1. Get the provider's authorization endpoint and state cookie to start the OAuth flow.
   * If credentials provider or similar, use redirect status 307 to preserve the request.
   */
  getAuthorizationUrl: () => Readonly<[string, string]>

  /**
   * The tokens can be stored and revoked later.
   */
  logout: (token: string) => Promise<boolean>

  /**
   * 1. Get the provider's authorization endpoint and state cookie to start the OAuth flow.
   * 2. After authorizing and being redirected, exchange the authorization code for tokens.
   * 3. Use the access token to get the user's profile.
   */
  authenticateRequest: (req: Request) => Promise<T>

  /**
   * Allowed method.
   */
  _authenticateRequestMethod: string
}

/**
 * Base provider configuration.
 */
export interface ProviderConfig<T extends Record<string, any> = {}> {
  onLogin?: (user: any) => MaybePromise<T>
  onLogout?: (user: any) => MaybePromise<void>
}

/**
 * Base configuration for OAuth providers.
 */
export interface OAuthConfig<T extends Record<string, any> = {}> extends ProviderConfig<T> {
  clientId: string;
  clientSecret: string;
  scope?: string[];
};

