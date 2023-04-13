import type { MaybePromise } from "$lib/utils/promise"
import type { Provider, ProviderConfig } from ".."

/**
 * @see [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3)
 */
export interface OAuthProvider<T> extends Provider {
  /**
   * The URL to the provider's authorization endpoint.
   */
  issuer?: string,

  /**
   * 1. Get the provider's authorization endpoint and state cookie to start the OAuth flow.
   * If credentials provider or similar, use redirect status 307 to preserve the request.
   */
  login: () => MaybePromise<Readonly<[string, string]>>

  /**
   * The tokens can be stored and revoked later.
   */
  logout: (token: string) => MaybePromise<boolean>

  /**
   * 1. Get the provider's authorization endpoint and state cookie to start the OAuth flow.
   * 2. After authorizing and being redirected, exchange the authorization code for tokens.
   * 3. Use the access token to get the user's profile.
   */
  callback: (req: Request) => MaybePromise<T>
}

/**
 * Base configuration for OAuth providers.
 */
export interface OAuthConfig<T extends Record<string, any> = {}> extends ProviderConfig<T> {
  clientId: string;
  clientSecret: string;
  scope?: string[];
};

