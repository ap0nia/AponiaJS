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
export type Provider = {
  id: string,

  type: ProviderType,

  login: (...args: any) => MaybePromise<any>

  logout: (...args: any) => MaybePromise<any>

  handleLogin: (request: Request) => MaybePromise<any>

  handleLogout: (request: Request) => MaybePromise<any>
}

/**
 * Base provider configuration.
 */
export interface ProviderConfig<T extends Record<string, any> = {}> {
  onLogin?: (...args: any) => MaybePromise<T | null>
  onLogout?: (...args: any) => MaybePromise<void>
}

