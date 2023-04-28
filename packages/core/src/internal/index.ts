import { toInternalRequest } from "./request.js"
import type { InternalResponse } from "./response.js"
import type { TokenSessionManager } from "../session/token.js"
import type { DatabaseSessionManager } from "../session/database.js"
import type { CredentialsProvider } from "../providers/core/credentials.js"
import type { EmailProvider } from "../providers/core/email.js"
import type { OAuthProvider } from "../providers/core/oauth.js"
import type { OIDCProvider } from "../providers/core/oidc.js"

/**
 * Static auth pages.
 */
type Pages = {
  /**
   * Redirect URL after logging in.
   */
  loginRedirect: string

  /**
   * Redirect URL after logging out.
   */
  logoutRedirect: string

  /**
   * Logout endpoint.
   */
  logout: string

  /**
   * Utility endpoint to get session client-side.
   */
  session: string
}

/**
 * Any core provider.
 */
type AnyProvider<T> = 
  | OAuthProvider<any, T> 
  | OIDCProvider<any, T> 
  | CredentialsProvider<T> 
  | EmailProvider<T>

/**
 * Any session manager.
 */
type AnySessionManager<TUser, TSession, TRefresh> =
  | TokenSessionManager<TUser, TSession, TRefresh>
  | DatabaseSessionManager<TUser, TSession, TRefresh>

/**
 * Configuration.
 */
export interface AuthConfig<TUser, TSession = TUser, TRefresh = undefined> {
  /**
   * Providers.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session manager.
   */
  session: AnySessionManager<TUser, TSession, TRefresh>

  /**
   * Static auth pages.
   */
  pages?: Partial<Pages>
}

/**
 * Aponia Auth!
 */
export class Auth<TUser, TSession, TRefresh = undefined> {
  /**
   * Providers.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session handler.
   */
  session: AnySessionManager<TUser, TSession, TRefresh>

  /**
   * Static auth routes.
   */
  pages: Pages

  /**
   * Dynamic auth routes.
   */
  routes: {
    login: Map<string, AnyProvider<TUser>>
    callback: Map<string, AnyProvider<TUser>>
  }

  constructor(config: AuthConfig<TUser, TSession, TRefresh>) {
    this.providers = config.providers

    this.session = config.session

    this.pages = {
      loginRedirect: config.pages?.loginRedirect ?? '/',
      logoutRedirect: config.pages?.logoutRedirect ?? '/',
      logout: config.pages?.logout ?? '/auth/logout',
      session: config.pages?.session ?? '/auth/session',
    }

    this.routes = {
      login: new Map(),
      callback: new Map(),
    }

    this.providers.forEach(provider => {
      provider.setJwtOptions(this.session.jwt).setCookiesOptions(this.session.cookies)
      this.routes.login.set(provider.pages.login.route, provider)
      this.routes.callback.set(provider.pages.callback.route, provider)
    })
  }

  /**
   * Handle a request and return an internal response.
   * Specific implementations should convert the internal response accordingly.
   */
  async handle(request: Request): Promise<InternalResponse> {
    /**
     * 1. Convert request to internal request.
     */
    const internalRequest = await toInternalRequest(request)

    try {
      /**
       * 2. Generate an initial response with the session info.
       * - Any discovered `user` will be forwarded to the final response.
       */
      const sessionResponse = await this.session.handleRequest(internalRequest)

      switch (internalRequest.url.pathname) {
        case this.pages.session: {
          return sessionResponse
        }

        case this.pages.logout: {
          const response = await this.session.logout(internalRequest.request)
          if (!response.redirect) {
            response.redirect = this.pages.logoutRedirect
            response.status = 302
          }
          return response
        }
      }

      /**
       * 3. Generate a response from the provider.
       * - If a `user` is generated from a provider, then the session manager should create a new session.
       */
      let providerResponse: InternalResponse = {}

      const signinHandler = this.routes.login.get(internalRequest.url.pathname)

      if (signinHandler && signinHandler.pages.login.methods.includes(request.method)) {
        providerResponse = await signinHandler.login(internalRequest)
        if (providerResponse.user && !providerResponse.redirect) {
          providerResponse.redirect = this.pages.loginRedirect
          providerResponse.status = 302
        }
      }

      const callbackHandler = this.routes.callback.get(internalRequest.url.pathname)

      if (callbackHandler && callbackHandler.pages.callback.methods.includes(request.method)) {
        providerResponse = await callbackHandler.callback(internalRequest)
        if (providerResponse.user && !providerResponse.redirect) {
          providerResponse.redirect = this.pages.loginRedirect
          providerResponse.status = 302
        }
      }

      if (sessionResponse.cookies?.length) {
        providerResponse.cookies ??= []
        providerResponse.cookies.push(...sessionResponse.cookies)
      }

      /**
       * 4.The session handler handles the provider response.
       */
      const internalResponse = await this.session.handleResponse(providerResponse)

      /**
       * The final `user` is either from the initial session response or the handled provider response.
       */
      internalResponse.user ||= sessionResponse.user

      return internalResponse
    } catch (error) {
      return { error }
    }
  }
}

export function Aponia<
  TUser, TSession = TUser, TRefresh = undefined
>(config: AuthConfig<TUser, TSession, TRefresh>) {
  return new Auth(config)
}
