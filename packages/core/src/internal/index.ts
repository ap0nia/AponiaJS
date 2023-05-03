import { toInternalRequest } from "./request.js"
import type { InternalResponse } from "./response.js"
import type { SessionManager } from "../session/index.js"
import type { CredentialsProvider } from "../providers/core/credentials.js"
import type { EmailProvider } from "../providers/core/email.js"
import type { OAuthProvider } from "../providers/core/oauth.js"
import type { OIDCProvider } from "../providers/core/oidc.js"

/**
 * Static auth pages not associated with providers.
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
   * Endpoint to get session.
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
  session: SessionManager<TUser, TSession, TRefresh>

  /**
   * Static auth pages.
   */
  pages?: Partial<Pages>
}

/**
 * Aponia `Auth` class.
 */
export class Auth<TUser, TSession, TRefresh = undefined> {
  /**
   * Providers.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session manager.
   */
  session: SessionManager<TUser, TSession, TRefresh>

  /**
   * Static auth routes handled by Aponia.
   */
  pages: Pages

  /**
   * Dynamic auth routes handled by providers.
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

    /**
     * Each provider has internal routes for login and callback that can be overridden.
     * Use that info to register the provider into the route maps.
     */
    this.providers.forEach(provider => {
      /**
       * All providers will inherit JWT and cookie options from the session manager.
       * When used standalone, they can be defined in the provider config directly.
       */
      provider
        .setJwtOptions(this.session.jwt)
        .setCookiesOptions(this.session.cookies)

      this.routes.login.set(provider.pages.login.route, provider)
      this.routes.callback.set(provider.pages.callback.route, provider)
    })
  }

  /**
   * Handle a `Request` and return an `InternalResponse`.
   * Specific usages and framework integrations should handle the `InternalResponse` accordingly.
   */
  async handle(request: Request): Promise<InternalResponse> {
    /**
     * 1. Convert `Request` to an `InternalRequest`.
     */
    const internalRequest = await toInternalRequest(request)

    try {
      /**
       * 2. Generate an initial `InternalResponse` with the session info.
       * The `user` property will be defined if they're already logged in.
       * `cookies` may be defined if a new session was created.
       */
      const sessionResponse = await this.session.handleRequest(internalRequest)

      /**
       * 3.1 Aponia handles requests for static auth pages.
       */
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
       * 3.2 A provider handles the request.
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

      /**
       * 4. If the provider response has a defined `user`, i.e. they just logged in, then create a new session.
       */
      if (providerResponse.user) {
        const sessionTokens = await this.session.createSession(providerResponse.user)
        if (sessionTokens) {
          const sessionCookies = await this.session.createCookies(sessionTokens)
          providerResponse.cookies ??= []
          providerResponse.cookies.push(...sessionCookies)
        }
      }

      if (sessionResponse.cookies?.length) {
        providerResponse.cookies ??= []
        providerResponse.cookies.push(...sessionResponse.cookies)
      }

      /**
       * The final response has a defined `user` from the initial session response or the provider response.
       */
      providerResponse.user ||= sessionResponse.user

      return providerResponse
    } catch (error) {
      return { error }
    }
  }
}

/**
 * Create a new Aponia `Auth` instance.
 */
export function AponiaAuth<TUser, TSession = TUser, TRefresh = undefined>(
  config: AuthConfig<TUser, TSession, TRefresh>
) {
  return new Auth(config)
}
