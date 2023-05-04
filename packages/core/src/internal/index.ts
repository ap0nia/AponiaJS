import { toInternalRequest } from "./request.js"
import type { InternalRequest } from "./request.js"
import type { InternalResponse } from "./response.js"
import type { SessionManager } from "../session.js"
import type { CredentialsProvider } from "../providers/core/credentials.js"
import type { EmailProvider } from "../providers/core/email.js"
import type { OAuthProvider } from "../providers/core/oauth.js"
import type { OIDCProvider } from "../providers/core/oidc.js"

/**
 * Any core provider.
 */
type AnyProvider<T> = 
  | OAuthProvider<any, T> 
  | OIDCProvider<any, T> 
  | CredentialsProvider<T> 
  | EmailProvider<T>

/**
 * Static auth pages not associated with providers.
 */
interface Pages {
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
    const internalRequest = await toInternalRequest(request)

    const internalResponse = await this
      .generateInternalResponse(internalRequest)
      .catch(error => ({ error }))

    return internalResponse
  }

  async generateInternalResponse(internalRequest: InternalRequest): Promise<InternalResponse> {
    const { url, request } = internalRequest

    /**
     * 1. Generate an initial `InternalResponse` with the session info.
     * `user` will be defined if already logged in.
     * `cookies` will be defined if a new session was created.
     */
    const sessionResponse = await this.session.handleRequest(internalRequest)

    /**
     * 2.1 Aponia handles requests for static auth pages.
     */
    switch (url.pathname) {
      case this.pages.session: 
        return sessionResponse

      case this.pages.logout: 
        return this.session.logout(request)
    }

    const loginHandler = this.routes.login.get(url.pathname)
    const callbackHandler = this.routes.callback.get(url.pathname)

    const providerHandler = loginHandler && loginHandler.pages.login.methods.includes(request.method)
      ? loginHandler.login 
      : callbackHandler && callbackHandler.pages.callback.methods.includes(request.method)
      ? callbackHandler.callback
      : undefined

    /**
     * 2.2 A provider handles the request.
     */
    const providerResponse = await providerHandler?.(internalRequest) ?? {}

    /**
     * 3. If the provider response has a defined `user`, i.e. they just logged in, then create a new session.
     * If the session manager __doesn't__ create a session, then `user` will be unset.
     */
    if (providerResponse.user) {
      const sessionTokens = await this.session.createSession(providerResponse.user)
      providerResponse.user = sessionTokens?.user
      if (sessionTokens) {
        providerResponse.cookies ??= []
        providerResponse.cookies.push(...await this.session.createCookies(sessionTokens))
      }
    }

    const cookies = sessionResponse.cookies ?? []
    if (providerResponse.cookies) cookies.push(...providerResponse.cookies)

    const internalResponse = { 
      ...sessionResponse,
      ...providerResponse,
      cookies, 

      /** The final response's `user` can be from the initial session response or the provider response. */
      user: providerResponse.user || sessionResponse.user
    }

    return internalResponse
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
