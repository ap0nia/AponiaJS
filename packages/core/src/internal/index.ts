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
    const internalRequest = await toInternalRequest(request)

    const { pathname } = internalRequest.url

    let internalResponse: InternalResponse = {
      user: this.session.getUser(internalRequest.request),
    }

    try {
      const refreshResponse = await this.session.handleRequest(internalRequest)

      switch (pathname) {
        case this.pages.session: {
          const response = { body: await this.session.getUser(internalRequest.request) }
          return response
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


      const signinHandler = this.routes.login.get(pathname)

      if (signinHandler && signinHandler.pages.login.methods.includes(request.method)) {
        internalResponse = await signinHandler.login(internalRequest)
        if (internalResponse.user && !internalResponse.redirect) {
          internalResponse.redirect = this.pages.loginRedirect
          internalResponse.status = 302
        }
      }

      const callbackHandler = this.routes.callback.get(pathname)

      if (callbackHandler && callbackHandler.pages.callback.methods.includes(request.method)) {
        internalResponse = await callbackHandler.callback(internalRequest)
        if (internalResponse.user && !internalResponse.redirect) {
          internalResponse.redirect = this.pages.loginRedirect
          internalResponse.status = 302
        }
      }

      if (refreshResponse.cookies?.length) {
        internalResponse.cookies ??= []
        internalResponse.cookies.push(...refreshResponse.cookies)
      }

      return await this.session.handleResponse(internalResponse)
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
