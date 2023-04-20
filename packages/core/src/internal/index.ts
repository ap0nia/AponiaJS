import { toInternalRequest } from "./request"
import type { InternalResponse } from "./response"
import type { TokenSessionManager } from "../session/token"
import type { DatabaseSessionManager } from "../session/database"
import type { CredentialsProvider } from "../providers/core/credentials"
import type { EmailProvider } from "../providers/core/email"
import type { OAuthProvider } from "../providers/core/oauth"
import type { OIDCProvider } from "../providers/core/oidc"

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
export interface AuthConfig<TUser, TSession, TRefresh = undefined> {
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
      this.routes.login.set(provider.pages.login, provider)
      this.routes.callback.set(provider.pages.callback, provider)
    })
  }

  /**
   * Handle a request and return an internal response.
   * Specific implementations should convert the internal response accordingly.
   */
  async handle(request: Request): Promise<InternalResponse> {
    const internalRequest = await toInternalRequest(request)
    const { pathname } = internalRequest.url
    let internalResponse: InternalResponse = {}

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
      if (signinHandler) {
        internalResponse = await signinHandler.login(internalRequest)
        if (!internalResponse.redirect) {
          internalResponse.redirect = this.pages.loginRedirect
          internalResponse.status = 302
        }
      }

      const callbackHandler = this.routes.callback.get(pathname)
      if (callbackHandler) {
        internalResponse = await callbackHandler.callback(internalRequest)
        if (!internalResponse.redirect) {
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
  TUser, TSession, TRefresh = undefined
>(config: AuthConfig<TUser, TSession, TRefresh>) {
  return new Auth(config)
}
