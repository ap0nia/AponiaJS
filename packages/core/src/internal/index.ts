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
interface Pages {
  signOut: string
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

type AnySessionManager<TUser, TSession, TRefresh> =
  | TokenSessionManager<TUser, TSession, TRefresh>
  | DatabaseSessionManager<TUser, TSession, TRefresh>

/**
 * Configuration.
 */
export interface AuthConfig<TUser, TSession, TRefresh = undefined> {
  /**
   * Providers, each has assigned routes.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session handler.
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
      signOut: config.pages?.signOut ?? '/auth/logout',
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
    const refreshResponse = await this.session.handleRequest(internalRequest)
    const { pathname } = internalRequest.url

    switch (pathname) {
      case this.pages.signOut: {
        return await this.session.logout(internalRequest.request)
      }
    }

    let response: InternalResponse = {}

    const signinHandler = this.routes.login.get(pathname)
    if (signinHandler) {
      response = await signinHandler.login(internalRequest)
    }

    const callbackHandler = this.routes.callback.get(pathname)
    if (callbackHandler) {
      response = await callbackHandler.callback(internalRequest)
    }

    if (refreshResponse.cookies?.length) {
      response.cookies ??= []
      response.cookies.push(...refreshResponse.cookies)
    }

    return await this.session.handleResponse(response)
  }
}

export default Auth
