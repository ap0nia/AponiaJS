import { toInternalRequest } from "./request"
import type { InternalResponse } from "./response"
import type { TokenSessionManager } from "../session/token"
import type { CredentialsProvider } from "../providers/core/credentials"
import type { EmailProvider } from "../providers/core/email"
import type { OAuthProvider } from "../providers/core/oauth"
import type { OIDCProvider } from "../providers/core/oidc"

/**
 * Designated static auth pages.
 */
interface Pages {
  signOut: string
  session: string
}

type AnyProvider<T> = 
  | OAuthProvider<any, T> 
  | OIDCProvider<any, T> 
  | CredentialsProvider<T> 
  | EmailProvider<T>

/**
 * Configuration.
 */
export interface AuthConfig<TUser, TSession, TRefresh = undefined> {
  /**
   * List of providers.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session.
   */
  session: TokenSessionManager<TUser, TSession, TRefresh>

  /**
   * Designated auth pages.
   */
  pages?: Partial<Pages>
}

/**
 * Aponia Auth!
 */
export class Auth<TUser, TSession, TRefresh = undefined> {
  /**
   * List of providers.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session manager.
   */
  session: TokenSessionManager<TUser, TSession, TRefresh>

  /**
   * Static auth pages not associated with any provider.
   */
  pages: Pages

  /**
   * Routes. Generate internal response on match.
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
    const refreshResponse = await this.session.handleRefresh(internalRequest)
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
      response.cookies.concat(refreshResponse.cookies)
    }

    return response
  }
}

export default Auth
