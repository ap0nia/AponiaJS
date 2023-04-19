import { toInternalRequest } from "./request"
import type { InternalResponse } from "./response"
import type { SessionManager } from "../session"
import type { CredentialsProvider } from "../providers/core/credentials"
import type { EmailProvider } from "../providers/core/email"
import type { OAuthProvider } from "../providers/core/oauth"
import type { OIDCProvider } from "../providers/core/oidc"

/**
 * Designated auth pages.
 */
interface Pages {
  signOut: string
  session: string
}

type AnyProvider<TUser, TSession> = 
  | OAuthProvider<any, TUser, TSession> 
  | OIDCProvider<any, TUser, TSession> 
  | CredentialsProvider<TUser, TSession> 
  | EmailProvider<TUser, TSession>

/**
 * Configuration.
 */
export interface AuthConfig<TUser, TSession> {
  /**
   * List of providers.
   */
  providers: AnyProvider<TUser, TSession>[]

  /**
   * Session.
   */
  session: SessionManager<TUser, TSession>

  /**
   * Designated auth pages.
   */
  pages?: Partial<Pages>
}

/**
 * Aponia Auth!
 */
export class Auth<TUser, TSession> {
  /**
   * List of providers.
   */
  providers: AnyProvider<TUser, TSession>[]

  /**
   * Session manager.
   */
  session: SessionManager<TUser, TSession>

  /**
   * Static auth pages not associated with any provider.
   */
  pages: Pages

  /**
   * Routes. Generate internal response on match.
   */
  routes: {
    login: Map<string, AnyProvider<TUser, TSession>>
    callback: Map<string, AnyProvider<TUser, TSession>>
  }

  constructor(config: AuthConfig<TUser, TSession>) {
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
      provider
        .setJwtOptions(this.session.jwt)
        .setCookiesOptions(this.session.cookies)

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

    const userSession = await this.session.getRequestSession(internalRequest)
    internalRequest.session = userSession?.session
    internalRequest.user = userSession?.user

    const { pathname } = internalRequest.url

    switch (pathname) {
      case this.pages.session: {
        return { body: internalRequest.session }
      }

      case this.pages.signOut: {
        return await this.session.invalidateSession(internalRequest.session)
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

    if (response.session) {
      response.cookies ??= []
      response.cookies.push(await this.session.createSessionCookie(response.session))
      response.user ??= await this.session.getUserFromSession(response.session)
    }

    response.session ??= internalRequest.session
    response.user ??= internalRequest.user

    if (pathname.startsWith(this.pages.signOut)) {
      response = { ...response, ...await this.session.invalidateSession(internalRequest) }
    }

    return response
  }
}

export default Auth
