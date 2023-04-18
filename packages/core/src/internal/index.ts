import { CredentialsProvider } from "../providers/credentials"
import { EmailProvider } from "../providers/email"
import { toInternalRequest } from "./request"
import type { InternalResponse } from "./response"
import type { SessionManager } from "../session"
import type { OAuthProvider } from "../providers/oauth"
import type { OIDCProvider } from "../providers/oidc"

/**
 * Designated auth pages.
 */
interface Pages {
  signIn: string
  signOut: string
  callback: string
  session: string
}

type AnyProvider = 
  | OAuthProvider<any> 
  | OIDCProvider<any> 
  | CredentialsProvider<any> 
  | EmailProvider<any>

/**
 * Configuration.
 */
export interface AuthConfig {
  /**
   * List of providers.
   */
  providers: AnyProvider[]

  /**
   * Session.
   */
  session: SessionManager

  /**
   * Designated auth pages.
   */
  pages?: Partial<Pages>
}

/**
 * Aponia Auth!
 */
export class Auth {
  /**
   * List of providers.
   */
  providers: AnyProvider[]

  /**
   * Session manager.
   */
  session: SessionManager

  /**
   * Designated auth pages.
   */
  pages: Pages

  /**
   * Routes. Generate internal response on match.
   */
  routes: {
    signin: Map<string, AnyProvider>
    signout: Map<string, AnyProvider>
    callback: Map<string, AnyProvider>
  }

  constructor(config: AuthConfig) {
    this.providers = config.providers

    this.session = config.session

    this.pages = {
      signIn: config.pages?.signIn ?? '/auth/login',
      signOut: config.pages?.signOut ?? '/auth/logout',
      callback: config.pages?.callback ?? '/auth/callback',
      session: config.pages?.session ?? '/auth/session',
    }

    this.routes = {
      signin: new Map(),
      signout: new Map(),
      callback: new Map(),
    }

    this.providers.forEach(provider => {
      provider
        .setJWTOptions(this.session.jwt)
        .setCookiesOptions(this.session.cookies)
        .setPages(this.pages)

      this.routes.signin.set(provider.pages.signIn, provider)
      this.routes.signout.set(provider.pages.signOut, provider)
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
    }

    let response: InternalResponse = {}

    const signinHandler = this.routes.signin.get(pathname)
    if (signinHandler) {
      response = await signinHandler.signIn(internalRequest)
    }

    const signoutHandler = this.routes.signout.get(pathname)
    if (signoutHandler) {
      if (internalRequest.session) {
        await this.session.invalidateSession(internalRequest.session)
      }
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
