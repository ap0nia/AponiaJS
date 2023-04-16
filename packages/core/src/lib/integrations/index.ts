import { decode } from "../security/jwt"
import type { JWTOptions } from "../security/jwt"
// import { CredentialsProvider } from "../providers/credentials"
// import { EmailProvider } from "../providers/email"
import { SessionManager } from "../session"
import { toInternalRequest } from "./request"
import type { InternalResponse } from "./response"
import type { OAuthProvider } from "../providers/oauth"
import type { OIDCProvider } from "../providers/oidc"

/**
 * Designated auth pages.
 */
interface Pages {
  // suffixed with provider ID
  signIn: string
  signOut: string
  callback: string

  // static
  session: string
}

type AnyProvider = OAuthProvider<any> | OIDCProvider<any>

/**
 * Configuration.
 */
export interface AuthConfig {
  /**
   * Secret used for JWT signing.
   */
  secret: string

  /**
   * List of providers.
   */
  providers?: AnyProvider[]

  /**
   * Additional JWT options.
   */
  jwt?: Partial<Omit<JWTOptions, 'secret'>>

  /**
   * Whether to use secure cookies.
   */
  useSecureCookies?: boolean

  /**
   * Designated auth pages.
   */
  pages?: Partial<Pages>
}

/**
 * Aponia Auth!
 */
export class AponiaAuth {
  /**
   * Whether the auth instance has been fully initialized.
   */
  initialized?: boolean

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
    this.providers = config.providers ?? []

    this.session = new SessionManager({ secret: config.secret, jwt: config.jwt })

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
      provider.setJWTOptions(this.session.jwt)
      provider.setCookiesOptions(this.session.cookies)
      provider.setPagePrefixes(this.pages)

      this.routes.signin.set(provider.pages.signIn, provider)
      this.routes.signout.set(provider.pages.signOut, provider)
      this.routes.callback.set(provider.pages.callback, provider)
    })
  }

  /**
   * Asynchronously initialize all providers.
   * OAuth providers may need to fetch their configuration via discovery endpoints (OIDC).
   */
  async initialize() {
    if (this.initialized) return
    await Promise.all(this.providers.map(async (provider) => provider.initialize()))
    this.initialized = true
  }

  /**
   * Handle a request and return an internal response.
   * Specific implementations should convert the internal response accordingly.
   */
  async handle(request: Request): Promise<InternalResponse> {
    if (!this.initialized) await this.initialize()

    const internalRequest = await toInternalRequest(request)

    const requestSession = await this.session.getRequestSession(request)
    internalRequest.session = requestSession?.session
    internalRequest.user = requestSession?.user

    const { pathname } = internalRequest.url

    switch (pathname) {
      case this.pages.session: {
        const sessionToken = internalRequest.cookies[this.session.cookies.sessionToken.name]
        const body = await decode({ secret: this.session.jwt.secret, token: sessionToken })
        return { body }
      }
    }

    const signinHandler = this.routes.signin.get(pathname)
    if (signinHandler) {
      const response = await signinHandler.signIn(internalRequest)
      return response
    }

    const signoutHandler = this.routes.signout.get(pathname)
    if (signoutHandler) {
      const response = await signoutHandler.signOut(internalRequest)
      return response
    }

    const callbackHandler = this.routes.callback.get(pathname)
    if (callbackHandler) {
      const response = await callbackHandler.callback(internalRequest)
      return response
    }

    return {}
  }
}

export default AponiaAuth
