import { decode, type JWTOptions } from "../security/jwt"
import type { OAuthProvider } from "../providers/oauth"
import type { OIDCProvider } from "../providers/oidc"
// import { CredentialsProvider } from "../providers/credentials"
// import { EmailProvider } from "../providers/email"
import { SessionManager } from "../session"
import type { InternalResponse } from "./response"
import type { InternalRequest } from "./request"
import { defaultCookies } from "$lib/security/cookie"

interface Pages {
  signIn: string
  signOut: string
  callback: string
  session: string
}

type AnyProvider = OAuthProvider<any> | OIDCProvider<any>

export interface AuthConfig {
  providers?: AnyProvider[]
  secret: string
  useSecureCookies?: boolean
  jwt: Partial<JWTOptions>
  pages?: Partial<Pages>
}

/**
 * Aponia Auth!
 */
export class AponiaAuth {
  initialized?: boolean

  userConfig: AuthConfig

  session: SessionManager

  pages: Pages

  providers: AnyProvider[]

  routes: {
    signin: Map<string, AnyProvider>
    signout: Map<string, AnyProvider>
    callback: Map<string, AnyProvider>
  }

  constructor(config: AuthConfig) {
    this.pages = {
      signIn: config.pages?.signIn ?? '/auth/login',
      signOut: config.pages?.signOut ?? '/auth/logout',
      callback: config.pages?.callback ?? '/auth/callback',
      session: config.pages?.session ?? '/auth/session',
    }

    this.userConfig = config

    this.routes = {
      signin: new Map(),
      signout: new Map(),
      callback: new Map(),
    }

    this.providers = this.userConfig.providers ?? []

    this.providers.forEach(provider => {
      this.routes.signin.set(provider.pages.signIn, provider)
      this.routes.signout.set(provider.pages.signOut, provider)
      this.routes.callback.set(provider.pages.callback, provider)
    })
  }

  async initialize() {
    if (this.initialized) return

    await Promise.all(this.providers.map(async (provider) => {
      provider.setJWTOptions(this.session.jwt)
      provider.setCookiesOptions(this.session.cookies)
      await provider.initialize()
    }))

    this.initialized = true
  }

  async handle(request: InternalRequest): Promise<InternalResponse> {
    if (!this.initialized) await this.initialize()

    const requestSession = await this.session.getRequestSession(request.request)
    request.session = requestSession?.session
    request.user = requestSession?.user

    const { pathname } = request.url

    switch (pathname) {
      case this.pages.session: {
        const sessionToken = request.cookies[this.session.cookies.sessionToken.name]
        const body = await decode({ secret: this.session.jwt.secret, token: sessionToken })
        return { body }
      }
    }

    const signinHandler = this.routes.signin.get(pathname)
    if (signinHandler) {
      const response = await signinHandler.signIn(request)
      return response
    }

    const signoutHandler = this.routes.signout.get(pathname)
    if (signoutHandler) {
      const response = await signoutHandler.signOut(request)
      return response
    }

    const callbackHandler = this.routes.callback.get(pathname)
    if (callbackHandler) {
      const response = await callbackHandler.callback(request)
      return response
    }

    return {}
  }
}

export default AponiaAuth
