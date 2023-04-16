import { decode } from "../security/jwt"
import type { OAuthProvider } from "../providers/oauth"
import type { OIDCProvider } from "../providers/oidc"
// import { CredentialsProvider } from "../providers/credentials"
// import { EmailProvider } from "../providers/email"
import { SessionManager } from "../session"
import type { InternalResponse } from "./response"
import type { InternalRequest } from "./request"
import type { SessionManagerConfig } from "../session"

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
  session?: Partial<SessionManagerConfig<any, any>>
  pages?: Partial<Pages>
}

/**
 * Aponia Auth!
 */
export class AponiaAuth {
  initialized?: boolean

  userConfig: AuthConfig

  session: SessionManager<any, any>

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

    this.session = new SessionManager({
      ...config.session,
      jwt: {
        secret: config.secret,
        ...config.session?.jwt,
      }
    })

    this.userConfig = config

    this.routes = {
      signin: new Map(),
      signout: new Map(),
      callback: new Map(),
    }

    this.providers = []
  }

  async initialize() {
    this.providers = await Promise.all(
      this.userConfig.providers?.map(async (provider) => {
        await provider.initialize({
          ...this.userConfig,
          jwt: { secret: this.userConfig.secret }
        })

        this.routes.signin.set(provider.pages.signIn, provider)
        this.routes.signout.set(provider.pages.signOut, provider)
        this.routes.callback.set(provider.pages.callback, provider)

        return provider
      }) ?? []
    )

    if (!this.providers.length) {
      throw new Error('No providers found')
    }

    this.initialized = true
  }

  async handle(request: InternalRequest): Promise<InternalResponse> {
    const { pathname } = request.url

    /**
     * Static routes.
     */
    switch (pathname) {
      case this.pages.session:
        const sessionToken = request.cookies[this.session.cookies.sessionToken.name]
        const body = await decode({ secret: this.session.jwt.secret, token: sessionToken })
        return { body }
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
