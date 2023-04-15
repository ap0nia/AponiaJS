import { parse } from "cookie"
import type { Provider } from "@auth/core/providers"
import { decode } from "../jwt"
import { transformProviders } from './providers'
import { OAuthProvider } from "../providers/oauth"
import { OIDCProvider } from "../providers/oidc"
import { CredentialsProvider } from "../providers/credentials"
import { EmailProvider } from "../providers/email"
import { SessionManager } from "../session"
import type { Provider as AponiaProvider } from "../providers"
import type { InternalRequest, InternalResponse } from "./response"
import type { SessionManagerConfig } from "../session"

const skipCSRFCheck = Symbol("skip-csrf-check")

interface PagesOptions {
  signIn: string
  signOut: string
  callback: string
  session: string
  error: string
  verifyRequest: string
  newUser: string
}

export interface AuthConfig {
  providers?: Provider<any>[]

  secret: string

  session?: Partial<SessionManagerConfig<any, any>>

  pages?: Partial<PagesOptions>

  trustHost?: boolean

  skipCSRFCheck?: typeof skipCSRFCheck
}

export interface InternalAuthConfig {
  csrfToken?: string

  csrfTokenVerified?: boolean

  secret: string

  session: SessionManager<any, any>

  pages: PagesOptions
}

export class Auth {
  private _config: AuthConfig

  config: InternalAuthConfig

  providers: AponiaProvider[]

  routes: {
    signin: Map<string, AponiaProvider>
    signout: Map<string, AponiaProvider>
    callback: Map<string, AponiaProvider>
  }

  constructor(authOptions: AuthConfig) {
    const internalConfig: InternalAuthConfig = {
      ...authOptions,

      pages: {
        signIn: authOptions.pages?.signIn ?? '/auth/login',
        signOut: authOptions.pages?.signOut ?? '/auth/logout',
        callback: authOptions.pages?.callback ?? '/auth/callback',
        session: authOptions.pages?.session ?? '/auth/session',
        error: authOptions.pages?.error ?? '/auth/error',
        verifyRequest: authOptions.pages?.verifyRequest ?? '/auth/verify-request',
        newUser: authOptions.pages?.newUser ?? '/auth/new-user',
      },

      session: new SessionManager(authOptions.session ?? {}),
    }

    this.config = internalConfig

    this._config = authOptions

    this.routes = {
      signin: new Map(),
      signout: new Map(),
      callback: new Map(),
    }

    this.providers = []

    this.initializeProviders()
  }

  async initializeProviders() {
    const providers = this._config.providers ?? []

    const internalProviderConfigs = await Promise.all(
      providers.map(provider => transformProviders(provider, this.config))
    )

    const internalProviders = await Promise.all(
      internalProviderConfigs.map((config) => {
        switch (config.type) {
          case 'oauth':
            return new OAuthProvider(config)
          case 'oidc':
            return new OIDCProvider(config)
          case 'credentials':
            return new CredentialsProvider(config)
          case 'email':
            return new EmailProvider(config)
        }
      })
    )

    internalProviders.forEach((provider) => {
      this.routes.signin.set(provider.config.endpoints.signin, provider)
      this.routes.signout.set(provider.config.endpoints.signout, provider)
      this.routes.callback.set(provider.config.endpoints.callback, provider)
    })

    this.providers = internalProviders
  }

  async handle(request: InternalRequest): Promise<InternalResponse> {
    const { pathname } = request.url

    /**
     * Static routes.
     */
    switch (pathname) {
      case this.config.pages.session:
        const sessionToken = request.cookies[this.config.session.cookies.sessionToken.name]
        const session = await decode({ secret: this.config.secret, token: sessionToken })
        console.log('session! ', session)
    }

    const signinHandler = this.routes.signin.get(pathname)

    if (signinHandler) return signinHandler.signIn(request)

    const signoutHandler = this.routes.signout.get(pathname)

    if (signoutHandler) return signoutHandler.signOut(request)

    const callbackHandler = this.routes.callback.get(pathname)

    if (callbackHandler) return callbackHandler.callback(request)

    return {}
  }
}

export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { ...request, url, cookies }
}

