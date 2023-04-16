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

type Awaitable<T> = T | PromiseLike<T>

const pages = [
  'signIn',
  'signOut',
  'callback',
  'session',
  'error',
  'verifyRequest',
  'newUser'
] as const

type Pages = typeof pages[number]

type PagesOptions = { [k in Pages]: string }

/**
 * User-provided config.
 */
export interface AuthConfig {
  providers?: Provider<any>[]

  callbacks?: {
    onSignIn?: (request: InternalRequest) => Awaitable<void>
    onSignOut?: (request: InternalRequest) => Awaitable<void>
  }

  secret: string

  session?: Partial<SessionManagerConfig<any, any>>

  pages?: Partial<PagesOptions>
}

/**
 * Aponia Auth!
 */
export class AponiaAuth {
  userConfig: AuthConfig

  session: SessionManager<any, any>

  callbacks: AuthConfig['callbacks']

  pages: PagesOptions

  providers: AponiaProvider[]

  routes: {
    signin: Map<string, AponiaProvider>
    signout: Map<string, AponiaProvider>
    callback: Map<string, AponiaProvider>
  }

  constructor(authOptions: AuthConfig) {
    this.callbacks = authOptions.callbacks 

    this.pages = {
      signIn: authOptions.pages?.signIn ?? '/auth/login',
      signOut: authOptions.pages?.signOut ?? '/auth/logout',
      callback: authOptions.pages?.callback ?? '/auth/callback',
      session: authOptions.pages?.session ?? '/auth/session',
      error: authOptions.pages?.error ?? '/auth/error',
      verifyRequest: authOptions.pages?.verifyRequest ?? '/auth/verify-request',
      newUser: authOptions.pages?.newUser ?? '/auth/new-user',
    }

    this.session = new SessionManager({
      ...authOptions.session,
      jwt: {
        secret: authOptions.secret,
        ...authOptions.session?.jwt,
      }
    })

    this.userConfig = authOptions

    this.routes = {
      signin: new Map(),
      signout: new Map(),
      callback: new Map(),
    }

    this.providers = []

    this.initializeProviders()
  }

  async initializeProviders() {
    const providers = this.userConfig.providers ?? []

    const internalProviderConfigs = await Promise.all(
      providers.map(provider => transformProviders(provider, this))
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

    if (!this.providers.length) {
      throw new Error('No providers found')
    }
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

    if (signinHandler) return signinHandler.signIn(request)

    const signoutHandler = this.routes.signout.get(pathname)

    if (signoutHandler) return signoutHandler.signOut(request)

    const callbackHandler = this.routes.callback.get(pathname)

    if (callbackHandler) return callbackHandler.callback(request)

    return {}
  }
}

export default AponiaAuth
