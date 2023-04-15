import type { CookieSerializeOptions } from "cookie"
import { decode, encode } from "$lib/jwt"
import type { JWTOptions } from "$lib/jwt"
import type { Provider as AponiaProvider } from "$lib/providers"
import { parse } from "cookie"
import { defaultCookies } from "./cookie"
import type { InternalRequest, InternalResponse } from "./response"
import type { Provider } from "@auth/core/providers"
import { transformProviders } from './providers'
import { OAuthProvider } from "$lib/providers/oauth"
import { OIDCProvider } from "$lib/providers/oidc"
import { CredentialsProvider } from "$lib/providers/credentials"
import { EmailProvider } from "$lib/providers/email"
// import type { CallbacksOptions, EventCallbacks } from "@auth/core/types"

export const skipCSRFCheck = Symbol("skip-csrf-check")

/** 
 * [Documentation](https://authjs.dev/reference/configuration/auth-config#cookies)
 */
interface CookieOption {
  name: string
  options: CookieSerializeOptions
}

/** 
 * [Documentation](https://authjs.dev/reference/configuration/auth-config#cookies)
 */
interface CookiesOptions {
  sessionToken: CookieOption
  callbackUrl: CookieOption
  csrfToken: CookieOption
  pkceCodeVerifier: CookieOption
  state: CookieOption
  nonce: CookieOption
}

interface Theme {
  colorScheme?: "auto" | "dark" | "light"
  logo?: string
  brandColor?: string
  buttonText?: string
}

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
  session?: {
    strategy?: "jwt" | "database"
    maxAge?: number
    updateAge?: number
    generateSessionToken?: () => string
  }
  jwt?: Partial<JWTOptions>
  pages?: Partial<PagesOptions>
  debug?: boolean
  theme?: Theme
  useSecureCookies?: boolean
  cookies?: Partial<CookiesOptions>
  trustHost?: boolean
  skipCSRFCheck?: typeof skipCSRFCheck

  // callbacks?: Partial<CallbacksOptions>
  // events?: Partial<EventCallbacks>
  // adapter?: Adapter
  // logger?: Partial<LoggerInstance>
}

export interface InternalAuthConfig {
  csrfToken?: string
  csrfTokenVerified?: boolean
  secret: string
  session: NonNullable<Required<AuthConfig["session"]>>
  jwt: JWTOptions
  cookies: CookiesOptions
  pages: PagesOptions

  // pages: Partial<PagesOptions>
  // theme: Theme
  // debug: boolean
  // action: AuthAction
  // provider: InternalProvider<TProviderType>
  // adapter: Required<Adapter> | undefined
  // logger: LoggerInstance
  // url: URL
  // callbackUrl: string
  // events: Partial<EventCallbacks>
  // callbacks: CallbacksOptions
}

const maxAge = 30 * 24 * 60 * 60 // Sessions expire after 30 days of being idle by default

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

      secret: authOptions.secret ?? '',

      cookies: {
        ...defaultCookies(authOptions.useSecureCookies),
        ...authOptions.cookies,
      },

      session: {
        strategy: authOptions.session?.strategy ?? "jwt",
        maxAge,
        updateAge: 24 * 60 * 60,
        generateSessionToken: () => crypto.randomUUID(),
        ...authOptions.session,
      },

      jwt: {
        secret: authOptions.secret ?? '',
        maxAge: authOptions.session?.maxAge ?? maxAge,
        encode,
        decode,
        ...authOptions.jwt,
      },
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
        const sessionToken = request.cookies[this.config.cookies.sessionToken.name]
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

