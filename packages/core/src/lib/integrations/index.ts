import { decode, encode } from "$lib/jwt"
import type { JWTOptions } from "$lib/jwt"
import type { Provider as AponiaProvider } from "$lib/providers"
import { parse } from "cookie"
import { defaultCookies } from "./cookie"
import type { InternalRequest, InternalResponse } from "./response"
import type { Provider } from "@auth/core/providers"
import { transformProviders, type ProviderOptions, type CookiesOptions } from './providers'
import { OAuthProvider } from "$lib/providers/oauth"
import { OIDCProvider } from "$lib/providers/oidc"
import { CredentialsProvider } from "$lib/providers/credentials"
import { EmailProvider } from "$lib/providers/email"
// import type { CallbacksOptions, EventCallbacks } from "@auth/core/types"

export const skipCSRFCheck = Symbol("skip-csrf-check")

interface Theme {
  colorScheme?: "auto" | "dark" | "light"
  logo?: string
  brandColor?: string
  buttonText?: string
}

interface PagesOptions {
  signIn: string
  signOut: string
  error: string
  verifyRequest: string
  newUser: string
}

export interface AuthConfig {
  providers?: Provider<any>[]
  secret?: string
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

export interface InternalAuthConfig extends ProviderOptions {
  csrfToken?: string
  csrfTokenVerified?: boolean
  secret: string
  session: NonNullable<Required<AuthConfig["session"]>>

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

  constructor(authOptions: AuthConfig) {
    const internalConfig: InternalAuthConfig = {
      ...authOptions,

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

    this.providers = internalProviders
  }

  async handle(request: Request): Promise<InternalResponse> {
    const internalRequest = await toInternalRequest(request)
    const internalResponse = await this.providers[0].signIn(internalRequest)
    return internalResponse
  }
}

async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { ...request, url, cookies }
}

