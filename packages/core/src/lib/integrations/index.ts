import type { Provider } from "@auth/core/providers"
import { decode, encode, type JWTOptions } from "$lib/jwt"
import type { Provider as AponiaProvider } from "$lib/providers"
import { parse, type CookieSerializeOptions } from "cookie"
import { defaultCookies } from "./cookie"
import type { InternalRequest, InternalResponse } from "./response"
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

export interface AuthConfig {
  providers: Provider[]
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

export interface InternalAuthConfig {
  providers: AponiaProvider[]
  csrfToken?: string
  csrfTokenVerified?: boolean
  secret: string
  session: NonNullable<Required<AuthConfig["session"]>>
  jwt: JWTOptions
  cookies: CookiesOptions

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
  config: InternalAuthConfig

  constructor(authOptions: AuthConfig) {
    const internalConfig: InternalAuthConfig = {
      ...authOptions,

      secret: authOptions.secret ?? '',

      cookies: {
        ...defaultCookies(authOptions.useSecureCookies),
        ...authOptions.cookies,
      },

      providers: [],

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
  }

  async handle(request: Request): Promise<Response> {
    const internalRequest = await toInternalRequest(request)
    const internalResponse = await this.config.providers[0].signIn(internalRequest)
    const externalResponse = toExternalResponse(internalResponse)
    return externalResponse
  }
}

async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { ...request, url, cookies }
}

async function toExternalResponse(response: InternalResponse): Promise<Response> {
  const externalResponse = new Response(await response.body?.json())
  return externalResponse
}
