import * as oauth from 'oauth4webapi'
import type { JWTOptions } from "$lib/jwt"
import type { CookieSerializeOptions } from "cookie"
import type { InternalProvider, Provider } from "./providers"
import parseProviders from "./providers"

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

export class Auth {
  constructor(config: AuthConfig) {
    const request = new Request("https://example.com")

    parseProviders(config.providers).map(async provider => {
      const as = provider.authorization?.url ? undefined : await getAuthorizationUrl(provider)

      if (!provider.authorization?.url && !as?.authorization_endpoint) {
        throw new Error('No authorization endpoint found')
      }

      const url = provider.authorization?.url ?? new URL(as?.authorization_endpoint ?? '')

      const authParams = url.searchParams

      const params = Object.assign(
        {
          response_type: "code",
          client_id: provider.clientId,
          redirect_uri: `${provider.id}`,
          ...provider.authorization?.params,
        },
        Object.fromEntries(provider.authorization?.url?.searchParams ?? []),
        Object.fromEntries(new URL(request.url).searchParams)
      )

      Object.entries(params).forEach(([k, v]) => {
        if (typeof v === 'string') {
          authParams.set(k, v ?? '')
        }
      })
    })
  }
}

async function getAuthorizationUrl(provider: InternalProvider) {
  const issuer = new URL(provider.issuer ?? '')
  const discoveryResponse = await oauth.discoveryRequest(issuer)
  const as = await oauth.processDiscoveryResponse(issuer, discoveryResponse)
  return as
}
