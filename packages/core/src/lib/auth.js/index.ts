import type { JWTOptions } from "$lib/jwt"
import type { Provider } from "@auth/core/providers"
import type { CookieSerializeOptions } from "cookie"

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
