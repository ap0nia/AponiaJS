import type { CookieSerializeOptions } from "cookie"

export interface Cookie {
  name: string
  value: string
  options?: CookieSerializeOptions
}

export interface CookieOption {
  name: string
  options: CookieSerializeOptions
}

export interface CookiesOptions { 
  callbackUrl: CookieOption
  csrfToken: CookieOption
  pkceCodeVerifier: CookieOption
  state: CookieOption
  nonce: CookieOption
  sessionToken: CookieOption
  accessToken: CookieOption
  refreshToken: CookieOption
}

const defaultCookieName = 'aponia-auth'

const defaultSecurePrefix = '__Secure-'

const fifteenMinutesInSeconds = 60 * 15

export function createCookiesOptions(
  useSecureCookies = false,
  cookieName = defaultCookieName,
  securePrefix = defaultSecurePrefix
): CookiesOptions {
  const cookiePrefix = useSecureCookies ? securePrefix : ""
  return {
    sessionToken: {
      name: `${cookiePrefix}${cookieName}.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    accessToken: {
      name: `${cookiePrefix}${cookieName}.access-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    refreshToken: {
      name: `${cookiePrefix}${cookieName}.refresh-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    callbackUrl: {
      name: `${cookiePrefix}${cookieName}.callback-url`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    csrfToken: {
      // Default to __Host- for CSRF token for additional protection if using useSecureCookies
      // NB: The `__Host-` prefix is stricter than the `__Secure-` prefix.
      name: `${useSecureCookies ? "__Host-" : cookiePrefix}${cookieName}.csrf-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    pkceCodeVerifier: {
      name: `${cookiePrefix}${cookieName}.pkce.code_verifier`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: fifteenMinutesInSeconds,
      },
    },
    state: {
      name: `${cookiePrefix}${cookieName}.state`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: fifteenMinutesInSeconds,
      },
    },
    nonce: {
      name: `${cookiePrefix}${cookieName}.nonce`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: fifteenMinutesInSeconds,
      },
    },
  }
}

