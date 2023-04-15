import type { CookieOption, CookiesOptions } from "@auth/core/types"
import type { AnyInternalOAuthConfig } from "./providers"
import type { Cookie } from "./integrations/response"
import { encode } from "./jwt"

export interface InternalCookiesOptions extends CookiesOptions {
  refreshToken: CookieOption
}

/**
 * Use secure cookies if the site uses HTTPS
 * This being conditional allows cookies to work non-HTTPS development URLs
 * Honour secure cookie option, which sets 'secure' and also adds '__Secure-'
 * prefix, but enable them by default if the site URL is HTTPS; but not for
 * non-HTTPS URLs like http://localhost which are used in development).
 * For more on prefixes see https://googlechrome.github.io/samples/cookie-prefixes/
 *
 * @TODO Review cookie settings (names, options)
 */
export function defaultCookies(useSecureCookies: boolean = false): InternalCookiesOptions {
  const cookiePrefix = useSecureCookies ? "__Secure-" : ""
  return {
    // default cookie options
    refreshToken: {
      name: `${cookiePrefix}next-auth.refresh-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    sessionToken: {
      name: `${cookiePrefix}next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    callbackUrl: {
      name: `${cookiePrefix}next-auth.callback-url`,
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
      name: `${useSecureCookies ? "__Host-" : ""}next-auth.csrf-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
    pkceCodeVerifier: {
      name: `${cookiePrefix}next-auth.pkce.code_verifier`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15, // 15 minutes in seconds
      },
    },
    state: {
      name: `${cookiePrefix}next-auth.state`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15, // 15 minutes in seconds
      },
    },
    nonce: {
      name: `${cookiePrefix}next-auth.nonce`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
      },
    },
  }
}

/** 
 * Returns a signed cookie.
 */
export async function signCookie(
  type: keyof CookiesOptions,
  value: string,
  maxAge: number,
  provider: AnyInternalOAuthConfig
): Promise<Cookie> {
  return {
    name: provider.cookies[type].name,
    value: await encode({ ...provider.jwt, maxAge, token: { value } }),
    options: { 
      ...provider.cookies[type].options,
      expires: new Date(Date.now() + maxAge * 1000)
    },
  }
}

