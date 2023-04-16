import type { CookieOption, CookiesOptions } from "@auth/core/types"
import type { Cookie } from "../integrations/response"
import { encode } from "./jwt"
import type { JWTOptions } from "./jwt"

export interface InternalCookiesOptions extends CookiesOptions { refreshToken: CookieOption }

export function defaultCookies(useSecureCookies: boolean = false): InternalCookiesOptions {
  const cookiePrefix = useSecureCookies ? "__Secure-" : ""
  return {
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
export async function signCookie(cookie: CookieOption, value: string, jwtOptions: JWTOptions) {
  const signedCookie: Cookie = {
    name: cookie.name,
    value: await encode({ ...jwtOptions, token: { value } }),
    options: { 
      ...cookie.options,
      expires: new Date(Date.now() + (jwtOptions.maxAge ?? 60) * 1000)
    },
  }
  return signedCookie
}

