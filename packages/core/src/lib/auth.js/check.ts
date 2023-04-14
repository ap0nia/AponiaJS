import * as oauth from "oauth4webapi"
import { encode, decode } from "$lib/jwt"
import type { CookiesOptions } from "@auth/core/types"
import type { Cookie, InternalRequest } from "$lib/integrations/response"
import type { AnyInternalOAuthConfig } from "./providers"

type CheckPayload =  { value: string }

const PKCE_MAX_AGE = 60 * 15 // 15 minutes in seconds

export const pkce = {
  async create(options: AnyInternalOAuthConfig) {
    const code_verifier = oauth.generateRandomCodeVerifier()
    const value = await oauth.calculatePKCECodeChallenge(code_verifier)
    const maxAge = PKCE_MAX_AGE
    const cookie = await signCookie(
      "pkceCodeVerifier",
      code_verifier,
      maxAge,
      options
    )
    return [ value, cookie ] as const
  },

  /**
   * Returns code_verifier if the provider is configured to use PKCE,
   * and clears the container cookie afterwards.
   * An error is thrown if the code_verifier is missing or invalid.
   * @see https://www.rfc-editor.org/rfc/rfc7636
   * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#pkce
   */
  async use(request: InternalRequest, provider: AnyInternalOAuthConfig) {
    if (!provider.checks.includes("pkce")) {
      // TODO: review fallback code verifier
      return [ 'auth', null ] as const
    }

    const codeVerifier = request.cookies[provider.cookies.pkceCodeVerifier.name]

    if (!codeVerifier) throw new Error("PKCE code_verifier cookie was missing.")

    const value = await decode<CheckPayload>({
      ...provider.jwt,
      token: codeVerifier,
    })

    if (!value?.value) throw new Error("PKCE code_verifier value could not be parsed.")

    // Clear the pkce code verifier cookie after use
    const cookie: Cookie = {
      name: provider.cookies.pkceCodeVerifier.name,
      value: "",
      options: { ...provider.cookies.pkceCodeVerifier.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

const STATE_MAX_AGE = 60 * 15 // 15 minutes in seconds

export const state = {
  async create(provider: AnyInternalOAuthConfig) {
    // TODO: support customizing the state
    const value = oauth.generateRandomState()
    const cookie = await signCookie("state", value, STATE_MAX_AGE, provider)
    return [ value, cookie ] as const
  },

  /**
   * Returns state if the provider is configured to use state,
   * and clears the container cookie afterwards.
   * An error is thrown if the state is missing or invalid.
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-10.12
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
   */
  async use(request: InternalRequest, provider: AnyInternalOAuthConfig) {
    if (!provider.checks.includes('state')) {
      return [ oauth.skipStateCheck, null ] as const
    }

    const state = request.cookies[provider.cookies.state.name]

    if (!state) throw new Error("State cookie was missing.")

    // IDEA: Let the user do something with the returned state
    const value = await decode<CheckPayload>({ ...provider.jwt, token: state })

    if (!value?.value) throw new Error("State value could not be parsed.")

    // Clear the state cookie after use
    const cookie: Cookie = {
      name: provider.cookies.state.name,
      value: '',
      options: { ...provider.cookies.state.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

const NONCE_MAX_AGE = 60 * 15 // 15 minutes in seconds

export const nonce = {
  async create(provider: AnyInternalOAuthConfig) {
    const value = oauth.generateRandomNonce()
    const cookie = await signCookie("nonce", value, NONCE_MAX_AGE, provider)
    return [ value, cookie ] as const
  },

  /**
   * Returns nonce if the provider is configured to use nonce,
   * and clears the container cookie afterwards.
   * An error is thrown if the nonce is missing or invalid.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#nonce
   */
  async use(request: InternalRequest, provider: AnyInternalOAuthConfig) {
    if (!provider.checks.includes('nonce')) {
      return [ oauth.expectNoNonce, null ] as const
    }

    const nonce = request.cookies[provider.cookies.nonce.name]

    if (!nonce) throw new Error("Nonce cookie was missing.")

    const value = await decode<CheckPayload>({ ...provider.jwt, token: nonce })

    if (!value?.value) throw new Error("Nonce value could not be parsed.")

    // Clear the nonce cookie after use
    const cookie: Cookie = {
      name: provider.cookies.nonce.name,
      value: '',
      options: { ...provider.cookies.nonce.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
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

