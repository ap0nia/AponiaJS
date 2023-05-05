import * as oauth from 'oauth4webapi'
import { encode, decode } from "./jwt.js"
import type { Cookie } from "./cookie.js"
import type { JWTOptions } from "./jwt.js"
import type { InternalRequest } from '../internal/request.js'
import type { OAuthProvider } from "../providers/oauth.js"
import type { OIDCProvider } from '../providers/oidc.js'

type CheckPayload = { value: string }

type AnyOAuthProvider = OAuthProvider<any> | OIDCProvider<any>

type AnyOAuthProviderConfig = AnyOAuthProvider['config']

// 15 minutes in seconds
const PKCE_MAX_AGE = 60 * 15

export const pkce = {
  create: async (config: AnyOAuthProviderConfig) => {
    const code_verifier = oauth.generateRandomCodeVerifier()
    const value = await oauth.calculatePKCECodeChallenge(code_verifier)
    const cookie = await signCookie(
      'pkceCodeVerifier',
      config,
      code_verifier,
      { ...config.jwt, maxAge: PKCE_MAX_AGE }
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
  async use(request: InternalRequest, config: AnyOAuthProviderConfig) {
    if (!config.checks?.includes("pkce")) return [ 'auth', null ] as const

    const codeVerifier = request.cookies[config.cookies.pkceCodeVerifier.name]
    if (!codeVerifier) throw new Error("PKCE code_verifier cookie was missing.")

    const d = config.jwt.decode ?? decode

    const value = await d<CheckPayload>({
      ...config.jwt,
      token: codeVerifier,
    })
    if (!value?.value) throw new Error("PKCE code_verifier value could not be parsed.")

    const cookie: Cookie = {
      name: config.cookies.pkceCodeVerifier.name,
      value: "",
      options: { ...config.cookies.pkceCodeVerifier.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

// 15 minutes in seconds
const STATE_MAX_AGE = 60 * 15

export const state = {
  create: async (config: AnyOAuthProviderConfig) => {
    // TODO: support customizing the state
    const value = oauth.generateRandomState()
    const cookie = await signCookie(
      'state',
      config,
      value,
      { ...config.jwt, maxAge: STATE_MAX_AGE }
    )
    return [ value, cookie ] as const
  },

 /**
   * Returns state if the provider is configured to use state,
   * and clears the container cookie afterwards.
   * An error is thrown if the state is missing or invalid.
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-10.12
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
   */
  async use(request: InternalRequest, config: AnyOAuthProviderConfig) {
    if (!config.checks?.includes('state')) return [ oauth.skipStateCheck, null ] as const

    const state = request.cookies[config.cookies.state.name]
    if (!state) throw new Error("State cookie was missing.")

    const d = config.jwt.decode ?? decode

    // IDEA: Let the user do something with the returned state
    const value = await d<CheckPayload>({ ...config.jwt, token: state })
    if (!value?.value) throw new Error("State value could not be parsed.")

    const cookie: Cookie = {
      name: config.cookies.state.name,
      value: '',
      options: { ...config.cookies.state.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

// 15 minutes in seconds
const NONCE_MAX_AGE = 60 * 15

export const nonce = {
  create: async (config: AnyOAuthProviderConfig) => {
    const value = oauth.generateRandomNonce()
    const cookie = await signCookie(
      'nonce',
      config,
      value,
      { ...config.jwt, maxAge: NONCE_MAX_AGE },
    )
    return [ value, cookie ] as const
  },

  /**
   * Returns nonce if the provider is configured to use nonce,
   * and clears the container cookie afterwards.
   * An error is thrown if the nonce is missing or invalid.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#nonce
   */
  async use(request: InternalRequest, config: AnyOAuthProviderConfig) {
    if (!config.checks?.includes('nonce')) return [ oauth.expectNoNonce, null ] as const

    const nonce = request.cookies[config.cookies.nonce.name]
    if (!nonce) throw new Error("Nonce cookie was missing.")

    const d = config.jwt.decode ?? decode

    const value = await d<CheckPayload>({ ...config.jwt, token: nonce })
    if (!value?.value) throw new Error("Nonce value could not be parsed.")

    const cookie: Cookie = {
      name: config.cookies.nonce.name,
      value: '',
      options: { ...config.cookies.nonce.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

/** 
 * Returns a signed cookie.
 */
async function signCookie(
  key: keyof AnyOAuthProviderConfig['cookies'],
  config: AnyOAuthProviderConfig,
  value: string,
  jwt: JWTOptions
) {
  const e = config.jwt.encode ?? encode
  const signedCookie: Cookie = {
    name: config.cookies[key].name,
    value: await e({ ...jwt, token: { value } }),
    options: { 
      ...config.cookies[key].options,
      expires: new Date(Date.now() + (jwt.maxAge ?? 60) * 1000)
    },
  }
  return signedCookie
}
