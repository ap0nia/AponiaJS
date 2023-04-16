import * as oauth from "oauth4webapi"
import { decode } from "./jwt"
import { signCookie } from "./cookie"
import type { Cookie } from "../integrations/response"
import type { InternalRequest } from "../integrations/request"
import type { OAuthProvider } from "../providers/oauth"
import type { OIDCProvider } from "../providers/oidc"

type CheckPayload =  { value: string }

const PKCE_MAX_AGE = 60 * 15

type AnyProvider = OAuthProvider<any, any> | OIDCProvider<any, any>

export const pkce = {
  async create(options: AnyProvider) {
    const code_verifier = oauth.generateRandomCodeVerifier()

    const value = await oauth.calculatePKCECodeChallenge(code_verifier)

    const cookie = await signCookie(
      "pkceCodeVerifier",
      code_verifier,
      PKCE_MAX_AGE,
      options
    )

    return [ value, cookie ] as const
  },

  async use(request: InternalRequest, provider: AnyProvider) {
    if (!provider.config.checks.includes("pkce")) return [ 'auth', null ] as const

    const codeVerifier = request.cookies[provider.cookies.pkceCodeVerifier.name]

    if (!codeVerifier) throw new Error("PKCE code_verifier cookie was missing.")

    const value = await decode<CheckPayload>({
      ...provider.jwt,
      token: codeVerifier,
    })

    if (!value?.value) throw new Error("PKCE code_verifier value could not be parsed.")

    const cookie: Cookie = {
      name: provider.cookies.pkceCodeVerifier.name,
      value: "",
      options: { ...provider.cookies.pkceCodeVerifier.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

const STATE_MAX_AGE = 60 * 15

export const state = {
  async create(provider: AnyProvider) {
    const value = oauth.generateRandomState()

    const cookie = await signCookie("state", value, STATE_MAX_AGE, provider)

    return [ value, cookie ] as const
  },

  async use(request: InternalRequest, provider: AnyProvider) {
    if (!provider.config.checks.includes('state')) return [ oauth.skipStateCheck, null ] as const

    const state = request.cookies[provider.cookies.state.name]

    if (!state) throw new Error("State cookie was missing.")

    const value = await decode<CheckPayload>({ ...provider.jwt, token: state })

    if (!value?.value) throw new Error("State value could not be parsed.")

    const cookie: Cookie = {
      name: provider.cookies.state.name,
      value: '',
      options: { ...provider.cookies.state.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

const NONCE_MAX_AGE = 60 * 15

export const nonce = {
  async create(provider: AnyProvider) {
    const value = oauth.generateRandomNonce()

    const cookie = await signCookie("nonce", value, NONCE_MAX_AGE, provider)

    return [ value, cookie ] as const
  },

  async use(request: InternalRequest, provider: AnyProvider) {
    if (!provider.config.checks.includes('nonce')) return [ oauth.expectNoNonce, null ] as const

    const nonce = request.cookies[provider.cookies.nonce.name]

    if (!nonce) throw new Error("Nonce cookie was missing.")

    const value = await decode<CheckPayload>({ ...provider.jwt, token: nonce })

    if (!value?.value) throw new Error("Nonce value could not be parsed.")

    const cookie: Cookie = {
      name: provider.cookies.nonce.name,
      value: '',
      options: { ...provider.cookies.nonce.options, maxAge: 0 },
    }

    return [ value.value, cookie ] as const
  },
}

