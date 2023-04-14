import * as oauth from 'oauth4webapi'
import type { Cookie, InternalRequest, InternalResponse } from '$lib/integrations/response';
import type {
  InternalOAuthConfig,
  InternalOIDCConfig,
  InternalEmailConfig,
  InternalCredentialsConfig,
  AnyInternalConfig
} from './providers'
import type { CookiesOptions } from '@auth/core/types';
import { decode, encode } from '$lib/jwt';

export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  return { ...request, cookies: {} }
}

export async function handleAuth(request: Request, provider: AnyInternalConfig): Promise<InternalResponse> {
  const internalRequest = await toInternalRequest(request)

  switch (provider.type) {
    case 'oauth':
      return handleOAuth(internalRequest, provider);

    case 'oidc':
      return handleOIDC(internalRequest, provider);

    case 'email':
      return handleEmail(internalRequest, provider);

    case 'credentials':
      return handleCredentials(internalRequest, provider);

    default:
      throw new TypeError(`Invalid provider type. Received ${JSON.stringify(provider)}`);
  }
}

const STATE_MAX_AGE = 60 * 15 // 15 minutes in seconds
const PKCE_MAX_AGE = 60 * 15 // 15 minutes in seconds
const NONCE_MAX_AGE = 60 * 15 // 15 minutes in seconds

type Handler<T extends AnyInternalConfig> = (request: InternalRequest, provider: T) => Promise<InternalResponse>

export const handleOAuth: Handler<InternalOAuthConfig> = async (_request, provider) => {
  return handleOAuthUrl(_request, provider)
}

export const handleOIDC: Handler<InternalOIDCConfig> = async (_request, provider) => {
  return handleOAuthUrl(_request, provider)
}

export const handleOAuthUrl: Handler<InternalOAuthConfig | InternalOIDCConfig> = async (_request, provider) => {
  const cookies: Cookie[] = []
  const { url } = provider.authorization

  if (provider.checks?.includes('state')) {
    const state = oauth.generateRandomState()
    url.searchParams.set('state', state)
    cookies.push(await signCookie('state', state, STATE_MAX_AGE, provider))
  }

  if (provider.checks?.includes('pkce')) {
    if (provider.authorizationServer.code_challenge_methods_supported?.includes('S256')) {
      provider.checks = ['nonce']
    } else {
      const pkce = oauth.generateRandomCodeVerifier()
      url.searchParams.set('code_challenge', pkce)
      url.searchParams.set('code_challenge_method', 'S256')
      cookies.push(await signCookie('pkceCodeVerifier', pkce, PKCE_MAX_AGE, provider))
    }
  }

  if (provider.checks?.includes('nonce')) {
    const nonce = oauth.generateRandomState()
    url.searchParams.set('nonce', nonce)
    cookies.push(await signCookie('nonce', nonce, NONCE_MAX_AGE, provider))
  }

  if (provider.type === 'oidc' && !url.searchParams.has('scope')) {
    url.searchParams.set("scope", "openid profile email")
  }

  return { redirect: url.toString(), cookies }
}

interface CheckPayload { value: string }

export const handleOAuthCallback: Handler<InternalOAuthConfig> = async (request, provider) => {
  const cookies: Cookie[] = []

  const state = request.cookies.state

  if (!state && provider.checks.includes('state')) throw new Error('Missing state cookie')

  const decodedState = await decode<CheckPayload>({ ...provider.jwt, token: state })

  if (!decodedState?.value) throw new Error('Invalid state cookie')

  cookies.push({ 
    name: provider.cookies.state.name,
    value: '',
    options: { ...provider.cookies.state.options, maxAge: 0 }
  })

  const codeGrantParams = oauth.validateAuthResponse(
    provider.authorizationServer,
    provider.client,
    provider.authorization.url.searchParams,
    provider.checks.includes('state') ? decodedState.value : oauth.skipStateCheck
  )

  if (oauth.isOAuth2Error(codeGrantParams)) throw new Error(codeGrantParams.error_description)

  const pkce = request.cookies.pkce

  if (!pkce && provider.checks.includes('pkce')) throw new Error('Missing pkce cookie')

  const decodedPkce = await decode<CheckPayload>({ ...provider.jwt, token: pkce })

  if (!decodedPkce?.value) throw new Error('Invalid pkce cookie')

  cookies.push({
    name: provider.cookies.pkceCodeVerifier.name,
    value: '',
    options: { ...provider.cookies.pkceCodeVerifier.options, maxAge: 0 }
  })

  const codeGrantResponse = await oauth.authorizationCodeGrantRequest(
    provider.authorizationServer,
    provider.client,
    codeGrantParams,
    'auth url',
    provider.checks.includes('pkce') ? decodedPkce.value : 'auth'
  )

  const conformedResponse = await provider.token.conform(codeGrantResponse.clone())

  const challenges = oauth.parseWwwAuthenticateChallenges(conformedResponse)

  if (challenges) {
    challenges.forEach(challenge => { console.log("challenge", challenge) })
    throw new Error("TODO: Handle www-authenticate challenges as needed")
  }

  const tokens = await oauth.processAuthorizationCodeOAuth2Response(
    provider.authorizationServer,
    provider.client,
    conformedResponse,
  )

  if (oauth.isOAuth2Error(tokens)) throw new Error("TODO: Handle OAuth 2.0 response body error")

  const profile = await provider.userinfo.request({ tokens, provider })

  if (!profile) throw new Error("TODO: Handle missing profile")

  const profileResult = await provider.profile(profile.profile, tokens)

  return {
    ...profileResult,
    cookies
  }
}

export const handleOIDCCallback: Handler<InternalOIDCConfig> = async (request, provider) => {
  const cookies: Cookie[] = []

  const state = request.cookies.state

  if (!state && provider.checks.includes('state')) throw new Error('Missing state cookie')

  const decodedState = await decode<CheckPayload>({ ...provider.jwt, token: state })

  if (!decodedState?.value) throw new Error('Invalid state cookie')

  cookies.push({ 
    name: provider.cookies.state.name,
    value: '',
    options: { ...provider.cookies.state.options, maxAge: 0 }
  })

  const codeGrantParams = oauth.validateAuthResponse(
    provider.authorizationServer,
    provider.client,
    provider.authorization.url.searchParams,
    provider.checks.includes('state') ? decodedState.value : oauth.skipStateCheck
  )

  if (oauth.isOAuth2Error(codeGrantParams)) throw new Error(codeGrantParams.error_description)

  const pkce = request.cookies.pkce

  if (!pkce && provider.checks.includes('pkce')) throw new Error('Missing pkce cookie')

  const decodedPkce = await decode<CheckPayload>({ ...provider.jwt, token: pkce })

  if (!decodedPkce?.value) throw new Error('Invalid pkce cookie')

  cookies.push({
    name: provider.cookies.pkceCodeVerifier.name,
    value: '',
    options: { ...provider.cookies.pkceCodeVerifier.options, maxAge: 0 }
  })

  const codeGrantResponse = await oauth.authorizationCodeGrantRequest(
    provider.authorizationServer,
    provider.client,
    codeGrantParams,
    'auth url',
    provider.checks.includes('pkce') ? decodedPkce.value : 'auth'
  )

  const conformedResponse = await provider.token.conform(codeGrantResponse.clone())

  const challenges = oauth.parseWwwAuthenticateChallenges(conformedResponse)

  if (challenges) {
    challenges.forEach(challenge => { console.log("challenge", challenge) })
    throw new Error("TODO: Handle www-authenticate challenges as needed")
  }

  const nonce = request.cookies.nonce

  if (provider.checks.includes('nonce') && !nonce) throw new Error('Missing nonce cookie')

  const decodedNonce = await decode<CheckPayload>({ ...provider.jwt, token: nonce })

  if (!decodedNonce?.value) throw new Error('Invalid nonce cookie')

  const result = await oauth.processAuthorizationCodeOpenIDResponse(
    provider.authorizationServer,
    provider.client,
    conformedResponse,
    decodedNonce.value ?? oauth.expectNoNonce
  )

  if (oauth.isOAuth2Error(result)) throw new Error("TODO: Handle OIDC response body error")

  const profile = oauth.getValidatedIdTokenClaims(result)

  const profileResult = await provider.profile(profile, result)

  return {
    ...profileResult,
    cookies
  }
}

export const handleEmail: Handler<InternalEmailConfig> = async (request, provider) => {
  console.log({ request, provider })
  return {}
}

export const handleCredentials: Handler<InternalCredentialsConfig> = async (request, provider) => {
  console.log({ request, provider })
  return {}
}

/** 
 * Returns a signed cookie.
 */
export async function signCookie(
  type: keyof CookiesOptions,
  value: string,
  maxAge: number,
  provider: InternalOAuthConfig | InternalOIDCConfig 
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
