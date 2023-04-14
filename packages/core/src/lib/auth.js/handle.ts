import * as oauth from 'oauth4webapi'
import type { Cookie, InternalRequest, InternalResponse } from '$lib/integrations/response';
import type {
  InternalOAuthConfig,
  InternalOIDCConfig,
  InternalEmailConfig,
  InternalCredentialsConfig,
  AnyInternalConfig,
  AnyInternalOAuthConfig
} from './providers'
import * as checks from './check'

export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  return { ...request, cookies: {}, url: new URL(request.url) }
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

/**
 * Internal request handler.
 */
type Handler<T extends AnyInternalConfig> = (
  request: InternalRequest,
  provider: T
) => Promise<InternalResponse>

export const handleOAuth: Handler<InternalOAuthConfig> = async (_request, provider) => {
  return handleOAuthUrl(_request, provider)
}

export const handleOIDC: Handler<InternalOIDCConfig> = async (_request, provider) => {
  return handleOAuthUrl(_request, provider)
}

export const handleOAuthUrl: Handler<AnyInternalOAuthConfig> = async (request, provider) => {
  const cookies: Cookie[] = []
  const { url } = provider.authorization

  if (provider.checks?.includes('state')) {
    const [state, stateCookie] = await checks.state.create(provider)
    url.searchParams.set('state', state)
    cookies.push(stateCookie)
  }

  if (provider.checks?.includes('pkce')) {
    if (provider.authorizationServer.code_challenge_methods_supported?.includes('S256')) {
      provider.checks = ['nonce']
    } else {
      const [pkce, pkceCookie] = await checks.pkce.create(provider)
      url.searchParams.set('code_challenge', pkce)
      url.searchParams.set('code_challenge_method', 'S256')
      cookies.push(pkceCookie)
    }
  }

  if (provider.checks?.includes('nonce')) {
    const [nonce, nonceCookie] = await checks.nonce.create(provider)
    url.searchParams.set('nonce', nonce)
    cookies.push(nonceCookie)
  }

  if (!url.searchParams.has('redirect_uri')) {
    url.searchParams.set('redirect_uri', `${request.url.origin}/callback/${provider.id}`)
  }

  if (provider.type === 'oidc' && !url.searchParams.has('scope')) {
    url.searchParams.set("scope", "openid profile email")
  }

  return { redirect: url.toString(), cookies }
}

export const handleOAuthCallback: Handler<InternalOAuthConfig> = async (request, provider) => {
  const cookies: Cookie[] = []

  const [state, stateCookie] = await checks.state.use(request, provider)

  if (stateCookie) cookies.push(stateCookie)

  const codeGrantParams = oauth.validateAuthResponse(
    provider.authorizationServer,
    provider.client,
    provider.authorization.url.searchParams,
    state,
  )

  if (oauth.isOAuth2Error(codeGrantParams)) throw new Error(codeGrantParams.error_description)

  const [pkce, pkceCookie] = await checks.pkce.use(request, provider)

  if (pkceCookie) cookies.push(pkceCookie)

  const initialCodeGrantResponse = await oauth.authorizationCodeGrantRequest(
    provider.authorizationServer,
    provider.client,
    codeGrantParams,
    'provider.callbackUrl',
    pkce
  )

  const codeGrantResponse = await provider.token.conform(initialCodeGrantResponse.clone())

  const challenges = oauth.parseWwwAuthenticateChallenges(codeGrantResponse)

  if (challenges) {
    challenges.forEach(challenge => { 
      console.log("challenge", challenge)
    })
    throw new Error("TODO: Handle www-authenticate challenges as needed")
  }

  const tokens = await oauth.processAuthorizationCodeOAuth2Response(
    provider.authorizationServer,
    provider.client,
    codeGrantResponse,
  )

  if (oauth.isOAuth2Error(tokens)) throw new Error("TODO: Handle OAuth 2.0 response body error")

  const profile = await provider.userinfo.request({ tokens, provider })

  if (!profile) throw new Error("TODO: Handle missing profile")

  const profileResult = await provider.profile(profile.profile, tokens)

  return { ...profileResult, cookies }
}

export const handleOIDCCallback: Handler<InternalOIDCConfig> = async (request, provider) => {
  const cookies: Cookie[] = []

  const [state, stateCookie] = await checks.state.use(request, provider)

  if (stateCookie) cookies.push(stateCookie)

  const codeGrantParams = oauth.validateAuthResponse(
    provider.authorizationServer,
    provider.client,
    provider.authorization.url.searchParams,
    state,
  )

  if (oauth.isOAuth2Error(codeGrantParams)) throw new Error(codeGrantParams.error_description)

  const [pkce, pkceCookie] = await checks.pkce.use(request, provider)

  if (pkceCookie) cookies.push(pkceCookie)

  const initialCodeGrantResponse = await oauth.authorizationCodeGrantRequest(
    provider.authorizationServer,
    provider.client,
    codeGrantParams,
    'auth url',
    pkce,
  )

  const codeGrantResponse = await provider.token.conform(initialCodeGrantResponse.clone())

  const challenges = oauth.parseWwwAuthenticateChallenges(codeGrantResponse)

  if (challenges) {
    challenges.forEach(challenge => { console.log("challenge", challenge) })
    throw new Error("TODO: Handle www-authenticate challenges as needed")
  }

  const [nonce, nonceCookie] = await checks.nonce.use(request, provider)

  if (nonceCookie) cookies.push(nonceCookie)

  const result = await oauth.processAuthorizationCodeOpenIDResponse(
    provider.authorizationServer,
    provider.client,
    codeGrantResponse,
    nonce,
  )

  if (oauth.isOAuth2Error(result)) throw new Error("TODO: Handle OIDC response body error")

  const profile = oauth.getValidatedIdTokenClaims(result)

  const profileResult = await provider.profile(profile, result)

  return { ...profileResult, cookies }
}


/**
 * TODO
 */
export const handleEmail: Handler<InternalEmailConfig> = async (request, provider) => {
  console.log({ request, provider }, 'NOT IMPLEMENTED')
  return {}
}

/**
 * TODO
 */
export const handleCredentials: Handler<InternalCredentialsConfig> = async (request, provider) => {
  console.log({ request, provider }, 'NOT IMPLEMENTED')
  return {}
}
