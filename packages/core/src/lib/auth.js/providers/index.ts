import * as checks from '../check'
import type { Cookie, InternalRequest, InternalResponse } from '$lib/integrations/response'
import type { AnyInternalConfig, InternalOAuthConfig, InternalOIDCConfig } from '../providers'

export interface Provider<T extends AnyInternalConfig> {
  config: T

  signIn(request: InternalRequest): Promise<InternalResponse>

  callback(request: InternalRequest): Promise<InternalResponse>

  signOut(request: InternalRequest): Promise<InternalResponse>
}

/**
 * Common procedure for getting authorization URL for OAuth and OIDC providers.
 */
export async function handleOAuthUrl(
  request: InternalRequest,
  provider: InternalOAuthConfig | InternalOIDCConfig
) {
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

