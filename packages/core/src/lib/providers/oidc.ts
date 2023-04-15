import * as oauth from 'oauth4webapi'
import * as checks from '../check'
import { encode } from '../jwt';
import type { Cookie, InternalRequest, InternalResponse } from '../integrations/response'
import type { Provider, InternalOIDCConfig } from '.';


export class OIDCProvider implements Provider<InternalOIDCConfig> {
  constructor(readonly config: InternalOIDCConfig) {}

  async signIn(request: InternalRequest): Promise<InternalResponse> {
    const provider = this.config

    const cookies: Cookie[] = []
    const { url } = provider.authorization

    if (provider.checks?.includes('state')) {
      const [state, stateCookie] = await checks.state.create(provider)
      url.searchParams.set('state', state)
      cookies.push(stateCookie)
    }

    if (provider.checks?.includes('pkce')) {
      if (!provider.authorizationServer.code_challenge_methods_supported?.includes('S256')) {
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
      url.searchParams.set('redirect_uri', `${request.url.origin}${provider.endpoints.callback}`)
    }

    if (!url.searchParams.has('scope')) {
      url.searchParams.set("scope", "openid profile email")
    }

    return { status: 302, redirect: url.toString(), cookies }
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    const provider = this.config

    const cookies: Cookie[] = []

    const [state, stateCookie] = await checks.state.use(request, provider)

    if (stateCookie) cookies.push(stateCookie)

    const codeGrantParams = oauth.validateAuthResponse(
      provider.authorizationServer,
      provider.client,
      request.url.searchParams,
      state,
    )

    if (oauth.isOAuth2Error(codeGrantParams)) throw new Error(codeGrantParams.error_description)

    const [pkce, pkceCookie] = await checks.pkce.use(request, provider)

    if (pkceCookie) cookies.push(pkceCookie)

    const initialCodeGrantResponse = await oauth.authorizationCodeGrantRequest(
      provider.authorizationServer,
      provider.client,
      codeGrantParams,
      `${request.url.origin}${provider.endpoints.callback}`,
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

    console.log({ result })

    if (oauth.isOAuth2Error(result)) throw new Error("TODO: Handle OIDC response body error")

    const profile = oauth.getValidatedIdTokenClaims(result)

    const profileResult = await provider.profile(profile, result)

    cookies.push({
      name: provider.cookies.sessionToken.name,
      value: await encode({ ...provider.jwt, token: profileResult }),
      options: {
        ...provider.cookies.sessionToken.options, 
        maxAge: 30 * 24 * 60 * 60,
      }
    })

    return { cookies }
  }

  async signOut(request: InternalRequest): Promise<InternalResponse> {
    console.log("OIDCProvider.signOut not implemented ", request)
    return {}
  }
}
