import * as oauth from 'oauth4webapi'
import type { Cookie } from '$lib/integrations/response';
import type { InternalRequest, InternalResponse } from '$lib/integrations/response'
import * as checks from '../check'
import { handleOAuthUrl } from '.'
import type { InternalOIDCConfig } from '..'
import type { Provider } from '.';


export class OIDCProvider implements Provider<InternalOIDCConfig> {
  constructor(readonly config: InternalOIDCConfig) {}

  async signIn(request: InternalRequest): Promise<InternalResponse> {
    return handleOAuthUrl(request, this.config)
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    const provider = this.config

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

  async signOut(request: InternalRequest): Promise<InternalResponse> {
    console.log("OIDCProvider.signOut not implemented ", request)
    return {}
  }
}
