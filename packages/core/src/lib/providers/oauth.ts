import * as oauth from 'oauth4webapi'
import type { Cookie, InternalRequest, InternalResponse } from '$lib/integrations/response';
import * as checks from '$lib/integrations/check'
import { handleOAuthUrl } from '.';
import type { Provider, InternalOAuthConfig } from '.'


export class OAuthProvider implements Provider <InternalOAuthConfig> {
  constructor(readonly config: InternalOAuthConfig) {}

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

    const profileResult = await provider.profile(profile, tokens)

    return { ...profileResult, cookies }
  }

  async signOut(request: InternalRequest): Promise<InternalResponse> {
    console.log("OAuthProvider.signOut not implemented ", request)
    return {}
  }
}

