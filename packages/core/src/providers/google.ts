import * as oauth from 'oauth4webapi'
import type { OAuthConfig, ProviderConfig } from '.'

export const GOOGLE_ENDPOINTS = {
  authorization: 'https://accounts.google.com/o/oauth2/v2/auth',
  access_token: 'https://oauth2.googleapis.com/token',
  user: 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json',
  revoke: 'https://oauth2.googleapis.com/revoke',
} as const

export interface GoogleConfig extends OAuthConfig {
  redirect_uri: string
}

export class Google implements ProviderConfig<GoogleProfile> {
  id = 'google'
  type: ProviderConfig<GoogleProfile>['type'] = 'oidc'
  config: GoogleConfig

  constructor(config: GoogleConfig) {
    this.config = config
  }

  getAuthorizationUrl () {
    const state = oauth.generateRandomState()

    const authorizationParams = new URLSearchParams({
      client_id: this.config.clientId,
      scope: (this.config.scope ?? ['profile', 'email']).join(' '),
      state,
      response_type: 'code',
      redirect_uri: this.config.redirect_uri
    })

    const authorizationUrl = `${GOOGLE_ENDPOINTS.authorization}?${authorizationParams.toString()}`

    return [authorizationUrl, state] as const
  }

  async getTokens(code: string) {
    const tokenParams = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: this.config.redirect_uri
    })

    const tokens = await fetch(`${GOOGLE_ENDPOINTS.access_token}?${tokenParams.toString()}`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
      },
    }).then(res => res.json())

    return tokens
  }
  
  async revokeToken(token: string) {
    const revokeParams = new URLSearchParams({ token })

    const url = `${GOOGLE_ENDPOINTS.revoke}?${revokeParams.toString()}`

    const response = await fetch(url, { method: 'POST', })

    return response.ok
  }

  async getUser(access_token: string) {
    const params = new URLSearchParams({ access_token })
    const user: GoogleProfile = await fetch(`${GOOGLE_ENDPOINTS.user}&${params.toString()}`)
      .then(res => res.json())

    return user
  }
}

export interface GoogleProfile extends Record<string, any> {
  aud: string
  azp: string
  email: string
  email_verified: boolean
  exp: number
  family_name: string
  given_name: string
  hd: string
  iat: number
  iss: string
  jti: string
  name: string
  nbf: number
  picture: string
  sub: string
}
