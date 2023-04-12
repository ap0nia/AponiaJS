import * as oauth from 'oauth4webapi'
import type { OAuthConfig, ProviderConfig } from '.'

export const GOOGLE_ENDPOINTS = {
  authorization: 'https://accounts.google.com/o/oauth2/v2/auth',
  access_token: 'https://oauth2.googleapis.com/token',
  user: 'https://api.github.com/user',
  email: 'https://api.github.com/user/emails',
  revoke: 'https://oauth2.googleapis.com/revoke',
} as const

export class Google implements ProviderConfig<GoogleProfile> {
  id = 'google'
  type: ProviderConfig<GoogleProfile>['type'] = 'oidc'
  config: OAuthConfig

  constructor(config: OAuthConfig) {
    this.config = config
  }

  getAuthorizationUrl () {
    const state = oauth.generateRandomState()

    const authorizationParams = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: this.config.scope?.join(' ') || '',
      state,
    })

    const authorizationUrl = `${GOOGLE_ENDPOINTS.authorization}?${authorizationParams.toString()}`

    return [authorizationUrl, state] as const
  }

  async getTokens(code: string) {
    const tokenParams = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
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
    const user: GoogleProfile = await fetch(GOOGLE_ENDPOINTS.user, {
      method: 'GET',
      headers: {
        Authorization: `token ${access_token}`,
      },
    }).then(res => res.json())

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
