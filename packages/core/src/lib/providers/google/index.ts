import * as oauth from 'oauth4webapi'
import type { OAuthConfig, Provider } from '..'
import type { GoogleProfile } from './index.types'

export const GOOGLE_ENDPOINTS = {
  authorization: 'https://accounts.google.com/o/oauth2/v2/auth',
  access_token: 'https://oauth2.googleapis.com/token',
  user: 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json',
  revoke: 'https://oauth2.googleapis.com/revoke',
} as const

export interface GoogleOauthConfig<T> extends OAuthConfig {
  redirect_uri: string
  onAuth?: (user: GoogleProfile) => Promise<T>
}

export class Google<T = GoogleProfile> implements Provider<T> {
  id = 'google'

  type: Provider<T>['type'] = 'oidc'

  config: GoogleOauthConfig<T>

  constructor(config: GoogleOauthConfig<T>) {
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
  
  async logout(token: string) {
    const revokeParams = new URLSearchParams({ token })

    const url = `${GOOGLE_ENDPOINTS.revoke}?${revokeParams.toString()}`

    const response = await fetch(url, { method: 'POST', })

    return response.ok
  }

  async getUser(access_token: string) {
    const params = new URLSearchParams({ access_token })

    const user: GoogleProfile = await fetch(`${GOOGLE_ENDPOINTS.user}&${params.toString()}`)
      .then(res => res.json())

    return this.config.onAuth?.(user) ?? user as T
  }

  _authenticateRequestMethod = 'GET'

  async authenticateRequest(request: Request) {
    if (request.method !== this._authenticateRequestMethod) {
      throw new Error(`Invalid request method: ${request.method}`)
    }

    const code = new URL(request.url).searchParams.get('code')

    if (code == null) throw new Error('Invalid code')

    const tokens = await this.getTokens(code)

    const user = await this.getUser(tokens.access_token)

    return user
  }
}
