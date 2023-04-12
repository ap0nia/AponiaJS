import * as oauth from 'oauth4webapi'
import type { OAuthConfig, ProviderConfig } from '.'

/**
 * https://docs.github.com/en/rest/overview/authenticating-to-the-rest-api?apiVersion=2022-11-28#using-basic-authentication
 */
export function generateBasicAuthHeader(clientId: string, clientSecret: string) {
  const encodedCredentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
  return `Basic ${encodedCredentials}`
}


export const GITHUB_ENDPOINTS = {
  authorization: 'https://github.com/login/oauth/authorize',
  access_token: 'https://github.com/login/oauth/access_token',
  user: 'https://api.github.com/user',
  email: 'https://api.github.com/user/emails',
  revoke: 'https://api.github.com/applications/{client_id}/token',
} as const


export class Github implements ProviderConfig<GitHubUser> {
  id = 'github'
  type: ProviderConfig<GitHubUser>['type'] = 'oauth'
  config: OAuthConfig

  constructor(config: OAuthConfig) {
    this.config = config
  }

  getAuthorizationUrl() {
    const state = oauth.generateRandomState()

    const authorizationParams = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: this.config.scope?.join(' ') || '',
      state,
    })

    const authorizationUrl = `${GITHUB_ENDPOINTS.authorization}?${authorizationParams.toString()}`

    return [authorizationUrl, state] as const
  }

  async getTokens(code: string) {
    const tokenParams = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
    })

    const tokens = await fetch(`${GITHUB_ENDPOINTS.access_token}?${tokenParams.toString()}`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
      },
    }).then(res => res.json())

    return tokens
  }

  async revokeToken(access_token: string) {
    const url = `https://api.github.com/applications/${this.config.clientId}/grant`

    const response = await fetch(url, {
      method: 'DELETE',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: generateBasicAuthHeader(this.config.clientId, this.config.clientSecret)
      },
      body: JSON.stringify({ access_token })
    })

    return response.ok
  }

  async getUser(access_token: string) {
    const user: GitHubUser = await fetch(GITHUB_ENDPOINTS.user, {
      method: 'GET',
      headers: {
        Authorization: `token ${access_token}`,
      },
    }).then(res => res.json())

    if (user.email == null) {
      const emails: GitHubEmail[] = await fetch(GITHUB_ENDPOINTS.email).then(res => res.json())
      user.email = (emails.find((e) => e.primary) ?? emails[0]).email
    }

    return user
  }
}

export interface GitHubEmail {
  email: string
  primary: boolean
  verified: boolean
  visibility: "public" | "private"
}

/** 
 * @see [Get the authenticated user](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)
 */
export interface GitHubUser {
  login: string
  id: number
  node_id: string
  avatar_url: string
  gravatar_id: string | null
  url: string
  html_url: string
  followers_url: string
  following_url: string
  gists_url: string
  starred_url: string
  subscriptions_url: string
  organizations_url: string
  repos_url: string
  events_url: string
  received_events_url: string
  type: string
  site_admin: boolean
  name: string | null
  company: string | null
  blog: string | null
  location: string | null
  email: string | null
  hireable: boolean | null
  bio: string | null
  twitter_username?: string | null
  public_repos: number
  public_gists: number
  followers: number
  following: number
  created_at: string
  updated_at: string
  private_gists?: number
  total_private_repos?: number
  owned_private_repos?: number
  disk_usage?: number
  suspended_at?: string | null
  collaborators?: number
  two_factor_authentication: boolean
  plan?: {
    collaborators: number
    name: string
    space: number
    private_repos: number
  }
}
