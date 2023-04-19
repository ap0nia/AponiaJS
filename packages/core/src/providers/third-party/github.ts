import { OAuthDefaultConfig, OAuthProvider, mergeOAuthOptions } from "../core/oauth"
import type { OAuthUserConfig } from "../core/oauth"

export interface GitHubEmail {
  email: string
  primary: boolean
  verified: boolean
  visibility: "public" | "private"
}

/** @see [Get the authenticated user](https://docs.github.com/en/rest/users/users#get-the-authenticated-user) */
export interface GitHubProfile {
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

export const GitHubOptions: OAuthDefaultConfig<GitHubProfile> = {
  id: 'github',
  endpoints: {
    authorization: {
      url: "https://github.com/login/oauth/authorize",
      params: { scope: "read:user user:email" },
    },
    token: {
      url: "https://github.com/login/oauth/access_token",
    },
    userinfo: {
      url: "https://api.github.com/user",
      request: async ({ tokens, provider }) => {
        const url = new URL(provider.endpoints.userinfo.url)
        const profile = await fetch(url, {
          headers: { Authorization: `Bearer ${tokens.access_token}`, 'User-Agent': 'authjs' },
        }).then(async (res) => await res.json())

        if (!profile.email) {
          // If the user does not have a public email, get another via the GitHub API
          // See https://docs.github.com/en/rest/users/emails#list-public-email-addresses-for-the-authenticated-user
          const res = await fetch("https://api.github.com/user/emails", {
            headers: { Authorization: `Bearer ${tokens.access_token}`, 'User-Agent': 'authjs' },
          })

          if (res.ok) {
            const emails: GitHubEmail[] = await res.json()
            profile.email = (emails.find((e) => e.primary) ?? emails[0]).email
          }
        }

        return profile
      },
    },
  }
}

export default function GitHub<TUser = GitHubProfile, TSession = TUser>(
  options: OAuthUserConfig<GitHubProfile, TUser, TSession>
): OAuthProvider<GitHubProfile, TUser, TSession> {
  return new OAuthProvider(mergeOAuthOptions(options, GitHubOptions))
}

