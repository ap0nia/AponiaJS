import * as oauth from 'oauth4webapi'
import { OAuthProvider, mergeOAuthOptions, type OAuthDefaultConfig, type OAuthUserConfig } from "aponia"

interface Identifier {
  identifier: string
}

interface Element {
  identifiers?: Identifier[]
}

export interface LinkedInProfile extends Record<string, any> {
  id: string
  localizedFirstName: string
  localizedLastName: string
  profilePicture: {
    "displayImage~": {
      elements?: Element[]
    }
  }
}

export const LinkedInOptions: OAuthDefaultConfig<LinkedInProfile> = {
  id: 'linkedin',
  client: {
    token_endpoint_auth_method: "client_secret_post",
  },
  endpoints: {
    authorization: {
      url: "https://www.linkedin.com/oauth/v2/authorization",
      params: { scope: "r_liteprofile r_emailaddress" },
    },
    token: {
      url: "https://www.linkedin.com/oauth/v2/accessToken",
    },
    userinfo: {
      url: "https://api.linkedin.com/v2/me",
      params: {
        projection: `(id,localizedFirstName,localizedLastName,profilePicture(displayImage~digitalmediaAsset:playableStreams))`,
      },
      request: async ({ provider, tokens }) => {
        if (!tokens.access_token) throw new TypeError("No access token")

        const profile = await oauth
          .userInfoRequest(provider.authorizationServer, provider.config.client, tokens.access_token)
          .then(response => response.json())

        const email: LinkedInProfile['profilePicture']['displayImage~'] = await fetch(
          "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
          { headers: { Authorization: `Bearer ${tokens.access_token}` } }
        ).then(res => res.json())

        return { ...profile, ...email }
      },
    },
  }
}

export function LinkedIn<TUser = LinkedInProfile>(
  options: OAuthUserConfig<LinkedInProfile, TUser>
): OAuthProvider<LinkedInProfile, TUser> {
  return new OAuthProvider(mergeOAuthOptions(options, LinkedInOptions))
}

