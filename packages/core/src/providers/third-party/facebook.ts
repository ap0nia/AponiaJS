import { OAuthProvider, mergeOAuthOptions } from "../core/oauth"
import type { OAuthDefaultConfig, OAuthUserConfig } from "../core/oauth"

interface FacebookPictureData {
  url: string
}

interface FacebookPicture {
  data: FacebookPictureData
}

export interface FacebookProfile extends Record<string, any> {
  id: string
  picture: FacebookPicture
}

export const FacebookOptions: OAuthDefaultConfig<FacebookProfile> = {
  id: 'facebook',
  endpoints: {
    authorization: {
      url: "https://www.facebook.com/v15.0/dialog/oauth?scope=email",
    },
    token: {
      url: "https://graph.facebook.com/oauth/access_token",
    },
    userinfo: {
      // https://developers.facebook.com/docs/graph-api/reference/user/#fields
      url: "https://graph.facebook.com/me?fields=id,name,email,picture",
      request: async ({ tokens, provider }) => {
        const url = new URL(provider.endpoints.userinfo.url)
        return await fetch(url, {
          headers: { Authorization: `Bearer ${tokens.access_token}` },
        }).then(async (res) => await res.json())
      },
    }
  }
}

export default function Facebook<TUser = FacebookProfile, TSession = TUser>(
  options: OAuthUserConfig<FacebookProfile, TUser, TSession>
): OAuthProvider<FacebookProfile, TUser, TSession> {
  return new OAuthProvider(mergeOAuthOptions(options, FacebookOptions))
}

