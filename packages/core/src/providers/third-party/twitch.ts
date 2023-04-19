import { OAuthProvider, mergeOAuthOptions } from '../core/oauth'
import type { OAuthProviderDefaultOptions, OAuthProviderUserOptions } from "../core/oauth"

interface TwitchProfile extends Record<string, any> {
  sub: string
  preferred_username: string
  email: string
  picture: string
}

const twitchDefaultOptions: OAuthProviderDefaultOptions<TwitchProfile> = {
  id: 'twitch',
  endpoints: {
    authorization: {
      url: 'https://id.twitch.tv/oauth2/authorize'
    },
    token: {
      url: 'https://id.twitch.tv/oauth2/token',
    },
    userinfo: {
      url: 'https://id.twitch.tv/oauth2/userinfo',
    }
  },
}

export class Twitch<TUser, TSession = TUser> extends OAuthProvider<TwitchProfile, TUser, TSession> {
  constructor(options: OAuthProviderUserOptions<TwitchProfile, TUser, TSession>) {
    super(mergeOAuthOptions(options, twitchDefaultOptions))
  }
}
