import { OIDCProvider, mergeOIDCOptions } from '../core/oidc'
import type { OIDCDefaultOptions, OIDCUserOptions } from '../core/oidc'

export interface TwitchProfile extends Record<string, any> {
  sub: string
  preferred_username: string
  email: string
  picture: string
}

export const TwitchOptions: OIDCDefaultOptions<TwitchProfile> = {
  id: 'twitch',
  issuer: 'https://id.twitch.tv/oauth2',
  client: { token_endpoint_auth_method: "client_secret_post" },
  endpoints: {
   authorization: {
      params: {
        scope: "openid user:read:email",
        claims: {
          id_token: { email: null, picture: null, preferred_username: null },
        },
      },
    },
    token: {
      conform: async (response) => {
        const body = await response.json()
        if (response.ok) {
          if (typeof body.scope === "string") {
            console.warn(
              "'scope' is a string. Redundant workaround, please open an issue."
            )
          } else if (Array.isArray(body.scope)) {
            body.scope = body.scope.join(" ")
            return new Response(JSON.stringify(body), response)
          } else if ("scope" in body) {
            delete body.scope
            return new Response(JSON.stringify(body), response)
          }
        } else {
          const { message: error_description, error } = body
          if (typeof error !== "string") {
            return new Response(
              JSON.stringify({ error: "invalid_request", error_description }),
              response
            )
          }
          console.warn(
            "Response has 'error'. Redundant workaround, please open an issue."
          )
        }
      },
    },
  }
}

export default function Twitch<TUser = TwitchProfile, TSession = TUser>(
  options: OIDCUserOptions<TwitchProfile, TUser, TSession>
): OIDCProvider<TwitchProfile, TUser, TSession> {
  return new OIDCProvider(mergeOIDCOptions(options, TwitchOptions))
}
