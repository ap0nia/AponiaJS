import type * as oauth from 'oauth4webapi'
import type { InternalResponse } from '../../internal/response'
import { Provider } from '.'

type Awaitable<T> = PromiseLike<T> | T

type OAuthCheck = 'pkce' | 'state' | 'none' | 'nonce'

type TokenSet = Partial<oauth.OAuth2TokenEndpointResponse | oauth.OpenIDTokenEndpointResponse>

interface Pages {
  login: string
  callback: string
}

interface Endpoint<TContext = any, TResponse = any> {
  url: string
  params?: Record<string, unknown>
  request?: (context: TContext) => Awaitable<TResponse>
  conform?: (response: Response) => Awaitable<Response | undefined>
}

/**
 * User options.
 * @external
 */
export interface OAuthProviderUserOptions<TUser, TProfile = TUser, TSession = TProfile> {
  id?: string
  clientId: string
  clientSecret: string
  client?: Partial<oauth.Client>
  onAuth?: (user: TUser) => InternalResponse<TProfile, TSession>
  checks?: OAuthCheck[]
  pages?: Partial<Pages>
  endpoints?: Partial<OAuthUserEndpoints<TUser, TSession>>
}

/**
 * Users can provide just a string URL for the endpoints.
 * @external
 */
interface OAuthUserEndpoints<TUser, TSession = TUser> {
  authorization: string | Endpoint<OAuthProvider<TUser, TSession>>
  token: string | Endpoint<OAuthProvider<TUser, TSession>, TokenSet>
  userinfo: string | Endpoint<{ provider: OAuthProvider<TUser, TSession>; tokenSet: TokenSet }, TSession>
}

/**
 * Internal options.
 * @internal
 */
export interface OAuthProviderOptions<TProfile, TUser = TProfile, TSession = TUser> {
  id: string
  clientId: string
  clientSecret: string
  client: oauth.Client
  onAuth: (user: TProfile) => InternalResponse<TUser, TSession>
  checks: OAuthCheck[]
  pages: Pages
  endpoints: OAuthEndpoints<TProfile, TSession>
}

/**
 * Internally, endpoints should be fully defined.
 * @internal
 */
interface OAuthEndpoints<TUser, TSession = TUser> {
  authorization: Endpoint<OAuthProvider<TUser, TSession>>
  token: Endpoint<OAuthProvider<TUser, TSession>, TokenSet>
  userinfo: Endpoint<{ provider: OAuthProvider<TUser, TSession>; tokenSet: TokenSet }, TSession>
}


/**
 * @param TProfile The user profile returned by the OAuth provider.
 * @param TUser User.
 * @param TSession Session.
 */
export class OAuthProvider<TProfile, TUser = TProfile, TSession = TUser> {
  id: string

  type = "oauth" as const

  clientId: string

  clientSecret: string

  client: oauth.Client

  checks: OAuthCheck[]

  pages: Pages

  endpoints: OAuthEndpoints<TProfile, TSession>

  onAuth: (user: TProfile) => InternalResponse<TUser, TSession>

  constructor(options: OAuthProviderOptions<TProfile, TUser, TSession>) {
    this.id = options.id
    this.clientId = options.clientId
    this.clientSecret = options.clientSecret
    this.client = options.client
    this.checks = options.checks
    this.pages = options.pages
    this.endpoints = options.endpoints
    this.onAuth = options.onAuth
  }
}

interface TwitchProfile extends Record<string, any> {
  sub: string
  preferred_username: string
  email: string
  picture: string
}

export class Twitch<TUser, TSession = TUser> extends OAuthProvider<TwitchProfile, TUser, TSession> {
  constructor(o: OAuthProviderUserOptions<TwitchProfile, TUser, TSession>) {
    const id = o.id ?? 'twitch'
    super({
      ...o,
      id,
      client: {
        ...o.client,
        client_id: o.clientId,
        client_secret: o.clientSecret,
      },
      checks: o.checks ?? ['pkce'],
      pages: {
        login: o.pages?.login ?? `/auth/login/${id}`,
        callback: o.pages?.callback ?? `/auth/callback/${id}`,
      },
      endpoints: {
        authorization: { 
          url: ''
        },
        token: {
          url: ''
        },
        userinfo: {
          url: ''
        }
      },
      onAuth(profile) {
        return { user: profile, session: profile } as any
      },
    })
  }
}


export let y: Provider<any, { black: boolean }, {}>[] = []
y.push(new Twitch({
  clientId: '123',
  clientSecret: '123',
  onAuth(t) {
    return { user: { black: true }, session: { } }
  }
}))
