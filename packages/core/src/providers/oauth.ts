import * as oauth from 'oauth4webapi'
import * as checks from '../security/checks.js'
import { createCookiesOptions } from '../security/cookie.js'
import type { Cookie, CookiesOptions } from '../security/cookie.js'
import type { JWTOptions } from '../security/jwt.js'
import type { InternalRequest } from '../internal/request.js'
import type { InternalResponse } from '../internal/response.js'
import type { Awaitable, DeepPartial, Nullish, ProviderPages } from '../types.js'

type OAuthCheck = 'pkce' | 'state' | 'none' | 'nonce'

type TokenSet = Partial<oauth.OAuth2TokenEndpointResponse>

interface Endpoint<TContext = any, TResponse = any> {
  url: string
  params?: Record<string, unknown>
  request?: (context: TContext) => Awaitable<TResponse>
  conform?: (response: Response) => Awaitable<Response | Nullish>
}

export interface OAuthUserConfig<TProfile, TUser = TProfile> extends 
  DeepPartial<Omit<OAuthConfig<TProfile, TUser>, 'clientId' | 'clientSecret'>> 
{
  clientId: string
  clientSecret: string
  useSecureCookies?: boolean
}

export interface OAuthDefaultConfig<TProfile> extends 
  Pick<OAuthConfig<TProfile>, 'id' | 'endpoints'>,
  Omit<OAuthUserConfig<TProfile>, 'id' | 'endpoints'> {}

export interface OAuthConfig<TProfile, TUser = TProfile> {
  id: string
  clientId: string
  clientSecret: string
  client: oauth.Client
  jwt: JWTOptions
  cookies: CookiesOptions
  checks: OAuthCheck[]
  pages: ProviderPages
  endpoints: {
    authorization: Endpoint<OAuthProvider<TUser>>
    token: Endpoint<OAuthProvider<TUser>, TokenSet>
    userinfo: Endpoint<{ provider: OAuthProvider<TProfile, TUser>; tokens: TokenSet }, TProfile>
  }
  onAuth: (
    user: TProfile,
    context: OAuthProvider<TProfile, TUser>,
  ) => Awaitable<InternalResponse<TUser> | Nullish> | Nullish
}

export class OAuthProvider<TProfile, TUser = TProfile> {
  config: OAuthConfig<TProfile, TUser>

  authorizationServer: oauth.AuthorizationServer

  constructor(options: OAuthConfig<TProfile, TUser>) {
    this.config = options

    // OAuth doesn't use discovery for authorization server, only OIDC.
    this.authorizationServer = {
      issuer: 'auth.js',
      authorization_endpoint: options.endpoints.authorization.url,
      token_endpoint: options.endpoints.token.url,
      userinfo_endpoint: options.endpoints.userinfo.url,
    }
  }

  setJwtOptions(options: JWTOptions) {
    this.config.jwt = options
    return this
  }

  setCookiesOptions(options: CookiesOptions) {
    this.config.cookies = options
    return this
  }

  /**
   * Login the user.
   */
  async login(request: InternalRequest): Promise<InternalResponse> {
    const url = new URL(this.config.endpoints.authorization.url)

    const cookies: Cookie[] = []

    const params = this.config.endpoints.authorization.params ?? {}

    Object.entries(params).forEach(([key, value]) => {
      if (typeof value === 'string') {
        url.searchParams.set(key, value)
      }
    })

    if (!url.searchParams.has('redirect_uri')) {
      url.searchParams.set('redirect_uri', `${request.url.origin}${this.config.pages.callback.route}`)
    }

    if (this.config.checks?.includes('state')) {
      const [state, stateCookie] = await checks.state.create(this.config)
      url.searchParams.set('state', state)
      cookies.push(stateCookie)
    }

    if (this.config.checks?.includes('pkce')) {
      const [pkce, pkceCookie] = await checks.pkce.create(this.config)
      url.searchParams.set('code_challenge', pkce)
      url.searchParams.set('code_challenge_method', 'S256')
      cookies.push(pkceCookie)
    }

    if (this.config.checks?.includes('nonce')) {
      const [nonce, nonceCookie] = await checks.nonce.create(this.config)
      url.searchParams.set('nonce', nonce)
      cookies.push(nonceCookie)
    }

    return { status: 302, redirect: url.toString(), cookies }
  }

  /**
   * Callback after the user has logged in.
   */
  async callback(request: InternalRequest): Promise<InternalResponse> {
    const cookies: Cookie[] = []

    const [state, stateCookie] = await checks.state.use(request, this.config)

    if (stateCookie) cookies.push(stateCookie)

    const codeGrantParams = oauth.validateAuthResponse(
      this.authorizationServer,
      this.config.client,
      request.url.searchParams,
      state,
    )

    if (oauth.isOAuth2Error(codeGrantParams)) throw new Error(codeGrantParams.error_description)

    const [pkce, pkceCookie] = await checks.pkce.use(request, this.config)

    if (pkceCookie) cookies.push(pkceCookie)

    const initialCodeGrantResponse = await oauth.authorizationCodeGrantRequest(
      this.authorizationServer,
      this.config.client,
      codeGrantParams,
      `${request.url.origin}${this.config.pages.callback.route}`,
      pkce
    )

    const codeGrantResponse = 
      await this.config.endpoints.token.conform?.(initialCodeGrantResponse.clone())
      ?? initialCodeGrantResponse

    const challenges = oauth.parseWwwAuthenticateChallenges(codeGrantResponse)

    if (challenges) {
      challenges.forEach(challenge => { console.log("challenge", challenge) })
      throw new Error("TODO: Handle www-authenticate challenges as needed")
    }

    const tokens = await oauth.processAuthorizationCodeOAuth2Response(
      this.authorizationServer,
      this.config.client,
      codeGrantResponse,
    )

    if (oauth.isOAuth2Error(tokens)) throw new Error("TODO: Handle OAuth 2.0 response body error")

    const profile = 
      await (
        this.config.endpoints.userinfo.request?.({ provider: this, tokens }) ??
        oauth
          .userInfoRequest(this.authorizationServer, this.config.client, tokens.access_token)
          .then(response => response.json())
      )

    if (!profile) throw new Error("TODO: Handle missing profile")

    const processedResponse = (await this.config.onAuth(profile, this)) ?? {
      redirect: this.config.pages.callback.redirect,
      status: 302,
    }

    processedResponse.cookies ??= []
    processedResponse.cookies.push(...cookies)

    return processedResponse
  }
}

export function mergeOAuthOptions(
  userOptions: OAuthUserConfig<any, any>,
  defaultOptions: OAuthDefaultConfig<any>,
): OAuthConfig<any, any> {
  const id = userOptions.id ?? defaultOptions.id

  return {
    ...userOptions,
    ...defaultOptions,
    id,
    client: {
      ...defaultOptions.client,
      ...userOptions.client,
      client_id: userOptions.clientId,
      client_secret: userOptions.clientSecret,
    },
    onAuth: userOptions.onAuth ?? ((user) => ({ user, session: user })),
    checks: userOptions.checks ?? defaultOptions.checks ?? ['pkce'],
    pages: {
      login: {
        route: userOptions.pages?.login?.route ?? `/auth/login/${id}`,
        methods: userOptions.pages?.login?.methods ?? ['GET'],
      },
      callback: {
        route: userOptions.pages?.callback?.route ?? `/auth/callback/${id}`,
        methods: userOptions.pages?.callback?.methods ?? ['GET'],
        redirect: userOptions.pages?.callback?.redirect ?? '/',
      }
    },
    endpoints: { 
      authorization: {
        ...defaultOptions.endpoints.authorization,
        ...userOptions.endpoints?.authorization,
        params: {
          ...defaultOptions.endpoints?.authorization?.params,
          ...userOptions.endpoints?.authorization?.params,
          client_id: userOptions.clientId,
          response_type: 'code',
        }
      },
      token: { ...defaultOptions.endpoints.token, ...userOptions.endpoints?.token },
      userinfo: { ...defaultOptions.endpoints.userinfo, ...userOptions.endpoints?.userinfo }
    },
    jwt: { ...userOptions.jwt, secret: '' },
    cookies: createCookiesOptions(userOptions.useSecureCookies),
  }
}
