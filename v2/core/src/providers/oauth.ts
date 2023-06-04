import { defu } from 'defu'
import * as oauth from 'oauth4webapi'
import * as checks from '../security/checks.js'
import type { JWTOptions } from '../security/jwt.js'
import { createCookiesOptions } from '../security/cookie.js'
import type { Cookie, CookiesOptions } from '../security/cookie.js'
import type { Awaitable, DeepPartial, Nullish, ProviderPages } from '../types.js'

type OAuthCheck = 'pkce' | 'state' | 'none' | 'nonce'

type TokenSet = Partial<oauth.OAuth2TokenEndpointResponse>

interface Endpoint<TContext = any, TResponse = any> {
  url: string
  params?: Record<string, unknown>
  request?: (context: TContext) => Awaitable<TResponse>
  conform?: (response: Response) => Awaitable<Response | Nullish>
}

/**
 * Internal OAuth configuration.
 */
export interface OAuthConfig<TProfile> {
  id: string
  clientId: string
  clientSecret: string
  client: oauth.Client
  jwt: JWTOptions
  cookies: CookiesOptions
  checks: OAuthCheck[]
  pages: ProviderPages
  endpoints: {
    authorization: Endpoint<OAuthProvider<TProfile>>
    token: Endpoint<OAuthProvider<TProfile>, TokenSet>
    userinfo: Endpoint<{ provider: OAuthProvider<TProfile>; tokens: TokenSet }, TProfile>
  }
  onAuth: (
    user: TProfile,
    context: OAuthProvider<TProfile>,
  ) => Awaitable<AponiaAuth.InternalResponse | Nullish> | Nullish
}

/**
 * OAuth user configuration.
 */
export interface OAuthUserConfig<TProfile> extends
  DeepPartial<Omit<OAuthConfig<TProfile>, 'clientId' | 'clientSecret'>> {
  clientId: string
  clientSecret: string
  useSecureCookies?: boolean
}

/**
 * Pre-defined OAuth default configuration.
 */
export interface OAuthDefaultConfig<TProfile> extends
  Pick<OAuthConfig<TProfile>, 'id' | 'endpoints'>,
  Omit<OAuthUserConfig<TProfile>, 'id' | 'endpoints' | 'clientId' | 'clientSecret'> { }

/**
 * OAuth provider.
 */
export class OAuthProvider<TProfile> {
  config: OAuthConfig<TProfile>

  authorizationServer: oauth.AuthorizationServer

  constructor(options: OAuthConfig<TProfile>) {
    this.config = options

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
   * Handle OAuth login request.
   */
  async login(request: AponiaAuth.InternalRequest): Promise<AponiaAuth.InternalResponse> {
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
   * Handle OAuth callback request.
   */
  async callback(request: AponiaAuth.InternalRequest): Promise<AponiaAuth.InternalResponse> {
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

/**
 * Merge user and pre-defined default OAuth options.
 */
export function mergeOAuthOptions(
  userOptions: OAuthUserConfig<any>,
  defaultOptions: OAuthDefaultConfig<any>,
): OAuthConfig<any> {
  const id = userOptions.id ?? defaultOptions.id

  return defu(defaultOptions, userOptions, {
    id,
    client: {
      client_id: userOptions.clientId,
      client_secret: userOptions.clientSecret,
    },
    jwt: {
      secret: ''
    },
    cookies: createCookiesOptions(userOptions.useSecureCookies),
    checks: ['pkce'] as OAuthCheck[],
    pages: {
      login: {
        route: `/auth/login/${id}`,
        methods: ['GET'],
      },
      callback: {
        route: `/auth/callback/${id}`,
        methods: ['GET'],
        redirect: '/',
      }
    },
    endpoints: {
      authorization: {
        params: {
          response_type: 'code',
        }
      },
    },
    onAuth: ((user: any) => ({ user, session: user })),
  })
}
