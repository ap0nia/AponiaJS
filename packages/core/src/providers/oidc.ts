import { defu } from 'defu'
import * as oauth from 'oauth4webapi'
import * as checks from '../security/checks.js'
import type { JWTOptions } from '../security/jwt.js'
import { createCookiesOptions } from '../security/cookie.js'
import type { Cookie, CookiesOptions } from '../security/cookie.js'
import type { Awaitable, DeepPartial, Nullish, ProviderPages } from '../types.js'

type OIDCCheck = 'pkce' | 'state' | 'none' | 'nonce'

type TokenSet = Partial<oauth.OAuth2TokenEndpointResponse>

interface Endpoint<TContext = any, TResponse = any> {
  params?: Record<string, unknown>
  request?: (context: TContext) => Awaitable<TResponse>
  conform?: (response: Response) => Awaitable<Response | Nullish>
}

/**
 * Internal OIDC configuration.
 */
export interface OIDCConfig<TProfile> {
  id: string
  issuer: string
  client: oauth.Client
  clientId: string
  clientSecret: string
  jwt: JWTOptions
  cookies: CookiesOptions
  checks: OIDCCheck[]
  pages: ProviderPages
  endpoints: {
    authorization: Endpoint<OIDCProvider<TProfile>>
    token: Endpoint<OIDCProvider<TProfile>, TokenSet>
    userinfo: Endpoint<{ provider: OIDCProvider<TProfile>; tokens: TokenSet }, TProfile>
  }
  onAuth: (
    user: TProfile,
    tokens: oauth.OpenIDTokenEndpointResponse
  ) => Awaitable<Aponia.InternalResponse | Nullish> | Nullish
}

/**
 * OIDC user configuration.
 */
export interface OIDCUserConfig<TProfile> extends
  DeepPartial<Omit<OIDCConfig<TProfile>, 'clientId' | 'clientSecret'>> {
  clientId: string
  clientSecret: string
  useSecureCookies?: boolean
}

/**
 * Pre-defined OIDC default configuration.
 */
export interface OIDCDefaultConfig<TProfile> extends
  Pick<OIDCConfig<TProfile>, 'id' | 'issuer'>,
  Omit<OIDCUserConfig<TProfile>, 'id' | 'issuer' | 'clientId' | 'clientSecret'> { }

/**
 * OIDC provider.
 */
export class OIDCProvider<TProfile> {
  config: OIDCConfig<TProfile>

  authorizationServer: oauth.AuthorizationServer

  constructor(options: OIDCConfig<TProfile>) {
    this.config = options
    this.authorizationServer = { issuer: options.issuer }
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
   * Dynamically initialize OIDC authorization server.
   */
  async initialize() {
    const issuer = new URL(this.authorizationServer.issuer)

    const discoveryResponse = await oauth.discoveryRequest(issuer)

    const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

    const supportsPKCE = authorizationServer.code_challenge_methods_supported?.includes('S256')

    if (this.config.checks?.includes('pkce') && !supportsPKCE) {
      this.config.checks = ['nonce']
    }

    this.authorizationServer = authorizationServer
  }

  /**
   * Handle OAuth login request.
   */
  async login(request: Aponia.InternalRequest): Promise<Aponia.InternalResponse> {
    await this.initialize()

    if (!this.authorizationServer.authorization_endpoint) {
      throw new TypeError(`Invalid authorization endpoint. ${this.authorizationServer.authorization_endpoint}`)
    }

    const url = new URL(this.authorizationServer.authorization_endpoint)

    const cookies: Cookie[] = []

    Object.entries(this.config.endpoints?.authorization?.params ?? {}).forEach(([key, value]) => {
      if (typeof value === 'string') {
        url.searchParams.set(key, value)
      }
    })

    if (!url.searchParams.has('redirect_uri')) {
      url.searchParams.set('redirect_uri', `${request.url.origin}${this.config.pages.callback.route}`)
    }

    if (!url.searchParams.has('scope')) {
      url.searchParams.set("scope", "openid profile email")
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
  async callback(request: Aponia.InternalRequest): Promise<Aponia.InternalResponse> {
    await this.initialize()

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
      pkce,
    )

    const codeGrantResponse =
      await this.config.endpoints?.token?.conform?.(initialCodeGrantResponse.clone())
      ?? initialCodeGrantResponse

    const challenges = oauth.parseWwwAuthenticateChallenges(codeGrantResponse)

    if (challenges) {
      challenges.forEach(challenge => { console.log("challenge", challenge) })
      throw new Error("TODO: Handle www-authenticate challenges as needed")
    }

    const [nonce, nonceCookie] = await checks.nonce.use(request, this.config)

    if (nonceCookie) cookies.push(nonceCookie)

    const tokens = await oauth.processAuthorizationCodeOpenIDResponse(
      this.authorizationServer,
      this.config.client,
      codeGrantResponse,
      nonce,
    )

    if (oauth.isOAuth2Error(tokens)) throw new Error("TODO: Handle OIDC response body error")

    const profile = oauth.getValidatedIdTokenClaims(tokens) as TProfile

    const processedResponse = (await this.config.onAuth(profile, tokens)) ?? {
      redirect: this.config.pages.callback.redirect,
      status: 302,
    }

    processedResponse.cookies ??= []
    processedResponse.cookies.push(...cookies)

    return processedResponse
  }
}

/**
 * Merges the user options with the pre-defined default options.
 */
export function mergeOIDCOptions(
  userOptions: OIDCUserConfig<any>,
  defaultOptions: OIDCDefaultConfig<any>,
): OIDCConfig<any> {
  const id = userOptions.id ?? defaultOptions.id
  return defu(userOptions, {
    id,
    client: {
      client_id: userOptions.clientId,
      client_secret: userOptions.clientSecret,
    },
    jwt: {
      secret: ''
    },
    cookies: createCookiesOptions(userOptions.useSecureCookies),
    checks: ['pkce'] as OIDCCheck[],
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
          client_id: userOptions.clientId,
          response_type: 'code',
        }
      },
      token: {},
      userinfo: {},
    },
    onAuth: ((user: any) => ({ user, session: user })),
  }, defaultOptions)
}
