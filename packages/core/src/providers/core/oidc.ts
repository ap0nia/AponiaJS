import * as oauth from 'oauth4webapi'
import * as checks from '../../security/checks'
import { createCookiesOptions } from '../../security/cookie'
import type { Cookie, CookiesOptions } from '../../security/cookie'
import type { JWTOptions } from '../../security/jwt'
import type { InternalRequest } from '../../internal/request'
import type { InternalResponse } from '../../internal/response'

type Awaitable<T> = PromiseLike<T> | T

type OIDCCheck = 'pkce' | 'state' | 'none' | 'nonce'

type Tokens = Partial<oauth.OAuth2TokenEndpointResponse>

interface Pages {
  login: string
  callback: string
}

interface Endpoint<TContext = any, TResponse = any> {
  params?: Record<string, unknown>
  request?: (context: TContext) => Awaitable<TResponse>
  conform?: (response: Response) => Awaitable<Response | undefined>
}

export interface OIDCDefaultConfig<TProfile> {
  id: string
  issuer: string
  client?: Partial<oauth.Client>
  endpoints?: Partial<OIDCEndpoints<TProfile, any>>
  checks?: OIDCCheck[]
}

/**
 * User options. Several can be omitted and filled in by the provider's default options.
 * @external
 */
export interface OIDCUserConfig<TProfile, TUser = TProfile> {
  /**
   * Unique ID for the provider.
   */
  id?: string
  
  /**
   * Client ID for the provider.
   */
  clientId: string

  /**
   * Client secret for the provider.
   */
  clientSecret: string

  /**
   * Override the default OAuth client.
   */
  client?: Partial<oauth.Client>

  /**
   * A function that is called when the user is authenticated.
   */
  onAuth?: (user: TProfile) => Awaitable<InternalResponse<TUser>>

  /**
   * Checks to perform.
   */
  checks?: OIDCCheck[]

  /**
   * Pages to use.
   */
  pages?: Partial<Pages>

  /**
   * Endpoints to use.
   */
  endpoints?: Partial<OIDCUserEndpoints<TProfile, TUser>>

  /**
   * JWT options.
   */
  jwt?: Partial<JWTOptions>

  /**
   * Whether to use secure cookies.
   */
  useSecureCookies?: boolean
}

/**
 * Users can also provide just a string URL for the endpoints.
 * @external
 */
interface OIDCUserEndpoints<TProfile, TUser = TProfile> {
  authorization: string | Endpoint<OIDCProvider<TProfile, TUser>>
  token: string | Endpoint<OIDCProvider<TProfile, TUser>, Tokens>
  userinfo: string | Endpoint<{ provider: OIDCProvider<TProfile, TUser>; tokens: Tokens }, TProfile>
}

/**
 * Internal options. All options are generally defined.
 * @internal
 */
export interface OIDCConfig<TProfile, TUser = TProfile> {
  id: string
  issuer: string
  clientId: string
  clientSecret: string
  client: oauth.Client
  jwt: JWTOptions
  cookies: CookiesOptions
  checks: OIDCCheck[]
  pages: Pages
  endpoints?: Partial<OIDCEndpoints<TProfile, TUser>>
  onAuth: (user: TProfile) => Awaitable<InternalResponse<TUser>>
}

/**
 * Internally, endpoints shouldn't be strings.
 * @internal
 */
interface OIDCEndpoints<TProfile, TUser = TProfile> {
  authorization: Endpoint<OIDCProvider<TProfile, TUser>>
  token: Endpoint<OIDCProvider<TProfile, TUser>, Tokens>
  userinfo: Endpoint<{ provider: OIDCProvider<TProfile, TUser>; tokens: Tokens }, TProfile>
}

/**
 * @param TProfile The user profile returned by the OAuth provider.
 * @param TUser User.
 * @param TSession Session.
 */
export class OIDCProvider<TProfile, TUser = TProfile> implements OIDCConfig<TProfile, TUser> {
  initialized?: boolean

  id: string

  type = "oidc" as const

  issuer: string

  clientId: string

  clientSecret: string

  client: oauth.Client

  authorizationServer: oauth.AuthorizationServer

  jwt: JWTOptions

  cookies: CookiesOptions

  checks: OIDCCheck[]

  pages: Pages

  endpoints?: Partial<OIDCEndpoints<TProfile, TUser>>

  onAuth: (user: TProfile) => Awaitable<InternalResponse<TUser>>

  constructor(options: OIDCConfig<TProfile, TUser>) {
    this.id = options.id
    this.issuer = options.issuer
    this.clientId = options.clientId
    this.clientSecret = options.clientSecret
    this.client = options.client
    this.jwt = options.jwt
    this.cookies = options.cookies
    this.checks = options.checks
    this.pages = options.pages
    this.endpoints = options.endpoints
    this.onAuth = options.onAuth

    // OAuth doesn't use discovery for authorization server, only OIDC.
    this.authorizationServer = { issuer: options.issuer }
    this.initialized = false
  }

  setJwtOptions(options: JWTOptions) {
    this.jwt = options
    return this
  }

  setCookiesOptions(options: CookiesOptions) {
    this.cookies = options
    return this
  }

  async initialize() {
    const issuer = new URL(this.authorizationServer.issuer)
    const discoveryResponse = await oauth.discoveryRequest(issuer)
    const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

    const supportsPKCE = authorizationServer.code_challenge_methods_supported?.includes('S256')
    if (this.checks?.includes('pkce') && !supportsPKCE) {
      this.checks = ['nonce']
    }

    this.authorizationServer = authorizationServer
  }

  /**
   * Login the user.
   */
  async login(request: InternalRequest): Promise<InternalResponse> {
    if (!this.initialized) await this.initialize()

    if (!this.authorizationServer.authorization_endpoint) {
      throw new TypeError(`Invalid authorization endpoint. ${this.authorizationServer.authorization_endpoint}`)
    }

    const url = new URL(this.authorizationServer.authorization_endpoint)
    const cookies: Cookie[] = []

    Object.entries(this.endpoints?.authorization?.params ?? {}).forEach(([key, value]) => {
      if (typeof value === 'string') {
        url.searchParams.set(key, value)
      }
    })

    if (this.checks?.includes('state')) {
      const [state, stateCookie] = await checks.state.create(this)
      url.searchParams.set('state', state)
      cookies.push(stateCookie)
    }

    if (this.checks?.includes('pkce')) {
      const [pkce, pkceCookie] = await checks.pkce.create(this)
      url.searchParams.set('code_challenge', pkce)
      url.searchParams.set('code_challenge_method', 'S256')
      cookies.push(pkceCookie)
    }

    if (this.checks?.includes('nonce')) {
      const [nonce, nonceCookie] = await checks.nonce.create(this)
      url.searchParams.set('nonce', nonce)
      cookies.push(nonceCookie)
    }

    if (!url.searchParams.has('redirect_uri')) {
      url.searchParams.set('redirect_uri', `${request.url.origin}${this.pages.callback}`)
    }

    if (!url.searchParams.has('scope')) {
      url.searchParams.set("scope", "openid profile email")
    }

    return { status: 302, redirect: url.toString(), cookies }
  }

  /**
   * Callback after the user has logged in.
   */
  async callback(request: InternalRequest): Promise<InternalResponse> {
    if (!this.initialized) await this.initialize()

    const cookies: Cookie[] = []

    const [state, stateCookie] = await checks.state.use(request, this)

    if (stateCookie) cookies.push(stateCookie)

    const codeGrantParams = oauth.validateAuthResponse(
      this.authorizationServer,
      this.client,
      request.url.searchParams,
      state,
    )

    if (oauth.isOAuth2Error(codeGrantParams)) throw new Error(codeGrantParams.error_description)

    const [pkce, pkceCookie] = await checks.pkce.use(request, this)

    if (pkceCookie) cookies.push(pkceCookie)

    const initialCodeGrantResponse = await oauth.authorizationCodeGrantRequest(
      this.authorizationServer,
      this.client,
      codeGrantParams,
      `${request.url.origin}${this.pages.callback}`,
      pkce,
    )

    const codeGrantResponse = 
      await this.endpoints?.token?.conform?.(initialCodeGrantResponse.clone())
      ?? initialCodeGrantResponse

    const challenges = oauth.parseWwwAuthenticateChallenges(codeGrantResponse)

    if (challenges) {
      challenges.forEach(challenge => { console.log("challenge", challenge) })
      throw new Error("TODO: Handle www-authenticate challenges as needed")
    }

    const [nonce, nonceCookie] = await checks.nonce.use(request, this)

    if (nonceCookie) cookies.push(nonceCookie)

    const result = await oauth.processAuthorizationCodeOpenIDResponse(
      this.authorizationServer,
      this.client,
      codeGrantResponse,
      nonce,
    )

    if (oauth.isOAuth2Error(result)) throw new Error("TODO: Handle OIDC response body error")

    const profile = oauth.getValidatedIdTokenClaims(result) as TProfile

    const processedResponse = await this.onAuth(profile)
    processedResponse.cookies ??= []
    processedResponse.cookies.push(...cookies)

    return processedResponse
  }
}


/**
 * Merge user options with default options.
 */
export function mergeOIDCOptions(
  userOptions: OIDCUserConfig<any, any>,
  defaultOptions: OIDCDefaultConfig<any>,
): OIDCConfig<any, any> {
  const id = userOptions.id ?? defaultOptions.id

  const authorizationOptions = typeof userOptions.endpoints?.authorization === 'object'
    ? userOptions.endpoints.authorization
    : {}

  const tokenOptions = typeof userOptions.endpoints?.token === 'object'
    ? userOptions.endpoints.token
    : {}

  const userinfoOptions = typeof userOptions.endpoints?.userinfo === 'object'
    ? userOptions.endpoints.userinfo
    : {}

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
      login: userOptions.pages?.login ?? `/auth/login/${id}`,
      callback: userOptions.pages?.callback ?? `/auth/callback/${id}`,
    },
    endpoints: {
      authorization: {
        ...defaultOptions.endpoints?.authorization,
        ...authorizationOptions,
        params: {
          ...defaultOptions.endpoints?.authorization?.params,
          ...authorizationOptions.params,
          client_id: userOptions.clientId,
          response_type: 'code',
        },
      },
      token: {
        ...defaultOptions.endpoints?.token,
        ...tokenOptions,
      },
      userinfo: {
        ...defaultOptions.endpoints?.userinfo,
        ...userinfoOptions,
      },
    },
    // default cookie options, manually set later if needed.
    cookies: createCookiesOptions(userOptions.useSecureCookies),

    // default jwt options, manually set later if needed.
    jwt: {
      ...userOptions.jwt,
      secret: ''  // invalid secret: make sure to set it later if using JWT.
    },

  }
}

