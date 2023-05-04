import * as oauth from 'oauth4webapi'
import * as checks from '../../security/checks.js'
import { createCookiesOptions } from '../../security/cookie.js'
import type { Cookie, CookiesOptions } from '../../security/cookie.js'
import type { JWTOptions } from '../../security/jwt.js'
import type { InternalRequest } from '../../internal/request.js'
import type { InternalResponse } from '../../internal/response.js'

type Nullish = null | undefined | void

type Awaitable<T> = PromiseLike<T> | T

type OIDCCheck = 'pkce' | 'state' | 'none' | 'nonce'

type Tokens = Partial<oauth.OAuth2TokenEndpointResponse>

interface Pages {
  login: {
    route: string
    methods: string[]
  }
  callback: {
    route: string
    methods: string[]
  }
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
  onAuth?: (user: TProfile) => Awaitable<InternalResponse<TUser> | Nullish>

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
  onAuth: (user: TProfile) => Awaitable<InternalResponse<TUser> | Nullish>
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

  onAuth: (user: TProfile) => Awaitable<InternalResponse<TUser> | Nullish>

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
  }

  setJwtOptions(options: JWTOptions) {
    this.jwt = options
    return this
  }

  setCookiesOptions(options: CookiesOptions) {
    this.cookies = options
    return this
  }

  /**
   * Set the OIDC provider's `authorizationServer`.
   * `authorizationServer` will not be valid on creation; it must be asynchronously initialized at least once.
   */
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
      url.searchParams.set('redirect_uri', `${request.url.origin}${this.pages.callback.route}`)
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
      `${request.url.origin}${this.pages.callback.route}`,
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

    const processedResponse = (await this.onAuth(profile)) || {}

    processedResponse.cookies ??= []

    processedResponse.cookies.push(...cookies)

    return processedResponse
  }
}

/**
 * Merge user provided OIDC provider options with the OIDC provider's default options.
 */
export function mergeOIDCOptions(
  userOptions: OIDCUserConfig<any, any>,
  defaultOptions: OIDCDefaultConfig<any>,
): OIDCConfig<any, any> {
  const id = userOptions.id ?? defaultOptions.id

  const client = {
    ...defaultOptions.client,
    ...userOptions.client,
    client_id: userOptions.clientId,
    client_secret: userOptions.clientSecret,
  }

  const authorization = typeof userOptions.endpoints?.authorization === 'object'
    ? { ...defaultOptions.endpoints?.authorization, ...userOptions.endpoints.authorization }
    : { ...defaultOptions.endpoints?.authorization }

  authorization.params = {
    ...defaultOptions.endpoints?.authorization?.params,
    ...authorization.params,
    client_id: userOptions.clientId,
    response_type: 'code',
  }

  const token = typeof userOptions.endpoints?.token === 'object'
    ? { ...defaultOptions.endpoints?.token, ...userOptions.endpoints.token }
    : { ...defaultOptions.endpoints?.token }

  const userinfo = typeof userOptions.endpoints?.userinfo === 'object'
    ? { ...defaultOptions.endpoints?.userinfo, ...userOptions.endpoints.userinfo }
    : { ...defaultOptions.endpoints?.userinfo }

  /** Default jwt options, manually set later if needed. */
  const jwt = { ...userOptions.jwt, secret: '' }

  /** Default cookie options, manually set later if needed. */
  const cookies = createCookiesOptions(userOptions.useSecureCookies)

  return {
    ...userOptions,
    ...defaultOptions,
    id,
    client,
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
      }
    },
    endpoints: { authorization, token, userinfo },
    cookies,
    jwt
  }
}
