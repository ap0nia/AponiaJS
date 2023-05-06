import * as oauth from 'oauth4webapi'
import * as checks from '../security/checks.js'
import { createCookiesOptions } from '../security/cookie.js'
import type { Cookie, CookiesOptions } from '../security/cookie.js'
import type { JWTOptions } from '../security/jwt.js'
import type { InternalRequest } from '../internal/request.js'
import type { InternalResponse } from '../internal/response.js'
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
export interface OIDCConfig<T> {
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
    authorization: Endpoint<OIDCProvider<T>>
    token: Endpoint<OIDCProvider<T>, TokenSet>
    userinfo: Endpoint<{ provider: OIDCProvider<T>; tokens: TokenSet }, T>
  }
  onAuth: (
    user: T,
    context: OIDCProvider<T>,
  ) => Awaitable<InternalResponse | Nullish> | Nullish
}

/**
 * OIDC user configuration.
 */
export interface OIDCUserConfig<T> extends 
  DeepPartial<Omit<OIDCConfig<T>, 'clientId' | 'clientSecret'>> {
  clientId: string
  clientSecret: string
  useSecureCookies?: boolean
}

/**
 * Pre-defined OIDC default configuration.
 */
export interface OIDCDefaultConfig<T> extends 
  Pick<OIDCConfig<T>, 'id' | 'issuer'>,
  Omit<OIDCUserConfig<T>, 'id' | 'issuer' | 'clientId' | 'clientSecret'> {}

/**
 * OIDC provider.
 */
export class OIDCProvider<T> {
  config: OIDCConfig<T>

  authorizationServer: oauth.AuthorizationServer

  constructor(options: OIDCConfig<T>) {
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
  async login(request: InternalRequest): Promise<InternalResponse> {
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
  async callback(request: InternalRequest): Promise<InternalResponse> {
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

    const result = await oauth.processAuthorizationCodeOpenIDResponse(
      this.authorizationServer,
      this.config.client,
      codeGrantResponse,
      nonce,
    )

    if (oauth.isOAuth2Error(result)) throw new Error("TODO: Handle OIDC response body error")

    const profile = oauth.getValidatedIdTokenClaims(result) as T

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
 * Merges the user options with the pre-defined default options.
 */
export function mergeOIDCOptions(
  userOptions: OIDCUserConfig<any>,
  defaultOptions: OIDCDefaultConfig<any>,
): OIDCConfig<any> {
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
        ...defaultOptions.endpoints?.authorization,
        ...userOptions.endpoints?.authorization,
        params: {
          ...defaultOptions.endpoints?.authorization?.params,
          ...userOptions.endpoints?.authorization?.params,
          client_id: userOptions.clientId,
          response_type: 'code',
        }
      },
      token: { ...defaultOptions.endpoints?.token, ...userOptions.endpoints?.token },
      userinfo: { ...defaultOptions.endpoints?.userinfo, ...userOptions.endpoints?.userinfo }
    },
    jwt: { ...userOptions.jwt, secret: '' },
    cookies: createCookiesOptions(userOptions.useSecureCookies),
  }
}
