import * as oauth from 'oauth4webapi'
import type { OAuthConfig, OAuthUserConfig } from '@auth/core/providers'
import type { Awaitable, TokenSet } from '@auth/core/types'
import * as checks from '../security/checks'
import { merge } from '../utils/merge'
import { defaultProfile } from '../utils/profile'
import type { JWTOptions } from '../security/jwt'
import type { Mutable } from '../utils/mutable'
import type { InternalRequest } from '../internal/request'
import type { InternalCookie, InternalResponse } from '../internal/response'
import type { InternalCookiesOptions } from '../security/cookie'

interface Pages {
  signIn: string
  signOut: string
  callback: string
}

type Config<T> = OAuthConfig<T> & { options?: OAuthUserConfig<T> }

interface Options<T> {
  /**
   * Set the callbacks for the provider.
   */
  onAuth?: (profile: T, tokens: TokenSet, provider: OAuthProvider<T>) => Awaitable<InternalResponse | void>
}

export class OAuthProvider<T> {
  type = 'oauth' as const

  initialized?: boolean

  config: Required<OAuthConfig<T>>

  provider: OAuthConfig<any>

  client: oauth.Client

  authorizationServer: Mutable<oauth.AuthorizationServer>

  jwt: JWTOptions

  cookies: InternalCookiesOptions

  pages: Pages

  onAuth?: (profile: T, tokens: TokenSet, provider: OAuthProvider<T>) => Awaitable<InternalResponse | void>

  oauthFlow: {
    authorization: { 
      url: URL
    }
    token: {
      url: URL
      conform: (response: Response) => Awaitable<Response>
    }
    userinfo: {
      url: URL
      request: (context: { tokens: TokenSet, provider: OAuthConfig<any> }) => Awaitable<T>
    }
  }

  constructor(provider: Config<T>, options: Partial<Options<T>> = {}) {
    this.authorizationServer = Object.create(null)
    this.jwt = Object.create(null)
    this.cookies = Object.create(null)
    this.pages = Object.create(null)
    this.oauthFlow = Object.create(null)

    this.onAuth = options.onAuth

    this.config = merge(provider, provider.options)
    this.config.checks ??= ['pkce']
    this.config.profile ??= defaultProfile

    this.provider = provider

    this.client = {
      client_id: provider.clientId ?? '',
      client_secret: provider.clientSecret ?? '',
      ...provider.client,
    }
  }

  setPages(pages: Partial<Pages>) {
    this.pages = {
      signIn: `${pages.signIn ?? '/auth/login'}/${this.config.id}`,
      signOut: `${pages.signOut ?? '/auth/logout'}/${this.config.id}`,
      callback: `${pages.callback ?? '/auth/callback'}/${this.config.id}`
    }
  }

  setCookiesOptions(options: InternalCookiesOptions) {
    this.cookies = options
  }

  setJWTOptions(options: JWTOptions) {
    this.jwt = options
  }

  async initializeAuthorizationServer() {
    if (!this.config.issuer) {
      this.authorizationServer = { issuer: 'authjs.dev' }
      return
    }
    const issuer = new URL(this.config.issuer)
    const discoveryResponse = await oauth.discoveryRequest(issuer)
    this.authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)
  }

  async initialize() {
    await this.initializeAuthorizationServer()

    const authorizationUrl = typeof this.config.authorization === 'string' 
      ? new URL(this.config.authorization) 
      : this.config.authorization?.url
      ? new URL(this.config.authorization.url)
      : this.authorizationServer.authorization_endpoint
      ? new URL(this.authorizationServer.authorization_endpoint)
      : undefined

    if (!authorizationUrl) throw new TypeError('Invalid authorization endpoint')

    const params = {
      response_type: "code",
      client_id: this.config.clientId ?? '',
      ...(typeof this.config.authorization === 'object' && this.config.authorization?.params),
    }

    Object.entries(params).forEach(([key, value]) => {
      if (typeof value === 'string') {
        authorizationUrl.searchParams.set(key, value)
      }
    })

    const tokenUrl = typeof this.config.token === 'string' 
      ? new URL(this.config.token)
      : this.authorizationServer.token_endpoint
      ? new URL(this.authorizationServer.token_endpoint)
      : undefined

    if (!tokenUrl) throw new TypeError('Invalid token endpoint')

    const userinfoUrl = typeof this.config.userinfo === 'string'
      ? new URL(this.config.userinfo)
      : this.config.userinfo?.url
      ? new URL(this.config.userinfo.url)
      : this.authorizationServer.userinfo_endpoint
      ? new URL(this.authorizationServer.userinfo_endpoint)
      : this.config.userinfo?.request
      ? new URL('placeholder-url:The provided request method will be used instead')
      : undefined

    if (!userinfoUrl) throw new TypeError('Invalid userinfo endpoint')

    this.oauthFlow.authorization = { url: authorizationUrl }

    this.oauthFlow.token = {
      url: tokenUrl,
      conform: typeof this.config.token === 'object' 
        ? (this.config.token as any).conform 
        : (response) => response
    }

    this.oauthFlow.userinfo = {
      url: userinfoUrl,
      request: async (context) => {
        if (!context.tokens.access_token) throw new TypeError('Invalid token response')

        const request = typeof this.config.userinfo === 'object' && this.config.userinfo.request 
          ? this.config.userinfo.request(context)
          : oauth.userInfoRequest(
            this.authorizationServer,
            this.client,
            context.tokens.access_token
          ).then(res => res.json())

        return request
      }
    }

    this.authorizationServer.authorization_endpoint = authorizationUrl.toString()
    this.authorizationServer.token_endpoint = tokenUrl.toString()
    this.authorizationServer.userinfo_endpoint = userinfoUrl.toString()

    this.initialized = true
  }

   async signIn(request: InternalRequest): Promise<InternalResponse> {
    if (!this.initialized) await this.initialize()

    const cookies: InternalCookie[] = []
    const { url } = this.oauthFlow.authorization

    if (this.config.checks?.includes('state')) {
      const [state, stateCookie] = await checks.state.create(this)
      url.searchParams.set('state', state)
      cookies.push(stateCookie)
    }

    if (this.config.checks?.includes('pkce')) {
      if (!this.authorizationServer.code_challenge_methods_supported?.includes('S256')) {
        this.config.checks = ['nonce']
      } else {
        const [pkce, pkceCookie] = await checks.pkce.create(this)
        url.searchParams.set('code_challenge', pkce)
        url.searchParams.set('code_challenge_method', 'S256')
        cookies.push(pkceCookie)
      }
    }

    if (this.config.checks?.includes('nonce')) {
      const [nonce, nonceCookie] = await checks.nonce.create(this)
      url.searchParams.set('nonce', nonce)
      cookies.push(nonceCookie)
    }

    if (!url.searchParams.has('redirect_uri')) {
      url.searchParams.set('redirect_uri', `${request.url.origin}${this.pages.callback}`)
    }

    return { status: 302, redirect: url.toString(), cookies }
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    if (!this.initialized) await this.initialize()

    const cookies: InternalCookie[] = []

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
      pkce
    )

    const codeGrantResponse = await this.oauthFlow.token.conform(initialCodeGrantResponse.clone())

    const challenges = oauth.parseWwwAuthenticateChallenges(codeGrantResponse)

    if (challenges) {
      challenges.forEach(challenge => { 
        console.log("challenge", challenge)
      })
      throw new Error("TODO: Handle www-authenticate challenges as needed")
    }

    const tokens = await oauth.processAuthorizationCodeOAuth2Response(
      this.authorizationServer,
      this.client,
      codeGrantResponse,
    )

    if (oauth.isOAuth2Error(tokens)) throw new Error("TODO: Handle OAuth 2.0 response body error")

    const profile = await this.oauthFlow.userinfo.request({ tokens, provider: this.provider })

    if (!profile) throw new Error("TODO: Handle missing profile")

    const session = await this.config.profile(profile, tokens)

    return { session, redirect: '/', status: 302 }
  }
}
