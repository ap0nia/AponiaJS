import { toInternalRequest } from "./request.js"
import type { InternalRequest } from "./request.js"
import type { InternalResponse } from "./response.js"
import type { SessionManager } from "../session.js"
import type { CredentialsProvider } from "../providers/credentials.js"
import type { EmailProvider } from "../providers/email.js"
import type { OAuthProvider } from "../providers/oauth.js"
import type { OIDCProvider } from "../providers/oidc.js"
import type { Awaitable, Nullish, PageEndpoint } from "../types.js"

type AnyProvider<T> = 
  | OAuthProvider<any, T> 
  | OIDCProvider<any, T> 
  | CredentialsProvider<T> 
  | EmailProvider<T>

/**
 * Static auth pages handled by the framework.
 */
interface AuthPages {
  /**
   * Log a user out.
   */
  logout: PageEndpoint

  /**
   * Update a user's info.
   */
  update: PageEndpoint

  /**
   * Submit a "forgot password" request.
   */
  forgot: PageEndpoint

  /**
   * Reset a user's password, i.e. after receiving a "forgot password" response.
   */
  reset: PageEndpoint
}

/**
 * Callbacks for static auth pages.
 */
type AuthCallbacks<T> = {
  [k in keyof AuthPages]?: (request: InternalRequest) => Awaitable<InternalResponse<T> | Nullish>
}

/**
 * Auth configuration.
 */
export interface AuthConfig<TUser, TSession = TUser, TRefresh = undefined> {
  /**
   * Session manager. Handles session creation, validation / decoding, and destruction.
   */
  session: SessionManager<TUser, TSession, TRefresh>

  /**
   * Providers to use for authentication.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Static auth pages.
   */
  pages?: Partial<AuthPages>

  /**
   * Callbacks for static auth pages.
   */
  callbacks?: Partial<AuthCallbacks<TUser>>
}

/**
 * Auth framework.
 */
export class Auth<TUser, TSession, TRefresh = undefined> {
  session: SessionManager<TUser, TSession, TRefresh>

  providers: AnyProvider<TUser>[]

  pages: AuthPages

  callbacks: Partial<AuthCallbacks<TUser>>

  routes: {
    login: Map<string, AnyProvider<TUser>>
    callback: Map<string, AnyProvider<TUser>>
  }

  constructor(config: AuthConfig<TUser, TSession, TRefresh>) {
    this.providers = config.providers

    this.session = config.session

    this.pages = {
      logout: config.pages?.logout ?? { route: '/auth/logout', methods: ['POST'] },
      update: config.pages?.update ?? { route: '/auth/update', methods: ['POST'] },
      forgot: config.pages?.forgot ?? { route: '/auth/forgot', methods: ['POST'] },
      reset: config.pages?.reset ?? { route: '/auth/reset', methods: ['POST'] },
    }

    this.callbacks = config.callbacks ?? {}

    this.routes = {
      login: new Map(),
      callback: new Map(),
    }

    this.providers.forEach(provider => {
      provider
        .setJwtOptions(this.session.config.jwt)
        .setCookiesOptions(this.session.config.cookies)

      this.routes.login.set(provider.config.pages.login.route, provider)
      this.routes.callback.set(provider.config.pages.callback.route, provider)
    })
  }

  /**
   * Handle an incoming request.
   * Assumes a `Request` object according to web standards.
   * Convert framework implementation to one if it doesn't conform, i.e. ExpressJS.
   */
  async handle(request: Request): Promise<InternalResponse> {
    const internalRequest = await toInternalRequest(request)

    const internalResponse = await this
      .generateInternalResponse(internalRequest)
      .catch(error => ({ error }))

    return internalResponse
  }

  /**
   * Generate an `InternalResponse` from an `InternalRequest`.
   */
  async generateInternalResponse(internalRequest: InternalRequest): Promise<InternalResponse> {
    const { url, request } = internalRequest

    const sessionResponse = await this.session.handleRequest(internalRequest)

    if (url.pathname === this.pages.logout.route && this.pages.logout.methods.includes(request.method))
      return await this.callbacks.logout?.(internalRequest) ?? this.session.logout(request)

    if (url.pathname === this.pages.update.route && this.pages.update.methods.includes(request.method))
      return await this.callbacks.update?.(internalRequest) ?? {}

    if (url.pathname === this.pages.forgot.route && this.pages.forgot.methods.includes(request.method))
      return await this.callbacks.forgot?.(internalRequest) ?? {}

    if (url.pathname === this.pages.reset.route && this.pages.reset.methods.includes(request.method))
      return await this.callbacks.reset?.(internalRequest) ?? {}

    const loginHandler = this.routes.login.get(url.pathname)
    const callbackHandler = this.routes.callback.get(url.pathname)

    const providerResponse = loginHandler && loginHandler.config.pages.login.methods.includes(request.method)
      ? await loginHandler.login(internalRequest)
      : callbackHandler && callbackHandler.config.pages.callback.methods.includes(request.method)
      ? await callbackHandler.callback(internalRequest)
      : {}

    if (providerResponse.user) {
      const sessionTokens = await this.session.config.createSession?.(providerResponse.user)
      providerResponse.user = sessionTokens?.user

      if (sessionTokens) {
        providerResponse.cookies ??= []
        providerResponse.cookies.push(...await this.session.createCookies(sessionTokens))
      }
    }

    const cookies = sessionResponse.cookies ?? []
    if (providerResponse.cookies) cookies.push(...providerResponse.cookies)

    const internalResponse = { 
      ...sessionResponse,
      ...providerResponse,
      cookies,
      user: providerResponse.user || sessionResponse.user
    }

    return internalResponse
  }
}

/**
 * Create an auth instance.
 */
export function AponiaAuth<TUser, TSession = TUser, TRefresh = undefined>(
  config: AuthConfig<TUser, TSession, TRefresh>
) {
  return new Auth(config)
}
