import type { InternalRequest } from "./request.js"
import type { InternalResponse } from "./response.js"
import type { SessionManager } from "../session.js"
import type { CredentialsProvider } from "../providers/credentials.js"
import type { EmailProvider } from "../providers/email.js"
import type { OAuthProvider } from "../providers/oauth.js"
import type { OIDCProvider } from "../providers/oidc.js"
import type { Awaitable, Nullish, PageEndpoint } from "../types.js"

type AnyProvider<TUser, TRequest extends InternalRequest = InternalRequest> = 
  | OAuthProvider<any, TUser, TRequest> 
  | OIDCProvider<any, TUser, TRequest> 
  | CredentialsProvider<TUser, TRequest>
  | EmailProvider<TUser, TRequest>

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
type AuthCallbacks<TUser, TRequest extends InternalRequest = InternalRequest> = {
  [k in keyof AuthPages]?: (request: TRequest) => Awaitable<InternalResponse<TUser> | Nullish>
}

/**
 * Auth configuration.
 */
export interface AuthConfig<
  TUser,
  TSession = TUser,
  TRefresh = undefined,
  TRequest extends InternalRequest = InternalRequest
> {
  /**
   * Session manager. Handles session creation, validation / decoding, and destruction.
   */
  session: SessionManager<TUser, TSession, TRefresh, TRequest>

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
  callbacks?: Partial<AuthCallbacks<TUser, TRequest>>
}

/**
 * Auth framework.
 */
export class Auth<
  TUser,
  TSession = TUser,
  TRefresh = undefined,
  TRequest extends InternalRequest = InternalRequest
> {
  session: SessionManager<TUser, TSession, TRefresh, TRequest>

  providers: AnyProvider<TUser, TRequest>[]

  pages: AuthPages

  callbacks: Partial<AuthCallbacks<TUser, TRequest>>

  routes: {
    login: Map<string, AnyProvider<TUser, TRequest>>
    callback: Map<string, AnyProvider<TUser, TRequest>>
  }

  constructor(config: AuthConfig<TUser, TSession, TRefresh, TRequest>) {
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
   * Handle an incoming `InternalRequest`.
   */
  async handle(internalRequest: TRequest): Promise<InternalResponse<TUser>> {
    const internalResponse = await this
      .generateInternalResponse(internalRequest)
      .catch(error => ({ error }))

    return internalResponse
  }

  /**
   * Generate an `InternalResponse` from an `InternalRequest`.
   */
  async generateInternalResponse(internalRequest: TRequest): Promise<InternalResponse<TUser>> {
    const { url, request } = internalRequest

    /**
     * 1. Refresh the user's session if necessary and possible.
     */
    const sessionResponse = await this.session.handleRequest(internalRequest)

    /**
     * 2.1. Framework handles static auth pages.
     */
    if (url.pathname === this.pages.logout.route && this.pages.logout.methods.includes(request.method))
      return await this.callbacks.logout?.(internalRequest) ?? this.session.logout(request)

    if (url.pathname === this.pages.update.route && this.pages.update.methods.includes(request.method))
      return await this.callbacks.update?.(internalRequest) ?? sessionResponse

    if (url.pathname === this.pages.forgot.route && this.pages.forgot.methods.includes(request.method))
      return await this.callbacks.forgot?.(internalRequest) ?? sessionResponse

    if (url.pathname === this.pages.reset.route && this.pages.reset.methods.includes(request.method))
      return await this.callbacks.reset?.(internalRequest) ?? sessionResponse

    const loginHandler = this.routes.login.get(url.pathname)
    const callbackHandler = this.routes.callback.get(url.pathname)

    if (!loginHandler && !callbackHandler) return sessionResponse

    /**
     * 2.2. Providers handle login and callback pages.
     */
    const providerResponse = 
        loginHandler && loginHandler.config.pages.login.methods.includes(request.method)
      ? await loginHandler.login(internalRequest)
      : callbackHandler && callbackHandler.config.pages.callback.methods.includes(request.method)
      ? await callbackHandler.callback(internalRequest)
      : {}

    /**
     * 3. The provider logged in a user if `user` is defined. Create a new session for the user.
     */
    if (providerResponse.user) {
      const sessionTokens = await this.session.config.createSession?.(providerResponse.user)
      providerResponse.user = sessionTokens?.user
      if (sessionTokens) {
        providerResponse.cookies ??= []
        providerResponse.cookies.push(...await this.session.createCookies(sessionTokens))
      }
    }

    if (sessionResponse.cookies) {
      providerResponse.cookies ??= []
      providerResponse.cookies.push(...sessionResponse.cookies)
    }

    /**
     * User may be defined as a result of a provider login, or a session refresh. 
     * Otherwise call `session.getUserFromRequest(request)` to get the user for the current request.
     */
    providerResponse.user ||= sessionResponse.user

    return providerResponse
  }
}

/**
 * Create an auth instance.
 */
export function AponiaAuth<
  TUser,
  TSession = TUser,
  TRefresh = undefined,
  TRequest extends InternalRequest = InternalRequest
>(
  config: AuthConfig<TUser, TSession, TRefresh, TRequest>
) {
  return new Auth(config)
}
