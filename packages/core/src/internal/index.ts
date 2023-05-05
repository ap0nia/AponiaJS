import { toInternalRequest } from "./request.js"
import type { InternalRequest } from "./request.js"
import type { InternalResponse } from "./response.js"
import type { SessionManager } from "../session.js"
import type { CredentialsProvider } from "../providers/credentials.js"
import type { EmailProvider } from "../providers/email.js"
import type { OAuthProvider } from "../providers/oauth.js"
import type { OIDCProvider } from "../providers/oidc.js"
import type { Awaitable, Nullish } from "../types.js"

/**
 * Any core provider.
 */
type AnyProvider<T> = 
  | OAuthProvider<any, T> 
  | OIDCProvider<any, T> 
  | CredentialsProvider<T> 
  | EmailProvider<T>

interface Endpoint {
  route: string
  methods: string[]
}

/**
 * Static auth pages not associated with providers.
 */
interface Pages {
  /**
   * Logout endpoint.
   */
  logout: Endpoint

  /**
   * Endpoint to update user.
   */
  update: Endpoint

  /**
   * Endpoint to request password reset.
   */
  forgot: Endpoint

  /**
   * Endpoint to reset password.
   */
  reset: Endpoint

  /**
   * Endpoint to verify account (email).
   */
  verify: Endpoint
}

/**
 * Callbacks for Aponia Auth pages.
 */
type Callbacks<T> = {
  [k in keyof Pages]?: (request: InternalRequest) => Awaitable<InternalResponse<T> | Nullish>
}

/**
 * Configuration.
 */
export interface AuthConfig<TUser, TSession = TUser, TRefresh = undefined> {
  /**
   * Providers.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session manager.
   */
  session: SessionManager<TUser, TSession, TRefresh>

  /**
   * Static auth pages.
   */
  pages?: Partial<Pages>

  /**
   * Callbacks to handle static auth pages.
   */
  callbacks?: Partial<Callbacks<TUser>>
}

/**
 * Aponia `Auth` class.
 */
export class Auth<TUser, TSession, TRefresh = undefined> {
  /**
   * Providers.
   */
  providers: AnyProvider<TUser>[]

  /**
   * Session manager.
   */
  session: SessionManager<TUser, TSession, TRefresh>

  /**
   * Static auth routes handled by Aponia.
   */
  pages: Pages

  /**
   * Callbacks.
   */
  callbacks: Partial<Callbacks<TUser>>

  /**
   * Dynamic auth routes handled by providers.
   */
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
      verify: config.pages?.verify ?? { route: '/auth/verify', methods: ['POST'] },
    }

    this.callbacks = config.callbacks ?? {}

    this.routes = {
      login: new Map(),
      callback: new Map(),
    }

    /**
     * Each provider has internal routes for login and callback that can be overridden.
     * Use that info to register the provider into the route maps.
     */
    this.providers.forEach(provider => {
      /**
       * All providers will inherit JWT and cookie options from the session manager.
       * When used standalone, they can be defined in the provider config directly.
       */
      provider
        .setJwtOptions(this.session.jwt)
        .setCookiesOptions(this.session.cookies)

      this.routes.login.set(provider.config.pages.login.route, provider)
      this.routes.callback.set(provider.config.pages.callback.route, provider)
    })
  }

  /**
   * Handle a `Request` and return an `InternalResponse`.
   * Specific usages and framework integrations should handle the `InternalResponse` accordingly.
   */
  async handle(request: Request): Promise<InternalResponse> {
    const internalRequest = await toInternalRequest(request)

    const internalResponse = await this
      .generateInternalResponse(internalRequest)
      .catch(error => ({ error }))

    return internalResponse
  }

  async generateInternalResponse(internalRequest: InternalRequest): Promise<InternalResponse> {
    const { url, request } = internalRequest

    /**
     * 1. Generate an initial `InternalResponse` with the session info.
     * `user` will be defined if already logged in.
     * `cookies` will be defined if a new session was created.
     */
    const sessionResponse = await this.session.handleRequest(internalRequest)

    /**
     * 2.1 Aponia handles requests for static auth pages.
     */
    if (url.pathname === this.pages.logout.route && this.pages.logout.methods.includes(request.method)) {
      return await this.callbacks.logout?.(internalRequest) ?? this.session.logout(request)
    }

    if (url.pathname === this.pages.update.route && this.pages.update.methods.includes(request.method)) {
      return await this.callbacks.update?.(internalRequest) ?? {}
    }

    if (url.pathname === this.pages.forgot.route && this.pages.forgot.methods.includes(request.method)) {
      return await this.callbacks.forgot?.(internalRequest) ?? {}
    }

    if (url.pathname === this.pages.reset.route && this.pages.reset.methods.includes(request.method)) {
      return await this.callbacks.reset?.(internalRequest) ?? {}
    }

    if (url.pathname === this.pages.verify.route && this.pages.verify.methods.includes(request.method)) {
      return await this.callbacks.verify?.(internalRequest) ?? {}
    }

    const loginHandler = this.routes.login.get(url.pathname)
    const callbackHandler = this.routes.callback.get(url.pathname)

    /**
     * 2.2 A provider handles the request.
     */
    const providerResponse = 
        loginHandler && loginHandler.config.pages.login.methods.includes(request.method)
      ? await loginHandler.login(internalRequest)
      : callbackHandler && callbackHandler.config.pages.callback.methods.includes(request.method)
      ? await callbackHandler.callback(internalRequest)
      : {}

    /**
     * 3. If the provider response has a defined `user`, i.e. they just logged in, then create a new session.
     * If the session manager __doesn't__ create a session, then `user` will be unset.
     */
    if (providerResponse.user) {
      const sessionTokens = await this.session.createSession(providerResponse.user)
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

      /** The final response's `user` can be from the initial session response or the provider response. */
      user: providerResponse.user || sessionResponse.user
    }

    return internalResponse
  }
}

/**
 * Create a new Aponia `Auth` instance.
 */
export function AponiaAuth<TUser, TSession = TUser, TRefresh = undefined>(
  config: AuthConfig<TUser, TSession, TRefresh>
) {
  return new Auth(config)
}
