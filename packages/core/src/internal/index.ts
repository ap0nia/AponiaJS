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

interface Pages {
  logout: PageEndpoint
  update: PageEndpoint
  forgot: PageEndpoint
  reset: PageEndpoint
  verify: PageEndpoint
}

type Callbacks<T> = {
  [k in keyof Pages]?: (request: InternalRequest) => Awaitable<InternalResponse<T> | Nullish>
}

export interface AuthConfig<TUser, TSession = TUser, TRefresh = undefined> {
  providers: AnyProvider<TUser>[]
  session: SessionManager<TUser, TSession, TRefresh>
  pages?: Partial<Pages>
  callbacks?: Partial<Callbacks<TUser>>
}

export class Auth<TUser, TSession, TRefresh = undefined> {
  session: SessionManager<TUser, TSession, TRefresh>
  providers: AnyProvider<TUser>[]
  pages: Pages
  callbacks: Partial<Callbacks<TUser>>
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

    this.providers.forEach(provider => {
      provider
        .setJwtOptions(this.session.jwt)
        .setCookiesOptions(this.session.cookies)

      this.routes.login.set(provider.config.pages.login.route, provider)
      this.routes.callback.set(provider.config.pages.callback.route, provider)
    })
  }

  async handle(request: Request): Promise<InternalResponse> {
    const internalRequest = await toInternalRequest(request)

    const internalResponse = await this
      .generateInternalResponse(internalRequest)
      .catch(error => ({ error }))

    return internalResponse
  }

  async generateInternalResponse(internalRequest: InternalRequest): Promise<InternalResponse> {
    const { url, request } = internalRequest

    const sessionResponse = await this.session.handleRequest(internalRequest)

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

    const providerResponse = 
        loginHandler && loginHandler.config.pages.login.methods.includes(request.method)
      ? await loginHandler.login(internalRequest)
      : callbackHandler && callbackHandler.config.pages.callback.methods.includes(request.method)
      ? await callbackHandler.callback(internalRequest)
      : {}

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
      user: providerResponse.user || sessionResponse.user
    }

    return internalResponse
  }
}

export function AponiaAuth<TUser, TSession = TUser, TRefresh = undefined>(
  config: AuthConfig<TUser, TSession, TRefresh>
) {
  return new Auth(config)
}
