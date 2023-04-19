import { encode, decode } from "../security/jwt";
import type { JWTOptions } from "../security/jwt";
import type { InternalRequest } from "../internal/request";
import type { InternalResponse } from "../internal/response";
import { createCookiesOptions } from "../security/cookie";
import type { Cookie, CookiesOptions } from "../security/cookie";
import { parse } from "cookie";

const DefaultAccessTokenMaxAge = 60 * 60 * 24

const DefaultRefreshTokenMaxAge = 60 * 60 * 24 * 7

type Awaitable<T> = T | PromiseLike<T>;

type Nullish = null | undefined | void;

type NewSession<TSession, TRefresh> = { session: TSession, refresh?: TRefresh } | Nullish;

type TokenMaxAge = {
  accessToken: number
  refreshToken: number
}

export interface TokenSessionConfig<TUser, TSession = TUser, TRefresh = undefined> {
  secret: string

  jwt?: Omit<JWTOptions, 'maxAge'>

  /**
   * Max age of the access and refresh tokens.
   */
  maxAge?: Partial<TokenMaxAge>

  /**
   * Cookie options for the access and refresh tokens.
   */
  useSecureCookies?: boolean

  /**
   * Create a new session from a user.
   */
  createSession: (user: TUser) => Awaitable<NewSession<TSession, TRefresh>>;

  /**
   * Refresh a session from a refresh token.
   */
  refreshSession: (refresh: TRefresh) => Awaitable<NewSession<TSession, TRefresh> | Nullish>;

  /**
   * Invalidate a session.
   */
  onInvalidateSession?: (session: TSession) => Awaitable<void>;
}

export class TokenSessionManager<
  TUser, TSession = TUser, TRefresh = undefined
> implements TokenSessionConfig<TUser, TSession, TRefresh> {
  secret: string

  jwt: Omit<JWTOptions, 'maxAge'>

  maxAge: TokenMaxAge

  cookies: CookiesOptions

  createSession: (user: TUser) => Awaitable<NewSession<TSession, TRefresh>>;

  refreshSession: (refresh: TRefresh) => Awaitable<NewSession<TSession, TRefresh> | Nullish>;

  onInvalidateSession?: (session: TSession, refresh?: TRefresh | Nullish) => Awaitable<void>;

  constructor(config: TokenSessionConfig<TUser, TSession, TRefresh>) {
    this.secret = config.secret;
    this.jwt = {
      ...config.jwt,
      secret: config.secret,
    }
    this.maxAge = { 
      accessToken: config.maxAge?.accessToken ?? DefaultAccessTokenMaxAge,
      refreshToken: config.maxAge?.refreshToken ?? DefaultRefreshTokenMaxAge,
    }
    this.cookies = createCookiesOptions(config.useSecureCookies)
    this.createSession = config.createSession;
    this.refreshSession = config.refreshSession;
    this.onInvalidateSession = config.onInvalidateSession;
  }

  /**
   * Incoming requests with tokens need to be actively refreshed if needed.
   */
  async handleRefresh(request: InternalRequest<TUser>): Promise<InternalResponse<TUser>> {
    const accessToken = request.cookies[this.cookies.accessToken.name]
    const refreshToken = request.cookies[this.cookies.refreshToken.name]

    const e = this.jwt.encode ?? encode
    const d = this.jwt.decode ?? decode

    const refresh = await d<TRefresh>({ secret: this.secret, token: refreshToken })

    if (!accessToken && refreshToken && refresh) {
      const newSession = await this.refreshSession(refresh)

      const cookies: Cookie[] = []

      if (newSession?.session) {
        cookies.push({
          name: this.cookies.accessToken.name,
          value: await e({ 
            secret: this.secret,
            maxAge: this.maxAge.accessToken,
            token: newSession.session
          }),
          options: this.cookies.accessToken.options
        })
      }

      if (newSession?.refresh) {
        cookies.push({
          name: this.cookies.refreshToken.name,
          value: await e({
            secret: this.secret,
            maxAge: this.maxAge.refreshToken,
            token: newSession.refresh
          }),
          options: this.cookies.refreshToken.options
        })
      }

      return { cookies }
    }

    return {}
  }

  /**
   * Outgoing responses with a defined user need to create new token cookie sessions.
   */
  async handleResponse(response: InternalResponse<TUser>): Promise<InternalResponse<TUser>> {
    if (!response.user) return response

    response.cookies ??= []

    const newSession = await this.createSession(response.user)

    const e = this.jwt.encode ?? encode

    if (newSession?.session) {
      response.cookies.push({
        name: this.cookies.accessToken.name,
        value: await e({ 
          secret: this.secret,
          maxAge: this.maxAge.accessToken,
          token: newSession.session
        }),
        options: this.cookies.accessToken.options
      })
    }

    if (newSession?.refresh) {
      response.cookies.push({
        name: this.cookies.refreshToken.name,
        value: await e({ 
          secret: this.secret,
          maxAge: this.maxAge.refreshToken,
          token: newSession.refresh
        }),
        options: this.cookies.refreshToken.options
      })
    }

    return response
  }

  async getUser(request: Request): Promise<TUser | Nullish> {
    const cookies = parse(request.headers.get("cookie") ?? "")
    const accessToken = cookies[this.cookies.accessToken.name]
    if (!accessToken) return null

    const d = this.jwt.decode ?? decode

    const user = await d<TUser>({ secret: this.secret, token: accessToken })
    return user
  }

  async logout(request: Request): Promise<InternalResponse<TUser>> {
    const cookies = parse(request.headers.get("cookie") ?? "")
    const accessToken = cookies[this.cookies.accessToken.name]
    const refreshToken = cookies[this.cookies.refreshToken.name]

    const d = this.jwt.decode ?? decode

    const session = await d<TSession>({ secret: this.secret, token: accessToken })
    const refresh = await d<TRefresh>({ secret: this.secret, token: refreshToken })

    if (session) await this.onInvalidateSession?.(session, refresh)

    return {
      cookies: [
        { name: this.cookies.accessToken.name, value: "", options: { maxAge: 0 } },
        { name: this.cookies.refreshToken.name, value: "", options: { maxAge: 0 } }
      ]
    }
  }
}
