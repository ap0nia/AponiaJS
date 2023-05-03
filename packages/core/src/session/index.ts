import { parse } from "cookie";
import { encode, decode } from "../security/jwt.js";
import { createCookiesOptions } from "../security/cookie.js";
import type { JWTOptions, JWTEncodeParams, JWTDecodeParams } from "../security/jwt.js";
import type { Cookie, CookiesOptions } from "../security/cookie.js";
import type { InternalRequest } from "../internal/request.js";
import type { InternalResponse } from "../internal/response.js";

const DefaultAccessTokenMaxAge = 60 * 60

const DefaultRefreshTokenMaxAge = 60 * 60 * 24 * 7

type Awaitable<T> = T | PromiseLike<T>;

type Nullish = null | undefined | void;

type NewSession<TUser, TSession, TRefresh> = { 
  user: TUser,
  accessToken: TSession,
  refreshToken?: TRefresh 
}

type TokenMaxAge = {
  accessToken: number
  refreshToken: number
}

export interface SessionConfig<TUser, TSession = TUser, TRefresh = undefined> {
  /**
   * Secret used to sign the tokens.
   */
  secret: string

  /**
   * Custom JWT options.
   */
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
  createSession: (user: TUser) => Awaitable<NewSession<TUser, TSession, TRefresh> | Nullish>;

  /**
   * Get a user from a session.
   */
  getUserFromSession?: (session: TSession) => Awaitable<TUser | Nullish>;

  /**
   * Refresh a session from a refresh token.
   */
  handleRefresh: (
    tokens: { accessToken?: TSession | Nullish, refreshToken?: TRefresh | Nullish  }
  ) => Awaitable<NewSession<TUser, TSession, TRefresh> | Nullish>;

  /**
   * Invalidate a session.
   */
  onInvalidateSession?: (
    session: TSession,
    refresh?: TRefresh | Nullish
  ) => Awaitable<InternalResponse<TUser> | Nullish>
}

export class SessionManager<
  TUser, TSession = TUser, TRefresh = undefined
> implements SessionConfig<TUser, TSession, TRefresh> {
  secret: string

  jwt: Omit<JWTOptions, 'maxAge'>

  encode: (params: JWTEncodeParams) => Awaitable<string>

  decode: <T>(params: JWTDecodeParams) => Awaitable<T | Nullish>

  maxAge: TokenMaxAge

  cookies: CookiesOptions

  createSession: (user: TUser) => Awaitable<NewSession<TUser, TSession, TRefresh> | Nullish>;

  getUserFromSession: (session: TSession) => Awaitable<TUser | Nullish>;

  handleRefresh: (
    tokens: { accessToken?: TSession | Nullish, refreshToken?: TRefresh | Nullish  }
  ) => Awaitable<NewSession<TUser, TSession, TRefresh> | Nullish>;

  onInvalidateSession?: (
    session: TSession,
    refresh?: TRefresh | Nullish
  ) => Awaitable<InternalResponse<TUser> | Nullish>

  constructor(config: SessionConfig<TUser, TSession, TRefresh>) {
    this.secret = config.secret;
    this.jwt = {
      ...config.jwt,
      secret: config.secret,
    }
    this.maxAge = { 
      accessToken: config.maxAge?.accessToken ?? DefaultAccessTokenMaxAge,
      refreshToken: config.maxAge?.refreshToken ?? DefaultRefreshTokenMaxAge,
    }
    this.encode = config.jwt?.encode ?? encode
    this.decode = config.jwt?.decode ?? decode
    this.cookies = createCookiesOptions(config.useSecureCookies)
    this.createSession = config.createSession;
    this.getUserFromSession = config.getUserFromSession ?? ((session: TSession) => session as any);
    this.handleRefresh = config.handleRefresh;
    this.onInvalidateSession = config.onInvalidateSession;
  }

  async createCookies(newSession: NewSession<TUser, TSession, TRefresh>): Promise<Cookie[]> {
    const cookies: Cookie[] = []

    if (newSession?.accessToken) {
      cookies.push({
        name: this.cookies.accessToken.name,
        value: await this.encode({ 
          secret: this.secret,
          maxAge: this.maxAge.accessToken,
          token: newSession.accessToken
        }),
        options: {
          ...this.cookies.accessToken.options,
          maxAge: this.maxAge.accessToken,
        }
      })
    }

    if (newSession?.refreshToken) {
      cookies.push({
        name: this.cookies.refreshToken.name,
        value: await this.encode({
          secret: this.secret,
          maxAge: this.maxAge.refreshToken,
          token: newSession.refreshToken
        }),
        options: {
          ...this.cookies.refreshToken.options,
          maxAge: this.maxAge.refreshToken,
        }
      })
    }

    return cookies
  }

  /**
   * Handle request.
   */
  async handleRequest(request: InternalRequest): Promise<InternalResponse<TUser | TSession>> {
    const response: InternalResponse<TUser> = {}
    response.cookies ??= []

    const accessToken = request.cookies[this.cookies.accessToken.name]
    const refreshToken = request.cookies[this.cookies.refreshToken.name]

    let access: TSession | Nullish = null
    let refresh: TRefresh | Nullish = null

    try { 
      access = await this.decode<TSession>({ secret: this.secret, token: accessToken })
      response.user = access ? await this.getUserFromSession(access) : null
    } catch (e) {
      console.log('Error decoding access token', e)
    }

    try {
      refresh = await this.decode<TRefresh>({ secret: this.secret, token: refreshToken })
    } catch (e) {
      console.log('Error decoding refresh token', e)
    }

    const sessionTokens = await this.handleRefresh({ accessToken: access, refreshToken: refresh })

    if (sessionTokens) {
      const sessionCookies = await this.createCookies(sessionTokens)
      response.cookies.push(...sessionCookies)
    }
    
    response.user ||= sessionTokens?.user
    return response
  }

  /**
   * Logout the user.
   */
  async logout(request: Request): Promise<InternalResponse<TUser>> {
    const cookies = parse(request.headers.get("cookie") ?? "")

    const accessToken = cookies[this.cookies.accessToken.name]
    const refreshToken = cookies[this.cookies.refreshToken.name]

    let session: TSession | Nullish = null
    let refresh: TRefresh | Nullish = null

    try { 
      session = await this.decode<TSession>({ secret: this.secret, token: accessToken })
    } catch (e) {
      console.log('Error decoding access token', e)
    }

    try {
      refresh = await this.decode<TRefresh>({ secret: this.secret, token: refreshToken })
    } catch (e) {
      console.log('Error decoding refresh token', e)
    }

    const response = session
      ? (await this.onInvalidateSession?.(session, refresh)) ?? {}
      : {}

    response.cookies ??= []
    response.cookies.push(
      {
        name: this.cookies.accessToken.name,
        value: "",
        options: { ...this.cookies.accessToken.options, maxAge: 0, }
      }, 
      {
        name: this.cookies.refreshToken.name,
        value: "",
        options: { ...this.cookies.refreshToken.options, maxAge: 0, }
      }
    )

    return response
  }
}

export function Session<TUser, TSession = TUser, TRefresh = undefined>(
  config: SessionConfig<TUser, TSession, TRefresh>
): SessionManager<TUser, TSession, TRefresh> {
  return new SessionManager(config)
}
