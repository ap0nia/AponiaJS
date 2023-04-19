import { encode, decode } from '../security/jwt'
import { createCookiesOptions } from '../security/cookie'
import type { Cookie } from '../security/cookie'
import type { CookiesOptions } from '../security/cookie'
import type { JWTOptions, JWTEncodeParams, JWTDecodeParams } from '../security/jwt'
import type { InternalRequest } from '../internal/request'
import type { InternalResponse } from '../internal/response'

type Awaitable<T> = T | PromiseLike<T>

export interface SessionManagerConfig<TUser, TSession> {
  secret: string

  jwt?: Omit<JWTOptions, 'secret'>

  useSecureCookies?: boolean

  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  onInvalidate?: (context: { session: TSession, user: TUser }) => Awaitable<InternalResponse<TUser, TSession> | void>

  onRefresh?: (context: { session: TSession, user: TUser }) => Awaitable<InternalResponse<TUser, TSession> | void>
}

/**
 * Initialization:
 * 1. Create a session.
 * 2. Use the session to create a JWT session token.
 * 3. Store the JWT session token in a cookie.
 *
 * Usage for request:
 * 1. Parse tokens from the request cookie headers.
 * 1. Decode the JWT session token (`tokens.access_token`) to get the session.
 * 2. Call `getUserFromSession` to get the user.
 * 3. Share the user with other handlers.
 */
export class SessionManager<TUser = {}, TSession extends Record<string, any> = {}> {
  /**
   * Secret.
   */
  secret: string

  /**
   * JWT options.
   */
  jwt: JWTOptions

  /**
   * Cookie options for each type of cookie created.
   */
  cookies: CookiesOptions

  /**
   * Encode a JWT token.
   */
  encode: (params: JWTEncodeParams) => Awaitable<string>

  /**
   * Decode a JWT token.
   */
  decode: <T>(params: JWTDecodeParams) => Awaitable<T | null>

  /**
   * Get the user from the session.
   * @default return the session itself.
   */
  getUserFromSession: (session: TSession) => Awaitable<TUser | null>

  /**
   * Invalidate a session.
   */
  onInvalidate: (context: { session: TSession, user: TUser }) => Awaitable<InternalResponse<TUser, TSession> | void> 

  /**
   * Refresh a session.
   */
  onRefresh: (context: { session: TSession, user: TUser }) => Awaitable<InternalResponse<TUser, TSession> | void>

  constructor(config: SessionManagerConfig<TUser, TSession>) {
    this.secret = config.secret
    this.jwt = { ...config.jwt, secret: config.secret }
    this.cookies = createCookiesOptions(config.useSecureCookies)
    this.encode = config.jwt?.encode ?? encode
    this.decode = config.jwt?.decode ?? decode
    this.getUserFromSession = config.getUserFromSession ?? ((session) => session as any)
    this.onInvalidate = config.onInvalidate ?? (() => {})
    this.onRefresh = config.onRefresh ?? (() => {})
  }

  /**
   * Get the tokens from the request, based on the provided cookie options.
   */
  getTokens(request: InternalRequest) {
    return {
      access_token: request.cookies[this.cookies.sessionToken.name],
      refresh_token: request.cookies[this.cookies.refreshToken.name],
    }
  }

  /**
   * Create a session token.
   */
  async createSessionToken(session: TSession) {
    const token = await this.encode({ ...this.jwt, token: session })
    return token
  }

  /**
   * Create a session cookie.
   */
  async createSessionCookie(session: TSession): Promise<Cookie> {
    return {
      name: this.cookies.sessionToken.name,
      value: await this.createSessionToken(session),
      options: this.cookies.sessionToken.options
    }
  }

  /**
   * Get the session from the request.
   */
  async getRequestSession(request: InternalRequest) {
    const { access_token } = this.getTokens(request)

    if (!access_token) return null

    const session = await this.decode<TSession>({ ...this.jwt, token: access_token })

    if (!session) return null

    const user = this.getUserFromSession(session)

    return { session, user }
  }

  /**
   * Invalidate a session.
   */
  async invalidateSession(request: InternalRequest): Promise<InternalResponse> {
    const userSession = request.session ?? await this.getRequestSession(request)
    await this.onInvalidate(userSession)
    return {
      redirect: '/',
      status: 302,
      cookies: [
        {
          name: this.cookies.sessionToken.name,
          value: '',
          options: { maxAge: 0, path: '/' }
        },
        {
          name: this.cookies.refreshToken.name,
          value: '',
          options: { maxAge: 0, path: '/' }
        },
      ],
    }
  }
}
