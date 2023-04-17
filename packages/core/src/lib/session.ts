import { parse } from 'cookie'
import type { Awaitable } from '@auth/core/types'
import { encode, decode } from './security/jwt'
import type { JWTOptions, JWTEncodeParams, JWTDecodeParams } from './security/jwt'
import { defaultCookies } from './security/cookie'
import type { InternalCookiesOptions } from './security/cookie'
import type { Cookie } from './integrations/response'

export function getRequestTokens(request: Request, options: InternalCookiesOptions) {
  const cookies = parse(request.headers.get('cookie') ?? '')
  return {
    access_token: cookies[options.sessionToken.name],
    refresh_token: cookies[options.refreshToken.name],
  }
}

export interface Session {
  id: string;
  user_id: string;
  expires: number | bigint;
}

export interface SessionManagerConfig<TUser, TSession> {
  secret: string

  jwt?: Omit<JWTOptions, 'secret'>

  useSecureCookies?: boolean

  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  invalidateSession?: (sessionId: string) => Awaitable<void>

  invalidateUserSessions?: (userId: string) => Awaitable<void>

  refreshSession?: (session: TSession) => Awaitable<TSession | null>
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
export class SessionManager<TUser = {}, TSession extends Record<string, any> = Session> {
  /**
   * JWT options.
   */
  jwt: JWTOptions

  /**
   * Cookie options for each type of cookie created.
   */
  cookies: InternalCookiesOptions

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
   */
  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  /**
   * Invalidate a session.
   */
  invalidateSession: (sessionId: string) => Awaitable<void> 

  /**
   * Invalidate all sessions for a user.
   */
  invalidateUserSessions: (userId: string) => Awaitable<void>

  /**
   * Refresh a session.
   */
  refreshSession: (session: TSession, sessionToken: string) => Awaitable<TSession | null>

  constructor(config: SessionManagerConfig<TUser, TSession>) {
    this.jwt = { ...config.jwt, secret: config.secret }
    this.cookies = defaultCookies(config.useSecureCookies)
    this.encode = config.jwt?.encode ?? encode
    this.decode = config.jwt?.decode ?? decode
    this.getUserFromSession = config.getUserFromSession
    this.invalidateSession = config.invalidateSession ?? (() => {})
    this.invalidateUserSessions = config.invalidateUserSessions ?? (() => {})
    this.refreshSession = config.refreshSession ?? (() => null)
  }

  /**
   * Get the tokens from the request, based on the provided cookie options.
   */
  getTokens(request: Request) {
    return getRequestTokens(request, this.cookies)
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
  async getRequestSession(request: Request) {
    const { access_token } = this.getTokens(request)

    if (!access_token) return null

    const session = await this.decode<TSession>({ ...this.jwt, token: access_token })

    if (!session) return null

    const user = this.getUserFromSession?.(session) ?? null

    return { session, user }
  }
}
