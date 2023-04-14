import { parse } from 'cookie'
import { encode, decode } from '$lib/jwt'
import type { JWTOptions, JWTEncodeParams, JWTDecodeParams } from '$lib/jwt'

type Awaitable<T> = T | PromiseLike<T>

export const ACCESS_TOKEN_COOKIE_NAME = 'aponia-access'

export const REFRESH_TOKEN_COOKIE_NAME = 'aponia-refresh'

/**
 * Get session token from request cookies.
 */
export function getTokens(request: Request) {
  const cookies = parse(request.headers.get('cookie') ?? '')

  const access_token = cookies[ACCESS_TOKEN_COOKIE_NAME] ?? null

  const refresh_token = cookies[REFRESH_TOKEN_COOKIE_NAME] ?? null

  return { access_token, refresh_token }
}

/**
 * A session can be created to persist user login. 
 * Default expected interface for sessions.
 */
export interface Session {
  /**
   * Unique session identifier.
   */
  id: string;

  /**
   * Session owner.
   */
  user_id: string;

  /**
   * Session expiry date.
   */
  expires: number | bigint;
}

/**
 * JWT-session management configuration.
 */
export interface SessionManagerConfig<TUser, TSession> {
  /**
   * JWT configuration.
   */
  jwt?: JWTOptions

  /**
   * Get the user from the session, i.e. retrieved from cookies.
   */
  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession?: (sessionId: string) => Awaitable<void>

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions?: (userId: string) => Awaitable<void>
}

/**
 * Default JWT-based session manager only uses JWT to encode and decode sessions.
 *
 * Example flow:
 * 1. User logs in. Handle auth yourself.
 * 2. Create a session object, i.e. adding any desired additional info for the user.
 * 3. Call `createSessionToken` to create a session token from the session.
 * 4. Store the session token in a cookie.
 * 5. On subsequent requests, call `getRequestSession` to get the session from the request cookies.
 */
export class SessionManager<TUser = {}, TSession extends Record<string, any> = Session> {
  public static getSessionToken = getTokens

  /**
   * JWT configuration.
   */
  jwt: JWTOptions

  /**
   * Designated JWT encoder.
   */
  encode: (params: JWTEncodeParams) => Awaitable<string>

  /**
   * Designated JWT decoder.
   */
  decode: <T>(params: JWTDecodeParams) => Awaitable<T | null>

  /**
   * Get the user from the session, i.e. retrieved from cookies.
   */
  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession: (sessionId: string) => Awaitable<void> 

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions: (userId: string) => Awaitable<void>

  constructor(config: SessionManagerConfig<TUser, TSession>) {
    this.jwt = config?.jwt ?? { secret: '' }
    this.encode = config.jwt?.encode ?? encode
    this.decode = config.jwt?.decode ?? decode
    this.getUserFromSession = config.getUserFromSession
    this.invalidateSession = config.invalidateSession ?? (() => {})
    this.invalidateUserSessions = config.invalidateUserSessions ?? (() => {})
  }

  async createSessionToken(session: TSession) {
    const token = await this.encode({ ...this.jwt, token: session })
    return token
  }

  async getRequestSession(request: Request) {
    const { access_token } = SessionManager.getSessionToken(request)

    if (access_token == null) return null

    const session = await this.decode<TSession>({ ...this.jwt, token: access_token })

    if (session == null) return null

    const user = this.getUserFromSession?.(session) ?? null

    return { session, user }
  }
}
