import { parse } from 'cookie'
import { encode, decode } from '$lib/jwt'
import type { JwtConfig, JWTEncodeParams, JWTDecodeParams } from '$lib/jwt'
import type { MaybePromise } from '$lib/utils/promise'

export const SESSION_COOKIE_NAME = 'sid'

/**
 * Get session token from request cookies.
 */
export function getSessionToken(request: Request) {
  const cookies = parse(request.headers.get('cookie') ?? '')

  const sessionToken = cookies[SESSION_COOKIE_NAME]

  return sessionToken ?? null
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
  jwt?: JwtConfig

  /**
   * Get the user from the session, i.e. retrieved from cookies.
   */
  getUserFromSession?: (session: TSession) => MaybePromise<TUser | null>

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession?: (sessionId: string) => MaybePromise<void>

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions?: (userId: string) => MaybePromise<void>
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
  public static getSessionToken = getSessionToken

  /**
   * JWT configuration.
   */
  jwt: JwtConfig

  /**
   * Designated JWT encoder.
   */
  encode: (params: JWTEncodeParams) => MaybePromise<string>

  /**
   * Designated JWT decoder.
   */
  decode: <T>(params: JWTDecodeParams) => MaybePromise<T | null>

  /**
   * Get the user from the session, i.e. retrieved from cookies.
   */
  getUserFromSession?: (session: TSession) => MaybePromise<TUser | null>

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession: (sessionId: string) => MaybePromise<void> 

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions: (userId: string) => MaybePromise<void>

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
    const token = SessionManager.getSessionToken(request)

    if (token == null) return null

    const session = await this.decode<TSession>({ ...this.jwt, token })

    if (session == null) return null

    const user = this.getUserFromSession?.(session) ?? null

    return { session, user }
  }
}
