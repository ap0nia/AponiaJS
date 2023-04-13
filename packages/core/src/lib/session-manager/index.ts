import { parse } from 'cookie'
import { encode, decode } from '$lib/jwt'
import type { JwtConfig, JWTEncodeParams, JWTDecodeParams } from '$lib/jwt'
import type { MaybePromise } from '$lib/utils/promise'

export const SESSION_COOKIE_NAME = 'sid'

/**
 * Get session ID from request cookies.
 */
export function getSessionToken(request: Request) {
  const cookies = parse(request.headers.get('cookie') ?? '')

  const sessionId = cookies[SESSION_COOKIE_NAME]

  return sessionId || null
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
 * Basic session management configuration.
 */
export interface SessionManagerConfig {
  /**
   * JWT configuration.
   */
  jwt?: JwtConfig
}

export abstract class SessionManager<
  TUser = {},
  TSession extends Record<string, any> = Session,
  RequestSession = { session: TSession | null, user: TUser | null } | null
> {
  public static getSessionToken = getSessionToken

  jwt: JwtConfig

  encode: (params: JWTEncodeParams) => MaybePromise<string>

  decode: <T>(params: JWTDecodeParams) => MaybePromise<T | null>

  constructor(config: SessionManagerConfig) {
    this.jwt = config?.jwt ?? { secret: '' }
    this.encode = config.jwt?.encode ?? encode
    this.decode = config.jwt?.decode ?? decode
  }

  abstract getUserFromSession?: (session: TSession) => MaybePromise<TUser | null>

  abstract getRequestSession(request: Request): MaybePromise<RequestSession>

  async createSessionToken(session: TSession) {
    const token = await this.encode({ ...this.jwt, token: session })
    return token
  }

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession(_sessionId: string): MaybePromise<void> {
    console.log(`InvalidateSession. Not implemented`)
  }

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions(_userId: string): MaybePromise<void> {
    console.log(`InvalidateUserSessions. Not implemented`)
  }
}
