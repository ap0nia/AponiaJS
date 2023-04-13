import type { MaybePromise } from '$lib/utils/promise';
import { SessionManager, getSessionToken } from '.'
import type { Session } from '.'
import type { SessionManagerConfig } from '.'

export interface DatabaseSessionConfig<TUser, TSession> extends SessionManagerConfig {
  /**
   * Get the user from the database based on the session, i.e. retrieved from cookies.
   */
  getUser: (session: TSession) => MaybePromise<TUser | null>

  /**
   * Create a session from a user ID, i.e. storing it in the database.
   * Session can then be used to create a session token.
   */
  createSession: (userId: string) => MaybePromise<TSession>

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession: (sessionId: string) => MaybePromise<void>

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions: (userId: string) => MaybePromise<void>
}

/**
 * Database session interface.
 *
 * Example flow:
 * 1. User logs in. Handle auth yourself.
 * 2. Call `createSession` to create a session in the database and return the session.
 * 3. Call `createSessionToken` to create a session token from the session.
 * 4. Store the session token in a cookie.
 * 5. On subsequent requests, call `getRequestSession` to get the session from the request cookies.
 */
export class DatabaseSessionManager<TUser = {}, TSession extends Record<string, any> = Session> extends SessionManager<TSession> {
  getUser: (session: TSession) => MaybePromise<TUser | null>

  createSession: (userId: string) => MaybePromise<TSession>

  invalidateSession: (sessionId: string) => MaybePromise<void>

  invalidateUserSessions: (userId: string) => MaybePromise<void>

  constructor(config: DatabaseSessionConfig<TUser, TSession>) {
    super(config)

    this.getUser = config.getUser
    this.createSession = config.createSession
    this.invalidateSession = config.invalidateSession
    this.invalidateUserSessions = config.invalidateUserSessions
  }

  async getRequestSession(request: Request) {
    const token = getSessionToken(request)

    if (token == null) return null

    const session = await this.decode<TSession>({ ...this.jwt, token })

    if (session == null) return null

    const user = await this.getUser(session)

    return { session, user }
  }
}
