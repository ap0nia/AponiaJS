import { getSessionToken } from '.'
import type { User, Session } from '.'

type MaybePromise<T> = T | Promise<T>;

export type DatabaseSessionConfig<T = User> = {
  /**
   * Get a user by their ID.
   */
  getUser: (userId: string) => MaybePromise<T | null>

  /**
   * Create a session for a user.
   */
  createSession: (userId: string) => MaybePromise<Session>

  /**
   * Get a session by its ID.
   */
  getSession: (sessionId: string) => MaybePromise<Session | null>

  /**
   * Invalidate a session.
   */
  invalidateSession: (sessionId: string) => MaybePromise<void>

  /**
   * Invalidate all sessions for a user.
   */
  invalidateUserSessions: (userId: string) => MaybePromise<void>
}

/**
 * Database interface.
 */
export class DatabaseSession<T = User> implements DatabaseSessionConfig<T> {
  getUser: (userId: string) => MaybePromise<T | null>

  createSession: (userId: string) => MaybePromise<Session>

  getSession: (sessionId: string) => MaybePromise<Session | null>

  invalidateSession: (sessionId: string) => MaybePromise<void>

  invalidateUserSessions: (userId: string) => MaybePromise<void>

  constructor(methods: DatabaseSessionConfig<T>) {
    this.getUser = methods.getUser
    this.createSession = methods.createSession
    this.getSession = methods.getSession
    this.invalidateSession = methods.invalidateSession
    this.invalidateUserSessions = methods.invalidateUserSessions
  }

  async getRequestSession(request: Request) {
    const sessionToken = getSessionToken(request)

    const session = await this.getSession(sessionToken)

    if (session == null) throw new Error()

    if (session.expires < new Date().getTime()) throw new Error()

    return session
  }

  async getRequestUserSession(request: Request) {
    const session = await this.getRequestSession(request)

    const user = await this.getUser(session.user_id)

    if (user == null) throw new Error()

    return { user, session }
  }

  async validateSession(session: Session) {
    if (session.expires > new Date().getTime()) return session

    const newSession = await this.createSession(session.user_id)

    return newSession
  }

  async validateRequestUserSession(request: Request) {
    const { user, session } = await this.getRequestUserSession(request)

    const validSession = await this.validateSession(session)

    return { user, session: validSession }
  }
}
