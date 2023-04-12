import { getSessionToken } from '.'
import { decode, encode } from '../jwt';
import type { User, Session } from '.'
import type { JwtConfig } from '../jwt';

type MaybePromise<T> = T | Promise<T>;

export type DatabaseSessionConfig<T = User> = {
  jwt: JwtConfig

  /**
   * Get a user by their ID.
   */
  getUser: (session: Session) => MaybePromise<T | null>

  /**
   * Create a session for a user.
   */
  createSession: (userId: string) => MaybePromise<Session>

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
 * Database session interface.
 */
export class DatabaseSessionManager<T = User> implements DatabaseSessionConfig<T> {
  jwt: JwtConfig

  getUser: (session: Session) => MaybePromise<T | null>

  createSession: (userId: string) => MaybePromise<Session>

  invalidateSession: (sessionId: string) => MaybePromise<void>

  invalidateUserSessions: (userId: string) => MaybePromise<void>

  constructor(config: DatabaseSessionConfig<T>) {
    this.jwt = config.jwt

    this.getUser = config.getUser
    this.createSession = config.createSession
    this.invalidateSession = config.invalidateSession
    this.invalidateUserSessions = config.invalidateUserSessions
  }

  async createSessionToken(userId: string) {
    const session = await this.createSession(userId)

    if (session == null) return null

    const token = await encode({ ...this.jwt, token: session })

    return token
  }

  async getRequestSession(request: Request) {
    const token = getSessionToken(request)

    if (token == null) return null

    const session = await decode<Session>({ ...this.jwt, token })

    if (session == null) return null

    const user = await this.getUser(session)

    return { session, user }
  }
}
