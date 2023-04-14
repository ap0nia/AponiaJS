import { SessionManager } from '.'
import type { Session } from '.'
import type { SessionManagerConfig } from '.'

type Awaitable<T> = T | PromiseLike<T>

export interface DatabaseSessionManagerConfig<TUser, TSession> extends SessionManagerConfig<TUser, TSession> {
  /**
   * Create a session from a user ID, i.e. storing it in the database.
   * Session can then be used to create a session token.
   */
  createSession: (userId: string) => Awaitable<TSession>
}

/**
 * Database session manager extends the basic JWT-based session manager.
 *
 * Example flow:
 * 1. User logs in. Handle auth yourself.
 * 2. Call `createSession` to create a session in the database and return the session.
 * 3. Call `createSessionToken` to create a session token from the session.
 * 4. Store the session token in a cookie.
 * 5. On subsequent requests, call `getRequestSession` to get the session from the request cookies.
 */
export class DatabaseSessionManager<
  TUser = {}, 
  TSession extends Record<string, any> = Session,
> extends SessionManager<TUser, TSession> {

  createSession: (userId: string) => Awaitable<TSession>

  constructor(config: DatabaseSessionManagerConfig<TUser, TSession>) {
    super(config)
    this.createSession = config.createSession
  }
}
