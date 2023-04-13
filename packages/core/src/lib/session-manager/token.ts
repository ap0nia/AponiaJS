import { SessionManager } from ".";
import type { SessionManagerConfig } from ".";

export interface TokenSessionConfig<TUser, TSession> extends SessionManagerConfig {
  getUserFromSession?: (session: TSession) => TUser | null
}

/**
 * Token session interface.
 *
 * Example flow:
 * 1. User logs in. Handle auth yourself.
 * 2. Create your own session object.
 * 3. Call `createSessionToken` to create a session token from your session.
 * 4. Store the session token in a cookie.
 * 5. On subsequent requests, call `getRequestSession` to get the session from the request cookies.
 */
export class TokenSessionManager<
  TUser = {},
  TSession extends Record<string, any> = {}
> extends SessionManager<TUser, TSession> {

  getUserFromSession?: (session: TSession) => TUser | null

  constructor(config: TokenSessionConfig<TUser, TSession>) {
    super(config)

    this.getUserFromSession = config.getUserFromSession
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
