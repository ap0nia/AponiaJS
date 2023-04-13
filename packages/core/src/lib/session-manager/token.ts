import { SessionManager } from ".";
import type { SessionManagerConfig } from ".";

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
  constructor(config: SessionManagerConfig) {
    super(config)
  }

  async getRequestSession(request: Request) {
    const token = SessionManager.getSessionToken(request)

    if (token == null) return null

    const session = await this.decode<TSession>({ ...this.jwt, token })

    return { session, user: null }
  }
}
