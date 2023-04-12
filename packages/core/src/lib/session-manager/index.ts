import { parse } from 'cookie'

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
 * Default user object.
 */
export type User = {}


/**
 * After a user logs in with an account, a session can be created to persist login.
 */
export type Session = {
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
