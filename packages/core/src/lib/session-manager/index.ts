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

