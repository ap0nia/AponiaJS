import type { CookieSerializeOptions } from 'cookie'

/**
 * Internally generated cookies.
 * @internal
 */
export interface InternalCookie {
  name: string
  value: string
  options?: CookieSerializeOptions
}

/**
 * Internal Response.
 * @internal
 */
export interface InternalResponse<TUser = any, TSession = TUser> {
  user?: TUser
  session?: TSession
  status?: number
  redirect?: string
  cookies?: InternalCookie[]
  body?: any
  error?: any
}
