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
export interface InternalResponse<TUser = any, TSession = any> {
  session?: TSession
  user?: TUser
  status?: number
  redirect?: string
  cookies?: InternalCookie[]
  body?: any
  error?: any
}
