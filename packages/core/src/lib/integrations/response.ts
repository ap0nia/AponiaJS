import type { CookieSerializeOptions } from 'cookie'

/**
 * Internally generated cookies.
 * @internal
 */
export interface Cookie {
  name: string
  value: string
  options?: CookieSerializeOptions
}

/**
 * Internal Response.
 * @internal
 */
export interface InternalResponse {
  status?: number
  headers?: Headers | HeadersInit
  session?: any 
  user?: any
  body?: any
  redirect?: string
  cookies?: Cookie[]
  error?: any
}
