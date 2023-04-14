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
  body?: Body
  redirect?: string
  cookies?: Cookie[]
}

export interface InternalRequest extends Request {
  cookies: Record<string, string>
}
