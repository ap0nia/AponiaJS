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
 * Internal Response. `data` is used to share data between handlers and callbacks.
 * @internal
 */
export interface InternalResponse<T = any> {
  status?: number
  headers?: Headers | HeadersInit
  data?: T
  body?: any
  redirect?: string
  cookies?: Cookie[]
}
