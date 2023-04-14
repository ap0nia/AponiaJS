import type { CookieSerializeOptions } from 'cookie'

type Override<Left, Right> = Omit<Left, keyof Right> & Right

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

export type InternalRequest = Override<Request, {
  url: URL
  cookies: Record<string, string>
}>
