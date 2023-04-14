import type { Override } from '$lib/utils/override'
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

export type InternalRequest = Override<Request, {
  url: URL
  cookies: Record<string, string>
}>
