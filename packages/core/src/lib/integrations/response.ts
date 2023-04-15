import { parse } from "cookie"
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
  body?: any
  redirect?: string
  cookies?: Cookie[]
}

export type InternalRequest = {
  url: URL
  cookies: Record<string, string>
}

export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { ...request, url, cookies }
}
