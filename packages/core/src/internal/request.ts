import { parse } from "cookie"

/**
 * Request object used internally.
 */
export interface InternalRequest {
  /**
   * The original request.
   */
  request: Request

  /**
   * The request's parsed url.
   */
  url: URL

  /**
   * The request's cookies.
   */
  cookies: Record<string, string>
}

/**
 * Convert a `Request` to an `InternalRequest`.
 */
export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { request, url, cookies }
}
