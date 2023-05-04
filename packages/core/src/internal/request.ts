import { parse } from "cookie"

export interface InternalRequest {
  /**
   * Original request.
   */
  request: Request

  /**
   * Parsed request URL.
   */
  url: URL

  /**
   * Parsed cookies from original request cookie headers.
   */
  cookies: Record<string, string>
}

export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { request, url, cookies }
}
