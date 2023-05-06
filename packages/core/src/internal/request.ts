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
