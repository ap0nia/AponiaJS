declare namespace AponiaAuth {
  /**
   * The user that can be __identified__ by a session.
   *
   * @example username, email, profile picture, etc.
   */
  export interface User { id: number }

  /**
   * The data stored in a JWT, encrypted access token, and then into a cookie.
   * Should be short-lived and contain minimal data needed to identify the user.
   * Refreshed with relevant data from a refresh token.
   *
   * @example session ID, user ID, etc.
   *
   * An access token can be the same as the user.
   * Or it may contain a session ID or user ID which is subsequently used to identify the user.
   */
  export interface AccessToken extends User { }

  /**
   * Data that's used to refresh an access token.
   *
   * @example Session ID: Look up the session in the database, extend the expiration data, create tokens.
   * @example User ID: Look up the user in the database, create new tokens with new expiration dates.
   * @example User: Just create new tokens with new expiration dates.
   */
  export interface RefreshToken { }

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
   * An internally generated response.
   * Should be handled accordingly depending on the context of the usage.
   */
  export interface InternalResponse {
    /**
     * The decoded user. 
     */
    user?: AponiaAuth.User | Nullish

    /**
     * HTTP status code.
     */
    status?: number

    /**
     * The response redirect url.
     */
    redirect?: string

    /**
     * Cookies to set.
     */
    cookies?: (import('./security/cookie').Cookie)[] 

    /**
     * Any error that occurred.
     */
    error?: Error

    /**
     * Response body.
     */
    body?: unknown
  }
}
