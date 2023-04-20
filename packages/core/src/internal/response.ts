import type { Cookie } from "../security/cookie.js"

/**
 * Internal Response.
 * @internal
 */
export interface InternalResponse<TUser = any> {
  /**
   * User created during login or refresh.
   */
  user?: TUser

  /**
   * Response status.
   */
  status?: number

  /**
   * Redirect URL.
  */
  redirect?: string

  /**
   * Cookies to set.
   */
  cookies?: Cookie[]

  /**
   * Response body, i.e. for internal routes that can render pages.
   */
  body?: any

  /**
   * Error.
   */
  error?: any
}
