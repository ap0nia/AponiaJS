import type { Cookie } from "../security/cookie.js"
import type { Nullish } from "../types.js"

/**
 * An internally generated response.
 * Should be handled accordingly depending on the context of the usage.
 */
export interface InternalResponse<TUser = any> {
  /**
   * The decoded user. 
   * May only be defined if refresh ocurred or provider took action during current request.
   * Otherwise, 
   * 1. Get the encrypted session token from cookies
   * 2. Decrypt the session token to get session data
   * 3. Get the user from the session data, i.e. with a database lookup, or `session.config.getUserFromSession(session)`
   */
  user?: TUser | Nullish

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
  cookies?: Cookie[]

  /**
   * Any error that occurred.
   */
  error?: any
}
