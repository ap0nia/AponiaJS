import type { Cookie } from "../security/cookie.js"
import type { Nullish } from "../types.js"

/**
 * An internally generated response.
 * Should be handled accordingly depending on the context of the usage.
 */
export interface InternalResponse {
  /**
   * The decoded user. 
   */
  user?: Perdition.User | Nullish

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
