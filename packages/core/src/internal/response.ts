import type { Cookie } from "../security/cookie"

/**
 * Internal Response.
 * @internal
 */
export interface InternalResponse<TUser = any> {
  user?: TUser
  status?: number
  redirect?: string
  cookies?: Cookie[]
  body?: any
  error?: any
}
