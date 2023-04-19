import type { Cookie } from "../security/cookie"

/**
 * Internal Response.
 * @internal
 */
export interface InternalResponse<TUser = any, TSession = TUser> {
  user?: TUser
  session?: TSession
  status?: number
  redirect?: string
  cookies?: Cookie[]
  body?: any
  error?: any
}
