import type { Cookie } from "../security/cookie.js"
import type { Nullish } from "../types.js"

export interface InternalResponse<TUser = any> {
  user?: TUser | Nullish
  status?: number
  redirect?: string
  cookies?: Cookie[]
  body?: any
  error?: any
}
