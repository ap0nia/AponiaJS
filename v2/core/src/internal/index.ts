import { Awaitable, Nullish } from '../types'
import type { InternalRequest } from './request'
import type { InternalResponse } from './response'

export type Callback = (req: InternalRequest) => Awaitable<InternalResponse | Nullish>

export const handle = async (callback: Callback) => {
  return callback(undefined as any)
}
