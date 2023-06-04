import { Awaitable, Nullish } from './types'

export type Callback = (req: AponiaAuth.InternalRequest) => Awaitable<AponiaAuth.InternalResponse | Nullish>

export const handle = async (callback: Callback) => {
  return callback(undefined as any)
}


export * from './types.js'
