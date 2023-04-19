import type { InternalResponse } from '../../internal/response'

type Awaitable<T> = PromiseLike<T> | T

export interface Pages {
  login: string
  callback: string
}

export interface Provider<TProfile, TUser = TProfile> {
  onAuth: (user: TProfile) => Awaitable<InternalResponse<TUser>>
}
