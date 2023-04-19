import type { InternalResponse } from '../../internal/response'

export interface Pages {
  login: string
  callback: string
}

export interface Provider<TProfile, TUser = TProfile, TSession = TUser> {
  onAuth: (user: TProfile) => InternalResponse<TUser, TSession>
}
