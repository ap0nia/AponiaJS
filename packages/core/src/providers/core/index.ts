import type { InternalResponse } from '../../internal/response'

export interface Provider<TProfile, TUser = TProfile, TSession = TUser> {
  onAuth: (user: TProfile) => InternalResponse<TUser, TSession>
}
