import { Pages } from ".";
import type { InternalRequest } from "../../internal/request";
import type { InternalResponse } from "../../internal/response";

type Awaitable<T> = PromiseLike<T> | T

export interface CredentialsConfig<TUser, TSession = TUser>  {
  /**
   * Handle the user logging in.
   */
  onAuth: (user: InternalRequest) => Awaitable<InternalResponse<TUser, TSession>>

  /**
   * Pages.
   */
  pages?: Partial<Pages>
}

/**
 * Credentials provider (first-party only).
 */
export class CredentialsProvider<TUser, TSession = TUser> {
  id = 'credentials' as const

  onAuth: (user: InternalRequest) => Awaitable<InternalResponse<TUser, TSession>>

  pages: Pages

  constructor(config: CredentialsConfig<TUser, TSession>) {
    this.onAuth = config.onAuth
    this.pages = {
      login: config.pages?.login ?? `/auth/login/${this.id}`,
      callback: config.pages?.callback ?? `/auth/callback/${this.id}`,
    }
  }

  async login(request: InternalRequest): Promise<InternalResponse> {
    return this.onAuth(request)
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    return this.login(request)
  }
}

export default function Credentials<TUser, TSession = TUser>(config: CredentialsConfig<TUser, TSession>) {
  return new CredentialsProvider<TUser, TSession>(config)
}
