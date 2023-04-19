import { Pages } from ".";
import type { InternalRequest } from "../../internal/request";
import type { InternalResponse } from "../../internal/response";
import type { CookiesOptions } from "../../security/cookie";
import type { JWTOptions } from "../../security/jwt";
import type { Provider } from '.'

type Awaitable<T> = PromiseLike<T> | T

export interface EmailConfig<TUser, TSession = TUser>  {
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
 * Email provider (first-party only).
 */
export class EmailProvider<TUser, TSession = TUser> implements Provider<InternalRequest, TUser, TSession> {
  id = 'credentials' as const

  onAuth: (user: InternalRequest) => Awaitable<InternalResponse<TUser, TSession>>

  pages: Pages

  constructor(config: EmailConfig<TUser, TSession>) {
    this.onAuth = config.onAuth
    this.pages = {
      login: config.pages?.login ?? `/auth/login/${this.id}`,
      callback: config.pages?.callback ?? `/auth/callback/${this.id}`,
    }
  }

  setJwtOptions(options: JWTOptions) {
    // this.jwt = options
    return this
  }

  setCookiesOptions(options: CookiesOptions) {
    // this.cookies = options
    return this
  }
  async login(request: InternalRequest): Promise<InternalResponse> {
    return this.onAuth(request)
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    return this.login(request)
  }
}

export function Email<TUser, TSession = TUser>(config: EmailConfig<TUser, TSession>) {
  return new EmailProvider<TUser, TSession>(config)
}
