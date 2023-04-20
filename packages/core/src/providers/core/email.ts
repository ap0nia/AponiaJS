import type { InternalRequest } from "../../internal/request.js";
import type { InternalResponse } from "../../internal/response.js";

type Awaitable<T> = PromiseLike<T> | T

interface Pages {
  login: string
  callback: string
}

export interface EmailConfig<TUser>  {
  /**
   * Handle the user logging in.
   */
  onAuth: (user: InternalRequest) => Awaitable<InternalResponse<TUser>>

  /**
   * Pages.
   */
  pages?: Partial<Pages>
}

/**
 * Email provider (first-party only).
 */
export class EmailProvider<T> {
  id = 'credentials' as const

  onAuth: (user: InternalRequest) => Awaitable<InternalResponse<T>>

  pages: Pages

  constructor(config: EmailConfig<T>) {
    this.onAuth = config.onAuth
    this.pages = {
      login: config.pages?.login ?? `/auth/login/${this.id}`,
      callback: config.pages?.callback ?? `/auth/callback/${this.id}`,
    }
  }

  /**
   * Credentials doesn't use JWT.
   */
  setJwtOptions() {
    return this
  }

  /**
   * Credentials doesn't use cookies.
   */
  setCookiesOptions() {
    return this
  }


  async login(request: InternalRequest): Promise<InternalResponse> {
    return this.onAuth(request)
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    return this.login(request)
  }
}

export function Email<T>(config: EmailConfig<T>) {
  return new EmailProvider<T>(config)
}
