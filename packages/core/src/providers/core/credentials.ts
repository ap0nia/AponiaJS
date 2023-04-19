import { Pages } from ".";
import type { InternalRequest } from "../../internal/request";
import type { InternalResponse } from "../../internal/response";
import type { CookiesOptions } from "../../security/cookie";
import type { JWTOptions } from "../../security/jwt";
import type { Provider } from '.'

type Awaitable<T> = PromiseLike<T> | T

export interface CredentialsConfig<T>  {
  /**
   * Handle the user logging in.
   */
  onAuth: (user: InternalRequest) => Awaitable<InternalResponse<T>>

  /**
   * Pages.
   */
  pages?: Partial<Pages>
}

/**
 * Credentials provider (first-party only).
 */
export class CredentialsProvider<T> implements Provider<InternalRequest, T> {
  id = 'credentials' as const

  onAuth: (user: InternalRequest) => Awaitable<InternalResponse<T>>

  pages: Pages

  constructor(config: CredentialsConfig<T>) {
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

export function Credentials<TUser>(config: CredentialsConfig<TUser>) {
  return new CredentialsProvider<TUser>(config)
}
