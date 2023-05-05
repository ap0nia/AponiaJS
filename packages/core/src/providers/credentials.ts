import type { InternalRequest } from "../internal/request.js";
import type { InternalResponse } from "../internal/response.js";
import type { Awaitable, DeepPartial, Nullish, ProviderPages } from "../types.js";

const noop = () => {}

export interface CredentialsConfig<T>  {
  /**
   * Handle the user logging in.
   */
  onAuth: (internalRequest: InternalRequest) => Awaitable<InternalResponse<T> | Nullish>

  /**
   * Pages.
   */
  pages: ProviderPages
}

export interface CredentialsUserConfig<T> extends DeepPartial<CredentialsConfig<T>> {}

/**
 * Credentials provider (first-party only).
 */
export class CredentialsProvider<T> {
  id = 'credentials' as const

  config: CredentialsConfig<T>

  constructor(config: CredentialsUserConfig<T>) {
    this.config = {
      onAuth: config.onAuth ?? noop,
      pages: {
        login: {
          route: config.pages?.login?.route ?? `/auth/login/${this.id}`,
          methods: config.pages?.login?.methods ?? ['POST'],
        },
        callback: {
          route: config.pages?.callback?.route ?? `/auth/callback/${this.id}`,
          methods: config.pages?.callback?.methods ?? ['GET'],
          redirect: config.pages?.callback?.redirect ?? '/',
        }
      }
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

  /**
   * Login user.
   */
  async login(request: InternalRequest): Promise<InternalResponse> {
    return (await this.config.onAuth(request)) ?? {}
  }

  /**
   * Login user.
   */
  async callback(request: InternalRequest): Promise<InternalResponse> {
    return (await this.config.onAuth(request)) ?? {}
  }
}

export function Credentials<TUser>(config: CredentialsUserConfig<TUser>) {
  return new CredentialsProvider<TUser>(config)
}
