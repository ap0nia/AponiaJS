import type { InternalRequest } from "../internal/request.js";
import type { InternalResponse } from "../internal/response.js";
import type { Awaitable, DeepPartial, Nullish, ProviderPages } from "../types.js";

/**
 * Internal configuration for the credentials provider.
 */
export interface CredentialsConfig<T>  {
  onAuth?: (internalRequest: InternalRequest) => Awaitable<InternalResponse<T> | Nullish>
  pages: ProviderPages
}

/**
 * User configuration for the credentials provider.
 */
export interface CredentialsUserConfig<T> extends DeepPartial<CredentialsConfig<T>> {}

/**
 * Credentials provider.
 */
export class CredentialsProvider<T> {
  id = 'credentials' as const

  config: CredentialsConfig<T>

  constructor(config: CredentialsUserConfig<T>) {
    this.config = {
      ...config,
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

  setJwtOptions() {
    return this
  }

  setCookiesOptions() {
    return this
  }

  async login(request: InternalRequest): Promise<InternalResponse> {
    return (await this.config.onAuth?.(request)) ?? {}
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    return (await this.config.onAuth?.(request)) ?? {}
  }
}

/**
 * Create a credentials provider.
 */
export function Credentials<TUser>(config: CredentialsUserConfig<TUser>) {
  return new CredentialsProvider<TUser>(config)
}
