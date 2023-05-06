import type { InternalRequest } from "../internal/request.js";
import type { InternalResponse } from "../internal/response.js";
import type { Awaitable, DeepPartial, Nullish, ProviderPages } from "../types.js";

/**
 * Internal configuration for the credentials provider.
 */
export interface CredentialsConfig<TUser, TRequest extends InternalRequest = InternalRequest> {
  onAuth?: (internalRequest: TRequest) => Awaitable<InternalResponse<TUser> | Nullish>
  pages: ProviderPages
}

/**
 * User configuration for the credentials provider.
 */
export interface CredentialsUserConfig<TUser, TRequest extends InternalRequest = InternalRequest> 
  extends DeepPartial<CredentialsConfig<TUser, TRequest>> {}

/**
 * Credentials provider.
 */
export class CredentialsProvider<TUser, TRequest extends InternalRequest = InternalRequest> {
  id = 'credentials' as const

  config: CredentialsConfig<TUser, TRequest>

  constructor(config: CredentialsUserConfig<TUser, TRequest>) {
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

  async login(request: TRequest): Promise<InternalResponse<TUser>> {
    return (await this.config.onAuth?.(request)) ?? {}
  }

  async callback(request: TRequest): Promise<InternalResponse<TUser>> {
    return (await this.config.onAuth?.(request)) ?? {}
  }
}

/**
 * Create a credentials provider.
 */
export function Credentials<TUser>(config: CredentialsUserConfig<TUser>) {
  return new CredentialsProvider(config)
}
