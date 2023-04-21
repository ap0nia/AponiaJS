import type { InternalRequest } from "../../internal/request.js";
import type { InternalResponse } from "../../internal/response.js";

type Nullish = void | null | undefined

type Awaitable<T> = PromiseLike<T> | T

interface Pages {
  login: {
    route: string
    methods: string[]
  }
  callback: {
    route: string
    methods: string[]
  }
}

export interface CredentialsConfig<T>  {
  /**
   * Handle the user logging in.
   */
  onAuth: (internalRequest: InternalRequest) => Awaitable<InternalResponse<T> | Nullish>

  /**
   * Pages.
   */
  pages?: Partial<Pages>
}

/**
 * Credentials provider (first-party only).
 */
export class CredentialsProvider<T> {
  id = 'credentials' as const

  pages: Pages

  onAuth: (internalRequest: InternalRequest) => Awaitable<InternalResponse<T> | Nullish>

  constructor(config: CredentialsConfig<T>) {
    this.onAuth = config.onAuth
    this.pages = {
      login: {
        route: config.pages?.login?.route ?? `/auth/login/${this.id}`,
        methods: config.pages?.login?.methods ?? ['POST'],
      },
      callback: {
        route: config.pages?.callback?.route ?? `/auth/callback/${this.id}`,
        methods: config.pages?.callback?.methods ?? ['GET'],
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
    return (await this.onAuth(request)) ?? {}
  }

  /**
   * Login user.
   */
  async callback(request: InternalRequest): Promise<InternalResponse> {
    return (await this.onAuth(request)) ?? {}
  }
}

export function Credentials<TUser>(config: CredentialsConfig<TUser>) {
  return new CredentialsProvider<TUser>(config)
}
