export type Awaitable<T> = PromiseLike<T> | T

export type Nullish = void | undefined | null

export type DeepPartial<T> = {
  [k in keyof T]?: T[k] extends Record<string, unknown> ? DeepPartial<T[k]> : T[k]
}

export type ProviderPages = {
  /**
   * Route for initial email login.
   */
  login: {
    route: string
    methods: string[]
  }

  /**
   * Callback route for email login verification.
   */
  callback: {
    route: string
    methods: string[]
    redirect: string
  }
}
