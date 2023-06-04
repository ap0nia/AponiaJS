/**
 * Possibly asynchronous value.
 */
export type Awaitable<T> = PromiseLike<T> | T

/**
 * Union of nullish values.
 */
export type Nullish = void | undefined | null

/**
 * Make all properties and sub-properties optional.
 */
export type DeepPartial<T> = {
  [k in keyof T]?: T[k] extends Record<string, unknown> ? DeepPartial<T[k]> : T[k]
}

/**
 * An auth page / endpoint.
 */
export interface PageEndpoint {
  /**
   * The route (url pathname) to the page.
   */
  route: string

  /**
   * The accepted HTTP methods for the page.
   */
  methods: string[]

  /**
   * The redirect url after visiting the page.
   */
  redirect?: string
}

/**
 * Pages handled by providers.
 */
export type ProviderPages = {
  /**
   * The provider's login page.
   */
  login: PageEndpoint

  /**
   * The provider's callback page. Mostly applicable for OAuth providers.
   */
  callback: PageEndpoint
}


export interface Session { 
  aponia: string
}
