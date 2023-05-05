export type Awaitable<T> = PromiseLike<T> | T

export type Nullish = void | undefined | null

export type DeepPartial<T> = {
  [k in keyof T]?: T[k] extends Record<string, unknown> ? DeepPartial<T[k]> : T[k]
}

export interface PageEndpoint {
  route: string
  methods: string[]
  redirect?: string
}

export type ProviderPages = {
  login: PageEndpoint
  callback: PageEndpoint
}
