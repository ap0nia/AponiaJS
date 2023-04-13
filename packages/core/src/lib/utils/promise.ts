export type MaybePromise<T> = T | Promise<T>;

export type Awaitable<T> = T | PromiseLike<T>
