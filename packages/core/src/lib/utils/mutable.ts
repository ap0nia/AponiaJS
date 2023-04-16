/**
 * Make all properties of T mutable.
 * @example Mutable<oauth.AuthorizationServer>
 */
export type Mutable<T> = { -readonly [k in keyof T]: T[k] }
