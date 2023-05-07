import { parse } from 'cookie'
import type { Auth, InternalRequest } from 'aponia'
import { redirect, error } from '@sveltejs/kit'
import type { Handle, RequestEvent } from '@sveltejs/kit'

const defaultLocalsUserKey = 'user'

const defaultLocalsAuthKey = 'aponia-auth'

export interface SvelteInternalRequest extends InternalRequest, Omit<RequestEvent, 'cookies'> {}

export type Options<T extends InternalRequest = InternalRequest> = {
  /**
   * Key to store the user in locals.
   * User will only be defined if the session was refreshed or provider action occurred during the current request.
   */
  localsUserKey?: keyof App.Locals

  /**
   * Key to store the internally generated auth response in locals if debugging.
   */
  localsAuthKey?: keyof App.Locals

  /**
   * Whether to enable debugging.
   */
  debug?: boolean
} & (
  T extends SvelteInternalRequest 
  ? { toInternalRequest?: (requestEvent: RequestEvent) => T } 
  : { toInternalRequest: (requestEvent: RequestEvent) => T }
)

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status <= 308

export function defaultToInternalRequest(event: RequestEvent): SvelteInternalRequest {
  return { ...event, cookies: parse(event.request.headers.get('cookie') ?? '') }
}

export function createAuthHelpers<
  TUser,
  TSession = TUser,
  TRefresh = undefined,
  TRequest extends InternalRequest = InternalRequest
>(auth: Auth<TUser, TSession, TRefresh, TRequest>, options: Options<TRequest> = {} as any) {
  const localsUserKey = options.localsUserKey ?? defaultLocalsUserKey
  const localsAuthKey = options.localsAuthKey ?? defaultLocalsAuthKey

  const handle: Handle = async ({ event, resolve }) => {
    const toInternalRequest = options.toInternalRequest ?? defaultToInternalRequest

    const internalResponse = await auth.handle(toInternalRequest(event) as TRequest)

    internalResponse.cookies?.forEach((cookie) => {
      event.cookies.set(cookie.name, cookie.value, cookie.options)
    })

    if (internalResponse.redirect != null && validRedirect(internalResponse.status)) {
      throw redirect(internalResponse.status, internalResponse.redirect)
    }

    (event.locals as any)[localsUserKey] = internalResponse.user

    if (options.debug) {
      (event.locals as any)[localsAuthKey] = internalResponse
    }

    if (internalResponse.error) {
      throw error(internalResponse.status ?? 404, internalResponse.error)
    }

    return await resolve(event)
  }

  const getUser = async (event: RequestEvent): Promise<TUser | null> => {
    const initialUser = (event.locals as any)[localsUserKey]
    if (initialUser) return initialUser

    const accessToken = event.cookies.get(auth.session.config.cookies.accessToken.name)

    const { access } = await auth.session.decodeTokens({ accessToken })
    if (!access) return null

    const user = await auth.session.config.getUserFromSession(access)
    if (!user) return null

    return user
  }

  return { 
    /**
     * SvelteKit `handle` function for hooks.server.ts .
     */
    handle,

    /**
     * Lazily decode the user from `event.locals`
     */
    getUser 
  }
}

export default createAuthHelpers
