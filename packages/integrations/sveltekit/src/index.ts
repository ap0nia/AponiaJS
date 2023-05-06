import { parse } from 'cookie'
import type { Auth, InternalRequest } from 'aponia'
import { redirect } from '@sveltejs/kit'
import type { Handle, RequestEvent } from '@sveltejs/kit'

const defaultLocalsUserKey = 'user'

const defaultLocalsAuthKey = 'aponia-auth'

export interface SvelteInternalRequest extends InternalRequest, Omit<RequestEvent, 'cookies'> {}

export interface Options<T extends InternalRequest = InternalRequest> {
  /**
   * Control what kind of request is passed to the auth library.
   */
  toInternalRequest: (requestEvent: RequestEvent) => T

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
}

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status <= 308

export function createAuthHelpers<
  TUser,
  TSession = TUser,
  TRefresh = undefined,
  TRequest extends InternalRequest = InternalRequest
>(auth: Auth<TUser, TSession, TRefresh, TRequest>, options: Options<TRequest>) {
  const getUser = async (event: RequestEvent): Promise<TUser | null> => {
    const initialUser = (event.locals as any)[options.localsUserKey ?? defaultLocalsUserKey]
    if (initialUser) return initialUser

    const accessToken = event.cookies.get(auth.session.config.cookies.accessToken.name)

    const { access } = await auth.session.decodeTokens({ accessToken })
    if (!access) return null

    const user = await auth.session.config.getUserFromSession(access)
    if (!user) return null

    return user
  }

  const handle: Handle = async ({ event, resolve }) => {
    const internalResponse = await auth.handle(options.toInternalRequest(event))

    if (internalResponse.cookies != null) {
      internalResponse.cookies.forEach((cookie) => {
        event.cookies.set(cookie.name, cookie.value, cookie.options)
      })
    }

    if (internalResponse.redirect != null && validRedirect(internalResponse.status)) {
      throw redirect(internalResponse.status, internalResponse.redirect)
    }

    (event.locals as any)[options.localsUserKey ?? defaultLocalsUserKey] = internalResponse.user

    if (options.debug) {
      (event.locals as any)[options.localsAuthKey ?? defaultLocalsAuthKey] = internalResponse
    }

    return await resolve(event)
  }

  return { handle, getUser }
}

export function defaultToInternalRequest(event: RequestEvent): SvelteInternalRequest {
  return { ...event, cookies: parse(event.request.headers.get('cookie') ?? '') }
}

export default createAuthHelpers
