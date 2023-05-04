import type { Auth } from 'aponia'
import { json, redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'

const defaultLocalsUserKey = 'user'

const defaultLocalsAuthKey = 'aponia-auth'

export interface Options {
  /**
   * Which key to store the user in locals, if found during hook.
   */
  localsUserKey?: keyof App.Locals

  /**
   * Which key to store the internally generated auth response in locals if debugging.
   */
  localsAuthKey?: keyof App.Locals

  /**
   * Whether to enable debugging.
   */
  debug?: boolean
}

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status < 400

export function createAuthHandle<TUser, TSession, TRefresh>(
  auth: Auth<TUser, TSession, TRefresh>,
  options: Options = {}
) {
  const handle: Handle = async ({ event, resolve }) => {
    const internalResponse = await auth.handle(event.request)

    if (internalResponse.cookies != null) {
      internalResponse.cookies.forEach((cookie) => {
        event.cookies.set(cookie.name, cookie.value, cookie.options)
      })
    }

    if (internalResponse.redirect != null && validRedirect(internalResponse.status)) {
      throw redirect(internalResponse.status, internalResponse.redirect)
    }

    if (internalResponse.body != null) {
      return json(internalResponse.body)
    }

    if (options.debug) {
      (event.locals as any)[options.localsAuthKey ?? defaultLocalsAuthKey] = internalResponse
    }

    (event.locals as any)[options.localsUserKey ?? defaultLocalsUserKey] = internalResponse.user

    return await resolve(event)
  }

  return handle
}

export default createAuthHandle
