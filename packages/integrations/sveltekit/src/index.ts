import type { Auth } from 'aponia'
import { json, redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'

export interface Options {
  /**
   * Which key to store the user under in locals, if found during hook.
   */
  localsUserKey?: string
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

    (event.locals as any)[options.localsUserKey ?? 'user'] = internalResponse.user

    return await resolve(event)
  }

  return handle
}

export default createAuthHandle
