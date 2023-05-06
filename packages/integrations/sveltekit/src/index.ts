import type { Auth } from 'aponia'
import { RequestEvent, redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'

const defaultLocalsAuthKey = 'aponia-auth'

export interface Options {
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
  status != null && status >= 300 && status <= 308

export function createAuthHandle<TUser, TSession, TRefresh>(
  auth: Auth<TUser, TSession, TRefresh>,
  options: Options = {}
) {
  const getUser = async (event: RequestEvent) => {
    const accessToken = event.cookies.get(auth.session.config.cookies.accessToken.name)

    const { access } = await auth.session.decodeTokens({ accessToken })
    if (!access) return null

    const user = await auth.session.config.getUserFromSession(access)
    if (!user) return null

    return user
  }

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

    if (options.debug) {
      (event.locals as any)[options.localsAuthKey ?? defaultLocalsAuthKey] = internalResponse
    }

    return await resolve(event)
  }

  return { handle, getUser }
}

export default createAuthHandle
