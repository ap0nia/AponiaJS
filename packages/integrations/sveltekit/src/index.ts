import type { Auth } from 'aponia'
import { json, redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status < 400

export function createAuthHandle<TUser, TSession, TRefresh>(auth: Auth<TUser, TSession, TRefresh>) {
  const handle: Handle = async ({ event, resolve }) => {
    const internalResponse = await auth.handle(event.request)

    console.log({ internalResponse })

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

    return await resolve(event)
  }

  return handle
}

export default createAuthHandle
