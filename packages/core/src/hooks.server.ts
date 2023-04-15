import GitHub from '@auth/core/providers/github'
import Google from '@auth/core/providers/google'
import { Auth } from '$lib/integrations'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'
import { redirect, type Handle } from '@sveltejs/kit'

const auth = new Auth({
  providers: [
    GitHub({ clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET }),
    Google({ clientId: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET })
  ]
})

export const handle: Handle = async ({ event, resolve }) => {
  const internalResponse = await auth.handle(event.request)

  if (internalResponse == null) {
    return await resolve(event)
  }

  if (internalResponse.cookies != null) {
    internalResponse.cookies.forEach((cookie) => {
      event.cookies.set(cookie.name, cookie.value, cookie.options)
    })
  }

  if (internalResponse.headers != null) {
    event.setHeaders(
      internalResponse.headers instanceof Headers
      ? Object.fromEntries(internalResponse.headers.entries())
      : Object.fromEntries(Object.entries(internalResponse.headers))
    )
  }

  if (internalResponse.redirect != null && validRedirect(internalResponse.status)) {
    throw redirect(internalResponse.status, internalResponse.redirect)
  }

  return await resolve(event)
}

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status < 400
