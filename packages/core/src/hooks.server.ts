import { json, redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import GitHub from '@auth/core/providers/github'
import Google from '@auth/core/providers/google'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'
import { AponiaAuth } from './lib/integrations'
import { toInternalRequest } from './lib/integrations/request'
import { OAuthProvider } from './lib/providers/oauth'
import { OIDCProvider } from './lib/providers/oidc'

const auth = new AponiaAuth({
  secret: 'secret',
  providers: [
    new OAuthProvider(
      GitHub({ clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET })
    ),
    new OIDCProvider(
      Google({ clientId: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET })
    )
  ]
})

export const handle: Handle = async ({ event, resolve }) => {
  if (!auth.initialized) await auth.initialize()

  const internalRequest = await toInternalRequest(event.request)
  const internalResponse = await auth.handle(internalRequest)

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

  if (internalResponse.body != null) {
    return json(internalResponse.body)
  }

  return await resolve(event)
}

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status < 400
