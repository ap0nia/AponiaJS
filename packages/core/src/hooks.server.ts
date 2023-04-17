import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import GitHub from '@auth/core/providers/github'
import Google from '@auth/core/providers/google'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'
import { AponiaAuth } from './lib/internal'
import { OAuthProvider } from './lib/providers/oauth'
import { OIDCProvider } from './lib/providers/oidc'
import { SessionManager } from '$lib/session'

const auth = new AponiaAuth({
  session: new SessionManager({ secret: 'secret' }),
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
  const internalResponse = await auth.handle(event.request)

  if (internalResponse == null) {
    return await resolve(event)
  }

  if (internalResponse.cookies != null) {
    internalResponse.cookies.forEach((cookie) => {
      event.cookies.set(cookie.name, cookie.value, cookie.options)
    })
  }

  if (internalResponse.redirect != null && validRedirect(internalResponse.status)) {
    throw redirect(internalResponse.status, internalResponse.redirect)
  }

  return await resolve(event)
}

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status < 400
