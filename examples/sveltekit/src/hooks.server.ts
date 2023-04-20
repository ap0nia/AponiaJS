import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import { Aponia, GitHub, Google, TokenSession } from 'aponia'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'

interface User {
  id: number
  name: string
}

interface Session extends User {}

interface Refresh extends User {}

const auth = Aponia<User, Session, Refresh>({
  session: TokenSession({
    secret: 'secret',
    createSession(user) {
      return { accessToken: user, refreshToken: user }
    },
    refreshSession(refreshToken) {
      return { accessToken: refreshToken, refreshToken }
    },
    onInvalidateSession(session) {
      console.log('invalidating session: ', session)
    },
  }),
  providers: [
    GitHub({ 
      clientId: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      onAuth(user) {
        user.id
        user.bio
        user.email
        // ...
        return { user: { id: 100, name: user.url }}
      },
    }),
    Google({ 
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      onAuth(user) {
        user.email
        user.name
        user.family_name
        // ...
        return { user: { id: 69, name: user.name }}
      },
    }),
  ],
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
