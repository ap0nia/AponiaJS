import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import { Auth, GitHub, Google } from 'aponia'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'
import { TokenSessionManager } from 'aponia/dist/session/token'

interface User {
  id: number
  name: string
}

interface Session extends User {}

interface Refresh {}

const auth = new Auth<User, Session, Refresh>({
  session: new TokenSessionManager({
    secret: 'secret',
    createSession(user) {
      console.log({ user })
      return { session: { id: 123, name: '' }, refresh: {} }
    },
    refreshSession(refresh) {
      console.log({ refresh: '' })
    },
  }),
  providers: [
    GitHub({ 
      clientId: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      onAuth(user) {
        console.log(user)
        return {}
      },
    }),
    Google({ 
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      onAuth(user) {
        console.log(user)
        return {}
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
