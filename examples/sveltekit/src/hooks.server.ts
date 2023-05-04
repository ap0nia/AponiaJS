import { AponiaAuth, AponiaSession, Credentials, GitHub, Google } from 'aponia'
import createAuthHandle from '@aponia/integrations-sveltekit'
import { sequence } from '@sveltejs/kit/hooks'
import type { Handle } from '@sveltejs/kit'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'

type User = { id: number }

type AponiaSession = User

type Refresh = User

const auth = AponiaAuth<User, AponiaSession, Refresh>({
  session: AponiaSession({
    secret: 'secret',
    createSession: async (user) => {
      return { user, accessToken: user, refreshToken: user }
    },
    handleRefresh: async (tokens) => {
      if (tokens.accessToken) return
      if (!tokens.refreshToken) return
    },
    onInvalidateSession: async (session) => {
      console.log('invalidating session: ', session)
    },
  }),
  providers: [
    Credentials({
      onAuth: async ({ request }) => {
        const formData = await request.formData()
        const body = Object.fromEntries(formData.entries())
        return { body }
      },
    }),
    GitHub({
      clientId: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      onAuth: async (user) => {
        return { user: { id: user.id }, redirect: '/', status: 302 }
      },
    }),
    Google({ 
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      onAuth: async (user) => {
        return { user: { ...user, id: 69 } }
      },
    }),
  ],
})

export const authHandle = createAuthHandle(auth)

export const customHandle: Handle = async ({ event, resolve }) => {
  console.log(event.locals)
  return await resolve(event)
}

export const handle = sequence(authHandle, customHandle)
