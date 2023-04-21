import { eq } from 'drizzle-orm'
import { Aponia, TokenSession, Credentials, GitHub, Google } from 'aponia'
import createAuthHandle from '@aponia/integrations-sveltekit'
import { sequence } from '@sveltejs/kit/hooks'
import type { Handle } from '@sveltejs/kit'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'
import db from '$lib/server/db'
import { employees } from '$drizzle/schema'

type User = { id: number }

type Session = User

type Refresh = User

const auth = Aponia<User, Session, Refresh>({
  session: TokenSession({
    secret: 'secret',
    createSession: async (user) => {
      return { accessToken: user, refreshToken: user }
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
        const foundUser = db.select().from(employees).where(eq(employees.id, 1)).get()
        return { user, foundUser }
      },
    }),
    Google({ 
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      onAuth: async (user) => {
        user.email
        user.name
        user.family_name
        // ...
        return { user: {...user, id: 69 } }
      },
    }),
  ],
})

export const authHandle = createAuthHandle(auth)

export const customHandle: Handle = async ({ event, resolve }) => {
  // const allEmployees = db.select().from(employees).all()
  return await resolve(event)
}

export const handle = sequence(authHandle, customHandle)
