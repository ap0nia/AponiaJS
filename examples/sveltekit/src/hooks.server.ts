import { AponiaAuth } from 'aponia'
import { AponiaSession } from 'aponia/session'
import { Google } from 'aponia/providers/google'
import { createAuthHelpers } from '@aponia/sveltekit'
import { AUTH_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, } from '$env/static/private'

const session = AponiaSession({ 
  secret: AUTH_SECRET,
  createSession(user) {
    return { user, accessToken: user, refreshToken: user }
  },
  pages: {
    logoutRedirect: '/'
  },
})

const google = Google({ 
  clientId: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  onAuth(user) {
    return { user, redirect: '/', status: 302 }
  },
})

const auth = AponiaAuth({
  session,
  providers: [google]
})

export const handle = createAuthHelpers(auth)
