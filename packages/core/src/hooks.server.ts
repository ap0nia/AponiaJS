import { Google } from '$lib/providers/google'
import { GitHub } from '$lib/providers/github'
import { SvelteKit } from '$lib/integrations/sveltekit'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'
import { TokenSessionManager } from '$lib/session-manager/token'

const svelteKitter = new SvelteKit({
  strategy: 'jwt',
  callbackUrl: '/auth/callback',
  providers: [
    new GitHub({
      clientId: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
    }),
    new Google({
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      redirect_uri: 'http://localhost:5173/auth/callback/google',
    })
  ],
  sessionManager: new TokenSessionManager({ secret: 'secret' })
})

export const { handle } = svelteKitter
