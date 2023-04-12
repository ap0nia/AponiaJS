import { Google } from './providers/google'
import { Github } from './providers/github'
import { SvelteKit } from './integrations/sveltekit'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'

const svelteKitter = new SvelteKit({
  callbackUrl: '/auth/callback',
  providers: [
    new Github({
      clientId: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
    }),
    new Google({
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      redirect_uri: 'http://localhost:5173/auth/callback/google'
    })
  ]
})

export const { handle } = svelteKitter
