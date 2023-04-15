import GitHub from '@auth/core/providers/github'
import Google from '@auth/core/providers/google'
import { Auth } from '$lib/integrations'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '$env/static/private'
import type { Handle } from '@sveltejs/kit'

const auth = new Auth({
  providers: [
    GitHub({ clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET }),
    Google({ clientId: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET })
  ]
})

export const handle: Handle = async ({ event, resolve }) => {
  const authResponse = await auth.handle(event.request)
  console.log({ authResponse })
  return await resolve(event)
}
