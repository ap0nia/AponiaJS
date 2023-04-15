import GitHub from '@auth/core/providers/github'
import { Auth } from '$lib/integrations'
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET } from '$env/static/private'
import type { Handle } from '@sveltejs/kit'
import type { InternalRequest } from '$lib/integrations/response'

const auth = new Auth({
  providers: [
    GitHub({ clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET })
  ]
})

export const handle: Handle = async ({ event, resolve }) => {
  const req: InternalRequest = {
    ...event.request,
    cookies: {},
    url: new URL(event.request.url)
  }
  const internal = await auth.providers[0].signIn(req)
  console.log({ internal })
  return await resolve(event)
}
