import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import type { ProviderConfig } from '../../../oauth/src/providers'

export interface SvelteKitConfig {
  callbackUrl: string
  providers: ProviderConfig<any>[]
}


export class SvelteKit {
  config: SvelteKitConfig
  callbacks: Record<string, ProviderConfig<any>>

  constructor(config: SvelteKitConfig) {
    this.config = config

    this.callbacks = {}

    this.callbacks = this.config.providers.reduce((acc, p) => {
      acc[p.id] = p
      return acc
    }, this.callbacks)
  }

  handle: Handle = async ({ event, resolve }) => {
    const response = resolve(event)

    if (event.url.pathname.startsWith('/auth/callback')) {
      const providerId = event.url.pathname.split('/')[3]
      const provider = this.callbacks[providerId]
      const tokens = await provider.getTokens(event.url.searchParams.get('code') ?? '')
      const user = await provider.getUser(tokens.access_token)
      event.cookies.set('user', JSON.stringify(user))
    }

    if (event.url.pathname.startsWith('/auth/login')) {
      const providerId = event.url.pathname.split('/')[3]
      const provider = this.callbacks[providerId]
      const [url, state] = provider.getAuthorizationUrl()
      event.cookies.set('state', state, { path: '/', maxAge: 60 * 60 })
      throw redirect(302, url)
    }

    return response
  }
}
