import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import type { ProviderConfig } from '../../providers'

export interface SvelteKitConfig {
  callbackUrl: string
  providers: ProviderConfig<any>[]
}

const defaultConfig: SvelteKitConfig = {
  callbackUrl: '/auth/callback',
  providers: []
}

export class SvelteKit {
  config: SvelteKitConfig
  callbacks: Record<string, ProviderConfig<any>>

  constructor(config: SvelteKitConfig = defaultConfig) {
    this.config = config

    this.callbacks = {}

    this.callbacks = this.config.providers.reduce((acc, p) => {
      acc[p.id] = p
      return acc
    }, this.callbacks)
  }

  handle: Handle = async ({ event, resolve }) => {
    if (event.url.pathname.startsWith('/auth/login')) {
      const providerId = event.url.pathname.split('/')[3]
      const provider = this.callbacks[providerId]
      if (provider) {
        const [url, state] = provider.getAuthorizationUrl()
        event.cookies.set('state', state, { path: '/', maxAge: 60 * 60 })
        throw redirect(302, url)
      }
    }

    if (event.url.pathname.startsWith('/auth/callback')) {
      const providerId = event.url.pathname.split('/')[3]
      const provider = this.callbacks[providerId]
      if (provider) {
        const tokens = await provider.getTokens(event.url.searchParams.get('code') ?? '')
        const user = await provider.getUser(tokens.access_token)
        event.cookies.set('user', JSON.stringify(user), { path: '/', maxAge: 60 * 60 })
      }
    }


    const response = resolve(event)
    return response
  }
}
