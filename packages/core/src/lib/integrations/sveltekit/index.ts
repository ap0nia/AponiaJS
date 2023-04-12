import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import type { Provider } from '../../providers'
import type { TokenSessionManager } from '$lib/session-manager/token'
import type { DatabaseSessionManager } from '$lib/session-manager/database'
import { Integration } from '..'

/**
 * `jwt`: Use a JWT token to store the user's session.
 * `database`: Store the user's session in a database.
 * `none`: Do not store the user's session.
 */
type Strategy = 'jwt' | 'database' | 'none'

export type SvelteKitConfig<T extends Strategy = 'jwt'> = {
  callbackUrl: string
  providers: Provider<any>[]
  strategy: T
  sessionManager: T extends 'jwt' ? TokenSessionManager : DatabaseSessionManager
}

const defaultConfig: SvelteKitConfig = {
  callbackUrl: '/auth/callback',
  providers: [],
  strategy: 'jwt',
  sessionManager: Object.create(null),
}

export class SvelteKit<T extends Strategy = 'jwt'> extends Integration<T> {
  constructor(config: Partial<SvelteKitConfig<T>> = {}) {
    super({ ...defaultConfig, ...config } as any)
  }

  validRedirect(status?: number): status is Parameters<typeof redirect>[0] {
    return status != null && status >= 300 && status < 400
  }

  handle: Handle = async ({ event, resolve }) => {
    const internalResponse = await super.handleInternal(event.request)

    if (internalResponse == null) {
      return await resolve(event)
    }

    if (internalResponse.redirect != null && this.validRedirect(internalResponse.status)) {
      throw redirect(internalResponse.status, internalResponse.redirect)
    }

    if (internalResponse.cookies != null) {
      internalResponse.cookies.forEach((cookie) => {
        event.cookies.set(cookie.name, cookie.value, cookie.options)
      })
    }

    if (internalResponse.headers != null) {
      event.setHeaders(
        internalResponse.headers instanceof Headers
        ? Object.fromEntries(internalResponse.headers.entries())
        : Object.fromEntries(Object.entries(internalResponse.headers))
      )
    }

    return await resolve(event)
  }
}
