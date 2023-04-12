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

export type SvelteKitConfig<T extends Strategy = 'none'> = {
  callbackUrl?: string
  providers: Provider<any>[]
  strategy?: T
} & (
  T extends 'jwt' 
  ? { sessionManager: TokenSessionManager } 
  : T extends 'database' ? { sessionManager: DatabaseSessionManager } 
  : object
)

const defaultConfig: Partial<SvelteKitConfig> = {
  callbackUrl: '/auth/callback',
  providers: [],
  strategy: 'none',
}

export class SvelteKit<T extends Strategy = 'none'> extends Integration<T> {
  constructor(config: SvelteKitConfig<T>) {
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

    if (internalResponse.redirect != null && this.validRedirect(internalResponse.status)) {
      throw redirect(internalResponse.status, internalResponse.redirect)
    }

    return await resolve(event)
  }
}
