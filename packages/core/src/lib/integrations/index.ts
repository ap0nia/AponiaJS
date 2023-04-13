import { ACCESS_TOKEN_COOKIE_NAME } from '$lib/session-manager'
import { STATE_COOKIE_NAME } from '$lib/providers'
import type { Provider } from '$lib/providers'
import type { SessionManager } from '$lib/session-manager'
import type { DatabaseSessionManager } from '$lib/session-manager/database'
import type { InternalResponse } from './response'

/**
 * `jwt`: Use a JWT token to store the user's session.
 * `database`: Store the user's session in a database.
 * `none`: Do not store the user's session.
 */
export type Strategy = 'jwt' | 'database' | 'none'

export type IntegrationConfig<T extends Strategy = 'none'> = {
  callbackUrl: string
  providers: Provider[]
  strategy?: T
} & (
  T extends 'jwt' 
  ? { sessionManager: SessionManager } 
  : T extends 'database' ? { sessionManager: DatabaseSessionManager } 
  : object
)

const defaultConfig: IntegrationConfig = {
  callbackUrl: '/auth/callback',
  providers: [],
}

export class Integration<T extends Strategy = 'none'> {
  config: IntegrationConfig<T>

  callbacks: Map<string, Provider>

  constructor(config: Partial<IntegrationConfig<T>> = {}) {
    this.config = { ...defaultConfig, ...config } as any

    this.callbacks = new Map()

    this.callbacks = this.config.providers.reduce((acc, p) => {
      acc.set(p.id, p)
      return acc
    }, this.callbacks)
  }

  using<T extends Strategy>(strategy: T): this is Integration<T> {
    return (this.config.strategy ?? '')  as any === strategy
  }

  async handleInternal(request: Request): Promise<InternalResponse | void> {
    const url = new URL(request.url)

    const { pathname } = url

    try {
      switch (pathname) {
        case '/auth/session': {
          if (!(this.using('jwt') || this.using('database'))) break
          const session = await this.config.sessionManager.getRequestSession(request)
          console.log({ session })
        }
      }
    } catch {}

    const splitPath = pathname.split('/')

    const providerId = splitPath.pop() ?? ''

    const provider = this.callbacks.get(providerId)

    if (!provider) return

    try {
      switch (splitPath.join('/')) {
        case '/auth/login': {
          const [url, state] = provider.handleLogin(request)
          return {
            redirect: url,
            status: 307,
            cookies: [{ value: state, name: STATE_COOKIE_NAME, options: { path: '/' } }]
          }
        }

        case '/auth/callback': {
          const user = await provider.handleLogin(request)

          if (!(this.using('jwt') || this.using('database'))) {
            return { redirect: '/', status: 302 }
          }

          const sessionToken = await this.config.sessionManager.createSessionToken(user)

          return {
            redirect: '/',
            status: 302,
            cookies: [{ value: sessionToken, name: ACCESS_TOKEN_COOKIE_NAME, options: { path: '/' } }],
          }
        }

        case '/auth/logout': {
          return
        }
      }
    } catch (e) {
      console.error('error: ', e)
    }
  }
}
