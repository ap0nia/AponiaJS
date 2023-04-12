import type { Provider } from '$lib/providers'
import type { TokenSessionManager } from '$lib/session-manager/token'
import type { DatabaseSessionManager } from '$lib/session-manager/database'
import type { InternalResponse } from './response'

/**
 * `jwt`: Use a JWT token to store the user's session.
 * `database`: Store the user's session in a database.
 * `none`: Do not store the user's session.
 */
type Strategy = 'jwt' | 'database' | 'none'

export type IntegrationConfig<T extends Strategy = 'jwt'> = {
  callbackUrl: string
  providers: Provider<any>[]
  strategy: T
  sessionManager: T extends 'jwt' ? TokenSessionManager : DatabaseSessionManager
}

const defaultConfig: IntegrationConfig = {
  callbackUrl: '/auth/callback',
  providers: [],
  strategy: 'jwt',
  sessionManager: Object.create(null),
}

export class Integration<T extends Strategy = 'jwt'> {
  config: IntegrationConfig<T>

  callbacks: Map<string, Provider<any>>

  constructor(config: Partial<IntegrationConfig<T>> = {}) {
    this.config = { ...defaultConfig, ...config } as any

    this.callbacks = new Map()

    this.callbacks = this.config.providers.reduce((acc, p) => {
      acc.set(p.id, p)
      return acc
    }, this.callbacks)
  }

  usingJwt(): this is Integration<'jwt'> {
    return this.config.strategy === 'jwt'
  }

  usingDatabase(): this is Integration<'database'> {
    return this.config.strategy === 'database'
  }

  async handleInternal(request: Request): Promise<InternalResponse | void> {
    const url = new URL(request.url)

    const pathname = url.pathname.split('/')

    const providerId = pathname.pop() ?? ''

    const provider = this.callbacks.get(providerId)

    if (!provider) return

    switch (pathname.join('/')) {
      case '/auth/login': {
        const [url, state] = provider.getAuthorizationUrl()
        return {
          redirect: url,
          status: 307,
          cookies: [{ value: state, name: 'state' }]
        }
      }

      case '/auth/callback': {
        if (provider._authenticateRequestMethod !== request.method) return

        const user = await provider.authenticateRequest(request)

        if (this.usingJwt()) {
          const sessionToken = await this.config.sessionManager.createSessionToken(user)
          return {
            redirect: '/',
            status: 302,
            cookies: [{ value: sessionToken, name: 'session' }],
          }
        } 

        if (this.usingDatabase()) {
          return
        }

        return { redirect: '/', status: 302 }
      }

      case '/auth/logout': {
        if (this.usingJwt()) {
        }

        if (this.usingDatabase()) {
        }
        return
      }

      default:  
        return
    }
  }
}
