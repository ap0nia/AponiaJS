import { STATE_COOKIE_NAME, type Provider } from '$lib/providers'
import type { TokenSessionManager } from '$lib/session-manager/token'
import type { DatabaseSessionManager } from '$lib/session-manager/database'
import type { InternalResponse } from './response'
import { SESSION_COOKIE_NAME } from '$lib/session-manager'

/**
 * `jwt`: Use a JWT token to store the user's session.
 * `database`: Store the user's session in a database.
 * `none`: Do not store the user's session.
 */
export type Strategy = 'jwt' | 'database' | 'none'

export type IntegrationConfig<T extends Strategy = 'jwt'> = {
  callbackUrl: string
  providers: Provider<any>[]
  strategy?: T
} & (
  T extends 'jwt' 
  ? { sessionManager: TokenSessionManager } 
  : T extends 'database' ? { sessionManager: DatabaseSessionManager } 
  : object
)

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

    const { pathname } = url

    try {
      switch (pathname) {
        case '/auth/session': {
          if (this.usingJwt()) {
          console.log(' jwt session ')
            const session = await this.config.sessionManager.getRequestSession(request)
            console.log(' session ', session)
          }

          if (this.usingDatabase()) {
            const session = await this.config.sessionManager.getRequestSession(request)
            console.log(' session ', session)
          }
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
          const [url, state] = provider.getAuthorizationUrl()
          return {
            redirect: url,
            status: 307,
            cookies: [{ value: state, name: STATE_COOKIE_NAME, options: { path: '/' } }]
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
              cookies: [{ value: sessionToken, name: SESSION_COOKIE_NAME, options: { path: '/' } }],
            }
          } 

          if (this.usingDatabase()) {
            const sessionToken = await this.config.sessionManager.createSessionToken(user)
            return {
              redirect: '/',
              status: 302,
              cookies: [{ value: sessionToken, name: SESSION_COOKIE_NAME, options: { path: '/' } }],
            }
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
      }
    } catch {}
  }
}
