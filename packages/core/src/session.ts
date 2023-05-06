import { parse } from "cookie";
import { encode, decode } from "./security/jwt.js";
import { createCookiesOptions } from "./security/cookie.js";
import type { JWTOptions } from "./security/jwt.js";
import type { Cookie, CookiesOptions } from "./security/cookie.js";
import type { InternalRequest } from "./internal/request.js";
import type { InternalResponse } from "./internal/response.js";
import type { Awaitable, DeepPartial, Nullish } from './types.js'

const hourInSeconds = 60 * 60

const weekInSeconds = 7 * 24 * hourInSeconds

const DefaultAccessTokenMaxAge = hourInSeconds

const DefaultRefreshTokenMaxAge = weekInSeconds

/**
 * Ensure a possibly async value is a `Promise`.
 */
function asPromise<T>(value: Awaitable<T>): Promise<T> {
  return value instanceof Promise ? value : Promise.resolve(value)
}

interface NewSession { 
  user: Perdition.User,
  accessToken: Perdition.Session
  refreshToken?: Perdition.Refresh
}

interface TokenMaxAge {
  accessToken: number
  refreshToken: number
}

interface Pages {
  logoutRedirect: string
}

/**
 * Internal session configuration.
 */
export interface SessionConfig {
  secret: string

  pages: Partial<Pages>

  jwt: Required<Omit<JWTOptions, 'maxAge'>>

  cookies: CookiesOptions

  maxAge: Partial<TokenMaxAge>

  useSecureCookies?: boolean

  createSession?: (user: Perdition.User) => Awaitable<NewSession | Nullish>;

  getUserFromSession: (session: Perdition.Session) => Awaitable<Perdition.User | Nullish>;

  handleRefresh?: (
    tokens: { accessToken?: Perdition.Session | Nullish, refreshToken?: Perdition.Refresh | Nullish  }
  ) => Awaitable<NewSession | Nullish>;

  onInvalidateSession?: (
    session: Perdition.Session,
    refresh: Perdition.Refresh | Nullish,
    context: SessionManager,
  ) => Awaitable<InternalResponse | Nullish>
}

/**
 * Session user configuration.
 */
export interface SessionUserConfig extends 
  DeepPartial<Omit<SessionConfig, 'secret'>>,
  Required<Pick<SessionConfig, 'secret'>> {}

/**
 * Session manager.
 */
export class SessionManager {
  config: SessionConfig

  constructor(config: SessionUserConfig) {
    this.config = {
      ...config,
      secret: config.secret,
      pages: config.pages ?? {},
      jwt: {
        ...config.jwt,
        secret: config.secret,
        decode: config.jwt?.decode ?? decode,
        encode: config.jwt?.encode ?? encode,
      },
      cookies: createCookiesOptions(config.useSecureCookies),
      maxAge: { 
        accessToken: config.maxAge?.accessToken ?? DefaultAccessTokenMaxAge,
        refreshToken: config.maxAge?.refreshToken ?? DefaultRefreshTokenMaxAge,
      },
      getUserFromSession: config.getUserFromSession ?? ((session: Perdition.Session) => session as any),
    }
  }

  async decodeTokens(tokens: { accessToken?: string, refreshToken?: string }) {
    const access = await asPromise(
      this.config.jwt.decode<Perdition.Session>({ secret: this.config.secret, token: tokens.accessToken })
    ).catch(e => {
      console.log('Error decoding access token', e)
    })

    const refresh = await asPromise(
      this.config.jwt.decode<Perdition.Refresh>({ secret: this.config.secret, token: tokens.refreshToken })
    ).catch(e => {
      console.log('Error decoding access token', e)
    })

    return { access, refresh }
  }

  async createCookies(newSession: NewSession): Promise<Cookie[]> {
    const cookies: Cookie[] = []

    if (newSession?.accessToken) {
      cookies.push({
        name: this.config.cookies.accessToken.name,
        value: await this.config.jwt.encode({ 
          secret: this.config.secret,
          maxAge: this.config.maxAge.accessToken,
          token: newSession.accessToken
        }),
        options: {
          ...this.config.cookies.accessToken.options,
          maxAge: this.config.maxAge.accessToken,
        }
      })
    }

    if (newSession?.refreshToken) {
      cookies.push({
        name: this.config.cookies.refreshToken.name,
        value: await this.config.jwt.encode({
          secret: this.config.secret,
          maxAge: this.config.maxAge.refreshToken,
          token: newSession.refreshToken
        }),
        options: {
          ...this.config.cookies.refreshToken.options,
          maxAge: this.config.maxAge.refreshToken,
        }
      })
    }

    return cookies
  }

  /**
   * Get the user from a request.
   */
  async getUserFromRequest(request: InternalRequest): Promise<Perdition.User | Nullish> {
    const accessToken = request.cookies[this.config.cookies.accessToken.name]

    const { access } = await this.decodeTokens({ accessToken })
    if (!access) return null

    const user = await this.config.getUserFromSession(access)
    return user
  }

  /**
   * Handle a request by refreshing the user's session if necessary and possible.
   */
  async handleRequest(request: InternalRequest): Promise<InternalResponse> {
    const accessToken = request.cookies[this.config.cookies.accessToken.name]
    const refreshToken = request.cookies[this.config.cookies.refreshToken.name]

    // User is logged in or logged out and doesn't need to be refreshed.

    if (accessToken || (!accessToken && !refreshToken)) return {}

    // User is logged out, but can be refreshed.

    const { access, refresh } = await this.decodeTokens({ accessToken, refreshToken })

    const refreshedTokens = await this.config.handleRefresh?.({ accessToken: access, refreshToken: refresh })

    return {
      user: refreshedTokens?.user,
      cookies: refreshedTokens ? await this.createCookies(refreshedTokens) : undefined,
    }
  }

  /**
   * Log a user out.
   */
  async logout(request: Request): Promise<InternalResponse> {
    const cookies = parse(request.headers.get("cookie") ?? "")

    const accessToken = cookies[this.config.cookies.accessToken.name]

    const refreshToken = cookies[this.config.cookies.refreshToken.name]

    const { access, refresh } = await this.decodeTokens({ accessToken, refreshToken })

    const response = (access && await this.config.onInvalidateSession?.(access, refresh, this)) || {
      status: 302,
      redirect: this.config.pages.logoutRedirect,
    }

    response.cookies ??= []

    response.cookies.push(
      {
        name: this.config.cookies.accessToken.name,
        value: "",
        options: { ...this.config.cookies.accessToken.options, maxAge: 0, }
      }, 
      {
        name: this.config.cookies.refreshToken.name,
        value: "",
        options: { ...this.config.cookies.refreshToken.options, maxAge: 0, }
      }
    )

    return response
  }
}

/**
 * Create a new session manager.
 */
export function AponiaSession(config: SessionUserConfig): SessionManager {
  return new SessionManager(config)
}
