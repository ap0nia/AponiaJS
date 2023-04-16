import { parse } from 'cookie'
import type { Awaitable } from '@auth/core/types'
import { encode, decode } from './security/jwt'
import type { JWTOptions, JWTEncodeParams, JWTDecodeParams } from './security/jwt'
import { defaultCookies, type InternalCookiesOptions } from './security/cookie'

export function getRequestTokens(request: Request, options: InternalCookiesOptions) {
  const cookies = parse(request.headers.get('cookie') ?? '')

  const access_token = cookies[options.sessionToken.name]

  const refresh_token = cookies[options.refreshToken.name]

  return { access_token, refresh_token }
}

export interface Session {
  id: string;

  user_id: string;

  expires: number | bigint;
}

export interface SessionManagerConfig<TUser, TSession> {
  jwt?: JWTOptions

  cookies?: Partial<InternalCookiesOptions>

  useSecureCookies?: boolean

  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  invalidateSession?: (sessionId: string) => Awaitable<void>

  invalidateUserSessions?: (userId: string) => Awaitable<void>

  createSession?: (userId: string) => Awaitable<TSession>
}

export class SessionManager<TUser = {}, TSession extends Record<string, any> = Session> {
  jwt: JWTOptions

  cookies: InternalCookiesOptions

  encode: (params: JWTEncodeParams) => Awaitable<string>

  decode: <T>(params: JWTDecodeParams) => Awaitable<T | null>

  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  invalidateSession: (sessionId: string) => Awaitable<void> 

  invalidateUserSessions: (userId: string) => Awaitable<void>

  createSession: (userId: string) => Awaitable<TSession>

  constructor(config: SessionManagerConfig<TUser, TSession>) {
    this.jwt = config?.jwt ?? { secret: '' }
    this.cookies = { ...defaultCookies(config.useSecureCookies), ...config.cookies }
    this.encode = config.jwt?.encode ?? encode
    this.decode = config.jwt?.decode ?? decode
    this.getUserFromSession = config.getUserFromSession
    this.invalidateSession = config.invalidateSession ?? (() => {})
    this.invalidateUserSessions = config.invalidateUserSessions ?? (() => {})
    this.createSession = config.createSession ?? ((session) => ({ session } as any))
  }

  getTokens(request: Request) {
    return getRequestTokens(request, this.cookies)
  }

  async createSessionToken(session: TSession) {
    const token = await this.encode({ ...this.jwt, token: session })
    return token
  }

  async getRequestSession(request: Request) {
    const { access_token } = this.getTokens(request)

    if (access_token == null) return null

    const session = await this.decode<TSession>({ ...this.jwt, token: access_token })

    if (session == null) return null

    const user = this.getUserFromSession?.(session) ?? null

    return { session, user }
  }
}
