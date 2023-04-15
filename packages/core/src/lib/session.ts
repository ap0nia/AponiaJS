import { parse } from 'cookie'
import { encode, decode } from './jwt'
import type { JWTOptions, JWTEncodeParams, JWTDecodeParams } from './jwt'
import { defaultCookies, type InternalCookiesOptions } from './cookie'

type Awaitable<T> = T | PromiseLike<T>

/**
 * Get session token from request cookies.
 */
export function getRequestTokens(request: Request, options: InternalCookiesOptions) {
  const cookies = parse(request.headers.get('cookie') ?? '')

  const access_token = cookies[options.sessionToken.name]

  const refresh_token = cookies[options.refreshToken.name]

  return { access_token, refresh_token }
}

/**
 * A session can be created to persist user login. 
 * Default expected interface for sessions.
 */
export interface Session {
  /**
   * Unique session identifier.
   */
  id: string;

  /**
   * Session owner.
   */
  user_id: string;

  /**
   * Session expiry date.
   */
  expires: number | bigint;
}

/**
 * JWT-session management configuration.
 */
export interface SessionManagerConfig<TUser, TSession> {
  /**
   * JWT configuration.
   */
  jwt?: JWTOptions

  /**
   * Cookie options.
   */
  cookies?: Partial<InternalCookiesOptions>

  /**
   * Whether to use secure cookies.
   */
  useSecureCookies?: boolean

  /**
   * Get the user from the session, i.e. retrieved from cookies.
   */
  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession?: (sessionId: string) => Awaitable<void>

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions?: (userId: string) => Awaitable<void>

  /**
   * Create a session from a user ID, i.e. storing it in the database.
   * Session can then be used to create a session token.
   */
  createSession?: (userId: string) => Awaitable<TSession>
}

/**
 * Default JWT-based session manager only uses JWT to encode and decode sessions.
 *
 * Example flow:
 * 1. User logs in. Handle auth yourself.
 * 2. Create a session object, i.e. adding any desired additional info for the user.
 * 3. Call `createSessionToken` to create a session token from the session.
 * 4. Store the session token in a cookie.
 * 5. On subsequent requests, call `getRequestSession` to get the session from the request cookies.
 */
export class SessionManager<TUser = {}, TSession extends Record<string, any> = Session> {
  /**
   * JWT configuration.
   */
  jwt: JWTOptions

  /**
   * Internal cookie configuration.
   */
  cookies: InternalCookiesOptions

  /**
   * Secret.
   */
  secret: string

  /**
   * Whether to use secure cookies.
   */
  useSecureCookies: boolean

  /**
   * Designated JWT encoder.
   */
  encode: (params: JWTEncodeParams) => Awaitable<string>

  /**
   * Designated JWT decoder.
   */
  decode: <T>(params: JWTDecodeParams) => Awaitable<T | null>

  /**
   * Get the user from the session, i.e. retrieved from cookies.
   */
  getUserFromSession?: (session: TSession) => Awaitable<TUser | null>

  /**
   * Invalidate a session, i.e. log the user out of a specific session.
   */
  invalidateSession: (sessionId: string) => Awaitable<void> 

  /**
   * Invalidate user's sessions, i.e. log the user out of all sessions.
   */
  invalidateUserSessions: (userId: string) => Awaitable<void>

  /**
   * Create a session from a user ID, i.e. storing it in the database.
   * Session can then be used to create a session token.
   */
  createSession: (userId: string) => Awaitable<TSession>

  constructor(config: SessionManagerConfig<TUser, TSession>) {
    this.jwt = config?.jwt ?? { secret: '' }
    this.encode = config.jwt?.encode ?? encode
    this.decode = config.jwt?.decode ?? decode
    this.getUserFromSession = config.getUserFromSession
    this.invalidateSession = config.invalidateSession ?? (() => {})
    this.invalidateUserSessions = config.invalidateUserSessions ?? (() => {})
    this.createSession = config.createSession ?? ((session) => ({ session } as any))
    this.cookies = { ...defaultCookies(config.useSecureCookies), ...config.cookies }
    this.useSecureCookies = config.useSecureCookies ?? false
    this.secret = config.jwt?.secret ?? ''
  }

  /**
   * Get tokens from request cookies.
   */
  getTokens(request: Request) {
    return getRequestTokens(request, this.cookies)
  }

  /**
   * Create a session token from a session, i.e. after creating one.
   */
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
