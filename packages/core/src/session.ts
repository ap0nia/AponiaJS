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

function asPromise<T>(value: Awaitable<T>): Promise<T> {
  return value instanceof Promise ? value : Promise.resolve(value)
}

interface NewSession<TUser, TSession, TRefresh> { 
  user: TUser,
  accessToken: TSession,
  refreshToken?: TRefresh 
}

interface TokenMaxAge {
  accessToken: number
  refreshToken: number
}

interface Pages {
  logoutRedirect: string
}

export interface SessionUserConfig<TUser, TSession = TUser, TRefresh = undefined> extends 
  DeepPartial<Omit<SessionConfig<TUser, TSession, TRefresh>, 'secret'>>,
  Required<Pick<SessionConfig<TUser, TSession, TRefresh>, 'secret'>> {}

export interface SessionConfig<TUser, TSession = TUser, TRefresh = undefined> {
  secret: string

  pages: Partial<Pages>

  jwt: Required<Omit<JWTOptions, 'maxAge'>>

  cookies: CookiesOptions

  maxAge: Partial<TokenMaxAge>

  useSecureCookies?: boolean

  createSession?: (user: TUser) => Awaitable<NewSession<TUser, TSession, TRefresh> | Nullish>;

  getUserFromSession: (session: TSession) => Awaitable<TUser | Nullish>;

  handleRefresh?: (
    tokens: { accessToken?: TSession | Nullish, refreshToken?: TRefresh | Nullish  }
  ) => Awaitable<NewSession<TUser, TSession, TRefresh> | Nullish>;

  onInvalidateSession?: (
    session: TSession,
    refresh: TRefresh | Nullish,
    context: SessionManager<TUser, TSession, TRefresh>,
  ) => Awaitable<InternalResponse<TUser> | Nullish>
}

export class SessionManager<TUser, TSession = TUser, TRefresh = undefined> {
  config: SessionConfig<TUser, TSession, TRefresh>

  constructor(config: SessionUserConfig<TUser, TSession, TRefresh>) {
    this.config = {
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
      createSession: config.createSession,
      getUserFromSession: config.getUserFromSession ?? ((session: TSession) => session as any),
      handleRefresh: config.handleRefresh,
      onInvalidateSession: config.onInvalidateSession,
      useSecureCookies: config.useSecureCookies,
    }
  }

  async decodeTokens(tokens: { accessToken?: string, refreshToken?: string }) {
    const access = await asPromise(
      this.config.jwt.decode<TSession>({ secret: this.config.secret, token: tokens.accessToken })
    ).catch(e => {
      console.log('Error decoding access token', e)
    })

    const refresh = await asPromise(
      this.config.jwt.decode<TRefresh>({ secret: this.config.secret, token: tokens.refreshToken })
    ).catch(e => {
      console.log('Error decoding access token', e)
    })

    return { access, refresh }
  }

  async createCookies(newSession: NewSession<TUser, TSession, TRefresh>): Promise<Cookie[]> {
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

  async handleRequest(request: InternalRequest): Promise<InternalResponse<TUser>> {
    const response: InternalResponse<TUser> = {}
    response.cookies ??= []

    const accessToken = request.cookies[this.config.cookies.accessToken.name]

    const refreshToken = request.cookies[this.config.cookies.refreshToken.name]

    const { access, refresh } = await this.decodeTokens({ accessToken, refreshToken })

    response.user = access ? await this.config.getUserFromSession(access) : null

    const sessionTokens = await this.config.handleRefresh?.({ accessToken: access, refreshToken: refresh })

    if (sessionTokens) {
      response.cookies.push(...await this.createCookies(sessionTokens))
    }
    
    response.user ||= sessionTokens?.user

    return response
  }

  async logout(request: Request): Promise<InternalResponse<TUser>> {
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

export function AponiaSession<TUser, TSession = TUser, TRefresh = undefined>(
  config: SessionUserConfig<TUser, TSession, TRefresh>
): SessionManager<TUser, TSession, TRefresh> {
  return new SessionManager(config)
}
