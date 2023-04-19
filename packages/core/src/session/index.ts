import { createCookiesOptions } from "../security/cookie";
import type { Cookie, CookiesOptions } from "../security/cookie";
import type { JWTDecodeParams, JWTEncodeParams, JWTOptions } from "../security/jwt";
import type { InternalRequest } from "../internal/request";
import type { InternalResponse } from "../internal/response";

type Nullish = undefined | null | void;

type Awaitable<T> = T | PromiseLike<T>;

type Strategy = 'jwt' | 'session'

type JwtSessionOptions<TUser> = {
  encode: (params: JWTEncodeParams<TUser>) => Awaitable<string>
  decode: <T>(params: JWTDecodeParams) => Awaitable<T | Nullish>
  createRefreshToken: (user: TUser) => Awaitable<string | Nullish>
}

export type SessionManagerConfig<TStrategy extends Strategy, TUser, TSession> = {
  strategy: TStrategy
  secret: string
  jwt?: Omit<JWTOptions, 'secret'>
  useSessionCookies?: boolean
  getUserFromSession?: (session: TSession) => Awaitable<TUser | Nullish> 
  createSessionFromUser?: (user: TUser) => Awaitable<TSession | Nullish> 
} & (TStrategy extends 'jwt' ? JwtSessionOptions<TUser> : object)

export class SessionManager<TStrategy extends Strategy, TUser = {}, TSession = {}> {
  strategy: TStrategy

  secret: string

  cookies: CookiesOptions

  jwt: Omit<JWTOptions, 'secret'>

  createRefeshToken: (user: TUser) => Awaitable<string | Nullish>

  getUserFromSession: (session: TSession) => Awaitable<TUser | Nullish> 

  createSessionFromUser: (user: TUser) => Awaitable<TSession | Nullish> 

  encode: (params: JWTEncodeParams<TUser>) => Awaitable<string>

  decode: <T>(params: JWTDecodeParams) => Awaitable<T | Nullish>

  constructor(config: SessionManagerConfig<TStrategy, TUser, TSession>) {
    this.strategy = config.strategy;
    this.secret = config.secret;
    this.cookies = createCookiesOptions(config.useSessionCookies);
    this.jwt = { ...config.jwt }
    this.getUserFromSession = config.getUserFromSession ?? (() => undefined);
    this.createSessionFromUser = config.createSessionFromUser ?? (() => undefined);
    this.encode = 'encode' in config ? config.encode : (() => '');
    this.decode = 'decode' in config ? config.decode : (() => null);
    this.createRefeshToken = 'createRefreshToken' in config
      ? config.createRefreshToken 
      : (() => undefined);
  }

  async createJwtCookies(user: TUser): Promise<Cookie[]> {
    return [
      {
        name: this.cookies.accessToken.name,
        value: await this.encode({ ...this.jwt, secret: this.secret, token: user }),
        options: this.cookies.accessToken.options
      },
      {
        name: this.cookies.refreshToken.name,
        value: (await this.createRefeshToken(user)) || '',
        options: this.cookies.refreshToken.options
      }
    ]
  }

  async createSessionCookies(session: TSession): Promise<Cookie[]> {
    return [
      {
        name: this.cookies.sessionToken.name,
        value: String(session),
        options: this.cookies.sessionToken.options,
      }
    ]
  }

  /**
   */
  async handleRequest(
    request: InternalRequest<TUser, TSession>
  ): Promise<InternalRequest<TUser, TSession>> {
    return request
  }

  /**
   */
  async handleResponse(
    request: InternalRequest<TUser, TSession>,
    response: InternalResponse<TUser, TSession>
  ): Promise<InternalResponse<TUser, TSession>> {
    /**
     * if the response has a session and the response doesn't have a user,
     * try to get the user from the session
     */
    if (response.session && !response.user) {
      response.user = (await this.getUserFromSession(response.session)) || undefined;
    }

    /**
     * if the response has a user and the response doesn't have a session,
     * try to create a session from the user
     */
    if (response.user && !response.session) {
      response.session = (await this.createSessionFromUser(response.user)) || undefined;
    }

    /**
     * if the response has a session and the request didn't have one,
     * create a new session cookie.
     */
    if (response.session && !request.session && this.strategy === 'session') {
      response.cookies ??= []
      response.cookies.concat(await this.createSessionCookies(response.session))
    }

    if (response.user && !request.user && this.strategy === 'jwt') {
      response.cookies ??= []
      response.cookies.concat(await this.createJwtCookies(response.user))
    }

    /**
     * if the request has a session and the response didn't generate a new one,
     * propagate the session to the response
     */
    if (request.session && !response.session) {
      response.session = request.session;
    }

    return response;
  }

    /**
   * Invalidate a session.
   */
  async invalidateSession(request: InternalRequest): Promise<InternalResponse> {
    const userSession = request.session ?? await this.getRequestSession(request)
    await this.onInvalidate(userSession)
    return {
      redirect: '/',
      status: 302,
      cookies: [
        {
          name: this.cookies.sessionToken.name,
          value: '',
          options: { maxAge: 0, path: '/' }
        },
        {
          name: this.cookies.refreshToken.name,
          value: '',
          options: { maxAge: 0, path: '/' }
        },
      ],
    }
  }
}
