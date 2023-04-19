import type { InternalRequest } from "../internal/request";
import type { InternalResponse } from "../internal/response";

type Awaitable<T> = T | PromiseLike<T>;

export interface SessionManagerConfig<TUser, TSession> {
  getUserFromSession?: (session: TSession) => Awaitable<TUser | undefined | null | void> 
  createSessionFromUser?: (user: TUser) => Awaitable<TSession | undefined | null | void> 
}

export class SessionManager<TUser = {}, TSession = {}> implements SessionManagerConfig<TUser, TSession> {
  getUserFromSession: (session: TSession) => Awaitable<TUser | undefined | null | void> 
  createSessionFromUser: (user: TUser) => Awaitable<TSession | undefined | null | void> 

  constructor(config: SessionManagerConfig<TUser, TSession>) {
    this.getUserFromSession = config.getUserFromSession ?? (() => undefined);
    this.createSessionFromUser = config.createSessionFromUser ?? (() => undefined);
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
    if (response.session && !request.session) {
      response.cookies ??= []
      response.cookies.push({
        name: '',
        value: '',
      })
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
}
