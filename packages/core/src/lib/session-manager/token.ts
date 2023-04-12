import { getSessionToken } from ".";
import { encode, decode } from "../jwt";
import type { User, Session } from '.'

export interface Token extends Record<string, unknown> {
  session: Session
  user: User
}

export interface TokenSessionConfig {
  secret: string
  maxAge?: number
}

export class TokenSessionManager<T extends Token = Token> {
  config: TokenSessionConfig

  constructor(config: TokenSessionConfig) {
    this.config = config
  }

  async createSessionToken(session: T) {
    const token = await encode({ ...this.config, token: session })
    return token
  }

  async getRequestSession(request: Request) {
    const token = getSessionToken(request)

    const sessionUser = await decode<T>({ ...this.config, token })

    if (sessionUser == null) throw new Error()

    const { session, user } = sessionUser

    if (session.expires < new Date().getTime()) throw new Error()

    return { session, user }
  }

  async invalidateSession(request: Request) {
    return request
  }
 }
