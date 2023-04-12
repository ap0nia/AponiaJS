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

    if (token == null) return null

    const session = await decode<T>({ ...this.config, token })

    return session
  }

  async invalidateSession(request: Request) {
    return request
  }
 }
