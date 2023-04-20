import { TokenSessionManager } from './token'
import { DatabaseSessionManager } from './database'
import type { TokenSessionConfig } from './token'
import type { DatabaseSessionConfig } from './database'

export type AnySessionManager<TUser, TSession = TUser, TRefresh = undefined> = 
  | TokenSessionManager<TUser, TSession, TRefresh>
  | DatabaseSessionManager<TUser, TSession, TRefresh>

export type Strategy = 'jwt' | 'session'

export type SessionConfig<TStrategy extends Strategy, TUser, TSession = TUser, TRefresh = undefined> = 
  TStrategy extends 'jwt' 
    ? TokenSessionConfig<TUser, TSession, TRefresh> 
    : DatabaseSessionConfig<TUser, TSession, TRefresh>

export type SessionManager<TStrategy extends Strategy, TUser, TSession = TUser, TRefresh = undefined> =
  TStrategy extends 'jwt'
    ? TokenSessionManager<TUser, TSession, TRefresh>
    : DatabaseSessionManager<TUser, TSession, TRefresh>

export function Session<TStrategy extends Strategy, TUser, TSession = TUser, TRefresh = undefined>(
  strategy: TStrategy,
  config: SessionConfig<TStrategy, TUser, TSession, TRefresh>
): SessionManager<TStrategy, TUser, TSession, TRefresh> {
  if (strategy === 'jwt') return new TokenSessionManager(config)
  return new DatabaseSessionManager(config)
}
