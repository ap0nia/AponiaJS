import { type Auth, type InternalRequest } from 'aponia'
import type { Request, Response, NextFunction } from 'express'
import * as cookie from 'cookie'

const defaultLocalsUserKey = 'user'

const defaultLocalsAuthKey = 'aponia-auth'

export type Options<T extends InternalRequest = InternalRequest> = {
  /**
   * Key to store the user in locals.
   * User will only be defined if the session was refreshed or provider action occurred during the current request.
   */
  localsUserKey?: string

  /**
   * Key to store the internally generated auth response in locals if debugging.
   */
  localsAuthKey?: string

  /**
   * Whether to enable debugging.
   */
  debug?: boolean

  toInternalRequest?: (request: Request) => T
}


export function defaultToInternalRequest(req: Request): InternalRequest {
  const request = new Request(`${req.protocol}://${req.get('host')}${req.originalUrl}`, {
    method: req.method,
    headers: Object.entries(req.headers).map(([key, value]) =>
      [key.toLowerCase(), Array.isArray(value) ? value.join(', ') : (value ?? '')]
    ),
    body: req.body,
  })

  return {
    request,
    url: new URL(req.url),
    cookies: cookie.parse(req.headers.cookie ?? ''),
  }
}

export function createAuthHelpers<
  TUser,
  TSession = TUser,
  TRefresh = undefined,
  TRequest extends InternalRequest = InternalRequest
>(auth: Auth<TUser, TSession, TRefresh, TRequest>, options: Options<TRequest> = {} as any) {
  const localsUserKey = options.localsUserKey ?? defaultLocalsUserKey
  const localsAuthKey = options.localsAuthKey ?? defaultLocalsAuthKey

  const toInternalRequest = options.toInternalRequest ?? defaultToInternalRequest

  const handler = async (req: Request, res: Response, next: NextFunction) => {
    const internalResponse = await auth.handle(toInternalRequest(req) as TRequest)

    if (internalResponse.cookies?.length) {
      internalResponse.cookies.forEach((cookie) => {
        if (cookie.options?.maxAge) {
          cookie.options.maxAge *= 1000
        }
        res.cookie(cookie.name, cookie.value, cookie.options ?? {})
      })
    }

    (req as any)[localsUserKey] = internalResponse.user

    if (options.debug) {
      (req as any)[localsAuthKey] = internalResponse
    }

    if (internalResponse.redirect && internalResponse.status) {
      res.redirect(internalResponse.status, internalResponse.redirect)
    }

    if (internalResponse.body) {
      res.json(internalResponse.body)
    }

    return next()
  }

  return handler
}
