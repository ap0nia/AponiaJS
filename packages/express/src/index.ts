import './types'

import * as cookie from 'cookie'
import type { Auth } from 'aponia'
import type { Request, Response, NextFunction } from 'express'

export type Options = {
  /**
   * Whether to enable debugging.
   */
  debug?: boolean
}


export function toInternalRequest(expressRequest: Request): Aponia.InternalRequest {
  const url = new URL(`${expressRequest.protocol}://${expressRequest.get('host')}${expressRequest.originalUrl}`)

  const request = new Request(url, {
    method: expressRequest.method,
    headers: Object.entries(expressRequest.headers).map(([key, value]) =>
      [key.toLowerCase(), Array.isArray(value) ? value.join(', ') : (value ?? '')],
    ),
    ...(expressRequest.method !== 'GET' && expressRequest.method !== 'HEAD' && { body: expressRequest.body }),
  })

  return {
    url,
    request,
    expressRequest,
    cookies: cookie.parse(expressRequest.headers.cookie ?? ''),
  }
}

export function createAuthMiddleware(auth: Auth, options: Options = {}) {
  const getUser = async (req: Request) => {
    const initialUser = req.user
    if (initialUser) return initialUser

    const accessToken = req.cookies[auth.session.config.cookieOptions.accessToken.name]

    const { accessTokenData } = await auth.session.decodeTokens({ accessToken })
    if (!accessTokenData) return null

    const user = await auth.session.config.getAccessTokenUser(accessTokenData)
    if (!user) return null

    return user
  }

  const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const internalResponse = await auth.handle(toInternalRequest(req))

    req.user = internalResponse.user
    req.getUser = () => getUser(req)

    if (internalResponse.cookies?.length) {
      internalResponse.cookies.forEach((cookie) => {
        if (cookie.options?.maxAge) {
          cookie.options.maxAge *= 1000
        }
        res.cookie(cookie.name, cookie.value, cookie.options ?? {})
      })
    }

    if (options.debug) {
      req.aponiaAuthResponse = internalResponse
    }

    if (internalResponse.error) {
      res
        .status(internalResponse.status ?? 500)
        .json(internalResponse.error.stack ?? internalResponse.error.message)
    }

    if (internalResponse.redirect && internalResponse.status) {
      res.redirect(internalResponse.status, internalResponse.redirect)
    }

    if (internalResponse.body) {
      res.json(internalResponse.body)
    }

    return next()
  }

  return authMiddleware
}
