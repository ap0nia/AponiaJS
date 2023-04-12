import { redirect } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit'
import { Integration } from '..'
import type { IntegrationConfig, Strategy } from '..'

const validRedirect = (status?: number): status is Parameters<typeof redirect>[0] =>
  status != null && status >= 300 && status < 400



export class SvelteKit<T extends Strategy = 'none'> extends Integration<T> {
  constructor(config: IntegrationConfig<T>) {
    super(config as any)
  }

  handle: Handle = async ({ event, resolve }) => {
    const internalResponse = await super.handleInternal(event.request)

    if (internalResponse == null) {
      return await resolve(event)
    }

    if (internalResponse.cookies != null) {
      internalResponse.cookies.forEach((cookie) => {
        event.cookies.set(cookie.name, cookie.value, cookie.options)
      })
    }

    if (internalResponse.headers != null) {
      event.setHeaders(
        internalResponse.headers instanceof Headers
        ? Object.fromEntries(internalResponse.headers.entries())
        : Object.fromEntries(Object.entries(internalResponse.headers))
      )
    }

    if (internalResponse.redirect != null && validRedirect(internalResponse.status)) {
      throw redirect(internalResponse.status, internalResponse.redirect)
    }

    return await resolve(event)
  }
}
