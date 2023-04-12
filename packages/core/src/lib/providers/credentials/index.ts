import type { Provider, ProviderConfig } from '..'

/**
 * `Credentials` provider, i.e. username + password.
 */
export class Credentials<T extends Record<string, any> = {}> implements Provider<T> {
  id = 'credentials'

  type: Provider<T>['type'] = 'credentials'

  config: ProviderConfig<T>

  constructor(config: ProviderConfig<T>) {
    this.config = config
  }

  getAuthorizationUrl() {
    return ['https://localhost:5173/auth/callback/email', ''] as const
  }

  async logout() {
    return true
  }

  _authenticateRequestMethod = 'POST'

  async authenticateRequest(request: Request) {
    if (request.method !== this._authenticateRequestMethod) {
      throw new Error(`Invalid request method: ${request.method}`)
    }

    const formData = await request.formData()
    const form: any = Object.fromEntries(formData.entries())
    return this.config.onLogin?.(form) ?? form
  }
}
