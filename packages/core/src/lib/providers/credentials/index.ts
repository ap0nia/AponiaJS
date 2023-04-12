import type { MaybePromise } from '$app/forms'
import type { Provider } from '..'

type User = {}

export interface CredentialsConfig<TInput = User, TOutput = User> {
  onAuth?: (user: TInput) => MaybePromise<TOutput>
}

export class Credentials<TInput = User, TOutput = User> implements Provider<TOutput> {
  id = 'credentials'

  type: Provider<TOutput>['type'] = 'credentials'

  config: CredentialsConfig<TInput, TOutput>

  constructor(config: CredentialsConfig<TInput, TOutput>) {
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
    return this.config.onAuth?.(form) ?? form
  }
}
