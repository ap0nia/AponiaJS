import type { Provider, ProviderConfig } from '..'

/**
 * `Credentials` provider, i.e. username + password.
 */
export class Credentials<T extends Record<string, any> = {}> implements Provider {
  id: Provider['id'] = 'credentials'

  type: Provider['type'] = 'credentials'

  config: ProviderConfig<T>

  constructor(config: ProviderConfig<T>) {
    this.config = config
  }

  async login(user: any) {
    return this.config.onLogin?.(user) ?? user
  }

  async handleLogin(request: Request) {
    if (request.method !== 'POST') return 

    const user = await request.formData()

    return this.login(user)
  }

  async handleLogout() {
    return this.logout()
  }

  async logout() {
    return true
  }
}
