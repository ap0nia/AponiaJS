import type { InternalRequest, InternalResponse } from '$lib/integrations/response'
import type { InternalCredentialsConfig } from '../providers'
import type { Provider } from './index'

export class CredentialsProvider implements Provider<InternalCredentialsConfig> {
  constructor(readonly config: InternalCredentialsConfig) {}

  async signIn(request: InternalRequest, provider: InternalCredentialsConfig): Promise<InternalResponse> {
    return {}
  }

  async callback(request: InternalRequest, provider: InternalCredentialsConfig): Promise<InternalResponse> {
    return {}
  }

  async signOut(request: InternalRequest, provider: InternalCredentialsConfig): Promise<InternalResponse> {
    return {}
  }
}
