import type { InternalRequest, InternalResponse } from '$lib/integrations/response'
import type { Provider, InternalEmailConfig } from '.'


export class EmailProvider implements Provider<InternalEmailConfig> {
  constructor(readonly config: InternalEmailConfig) {}

  async signIn(request: InternalRequest): Promise<InternalResponse> {
    console.log("EmailProvider.signIn not implemented ", request)
    return {}
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    console.log("EmailProvider.callback not implemented ", request)
    return {}
  }

  async signOut(request: InternalRequest): Promise<InternalResponse> {
    console.log("EmailProvider.signOut not implemented ", request)
    return {}
  }
}
