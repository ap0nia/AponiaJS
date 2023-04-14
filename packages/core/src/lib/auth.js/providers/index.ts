import type { InternalRequest, InternalResponse } from '$lib/integrations/response'
import type { AnyInternalConfig } from '../providers'

export interface Provider<T extends AnyInternalConfig> {
  config: T

  signIn(request: InternalRequest, provider: T): Promise<InternalResponse>

  callback(request: InternalRequest, provider: T): Promise<InternalResponse>

  signOut(request: InternalRequest, provider: T): Promise<InternalResponse>
}
