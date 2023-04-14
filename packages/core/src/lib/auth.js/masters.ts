import type {
  InternalOAuthConfig,
  InternalOIDCConfig,
  InternalEmailConfig,
  InternalCredentialsConfig,
  AnyInternalConfig,
} from './providers'
import type { InternalRequest, InternalResponse } from '$lib/integrations/response'

export interface Provider<T extends AnyInternalConfig> {
  config: T

  signIn(request: InternalRequest, provider: T): Promise<InternalResponse>

  callback(request: InternalRequest, provider: T): Promise<InternalResponse>

  signOut(request: InternalRequest, provider: T): Promise<InternalResponse>
}

export class OAuthProvider implements Provider <InternalOAuthConfig> {
  constructor(readonly config: InternalOAuthConfig) {}

  async signIn(request: InternalRequest, provider: InternalOAuthConfig): Promise<InternalResponse> {
    return {}
  }

  async callback(request: InternalRequest, provider: InternalOAuthConfig): Promise<InternalResponse> {
    return {}
  }

  async signOut(request: InternalRequest, provider: InternalOAuthConfig): Promise<InternalResponse> {
    return {}
  }
}

export class OIDCProvider implements Provider<InternalOIDCConfig> {
  constructor(readonly config: InternalOIDCConfig) {}

  async signIn(request: InternalRequest, provider: InternalOIDCConfig): Promise<InternalResponse> {
    return {}
  }

  async callback(request: InternalRequest, provider: InternalOIDCConfig): Promise<InternalResponse> {
    return {}
  }

  async signOut(request: InternalRequest, provider: InternalOIDCConfig): Promise<InternalResponse> {
    return {}
  }
}


export class EmailProvider implements Provider<InternalEmailConfig> {
  constructor(readonly config: InternalEmailConfig) {}

  async signIn(request: InternalRequest, provider: InternalEmailConfig): Promise<InternalResponse> {
    return {}
  }

  async callback(request: InternalRequest, provider: InternalEmailConfig): Promise<InternalResponse> {
    return {}
  }

  async signOut(request: InternalRequest, provider: InternalEmailConfig): Promise<InternalResponse> {
    return {}
  }
}


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
