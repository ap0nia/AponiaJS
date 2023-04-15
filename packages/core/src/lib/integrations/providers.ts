import * as oauth from 'oauth4webapi'
import type { 
  CredentialsConfig,
  EmailConfig,
  OAuth2Config,
  OIDCConfig,
  Provider 
} from '@auth/core/providers'
import type {
  AnyInternalConfig,
  InternalCredentialsConfig,
  InternalEmailConfig,
  InternalOAuthConfig,
  InternalOIDCConfig 
} from '$lib/providers'

export interface ProviderOptions {
}

export async function transformProviders(provider: Provider, options: ProviderOptions): Promise<AnyInternalConfig> {
  switch (provider.type) {
    case 'oauth': 
      return transformOAuthProvider(provider, options)
    case 'oidc':
      return transformOIDCProvider(provider, options)
    case 'email':
      return transformEmailProvider(provider, options)
    case 'credentials':
      return transformCredentialsProvider(provider, options)
  }
}

export async function transformOAuthProvider(
  provider: OAuth2Config<any>,
  options: ProviderOptions
): Promise<InternalOAuthConfig> {
  const authorizationServer = await getAuthorizationServer(provider, options)

  const client: oauth.Client = {
    client_id: provider.clientId ?? '',
    client_secret: provider.clientSecret ?? '',
  }

  const authorizationUrl = typeof provider.authorization === 'string' 
    ? new URL(provider.authorization) 
    : provider.authorization?.url
    ? new URL(provider.authorization.url)
    : authorizationServer.authorization_endpoint
    ? new URL(authorizationServer.authorization_endpoint)
    : undefined

  if (!authorizationUrl) throw new TypeError('Invalid authorization endpoint')

  const params = {
    response_type: "code",
    client_id: provider.clientId,
    // redirect_uri: provider.callbackUrl,
    ...(typeof provider.authorization === 'object' && provider.authorization?.params),
  }

  Object.entries(params).forEach(([key, value]) => {
    if (typeof value === 'string') {
      authorizationUrl.searchParams.set(key, value)
    }
  })

  const tokenUrl = typeof provider.token === 'string' 
    ? new URL(provider.token)
    : authorizationServer.token_endpoint
    ? new URL(authorizationServer.token_endpoint)
    : undefined

  if (!tokenUrl) throw new TypeError('Invalid token endpoint')

  const tokenConform: InternalOAuthConfig['token']['conform'] = typeof provider.token === 'object'
    ? (provider.token as any).conform
    : (response) => response

  const userinfoUrl = typeof provider.userinfo === 'string'
    ? new URL(provider.userinfo)
    : authorizationServer.userinfo_endpoint
    ? new URL(authorizationServer.userinfo_endpoint)
    : undefined

  if (!userinfoUrl) throw new TypeError('Invalid userinfo endpoint')

  const userinfoRequest: InternalOAuthConfig['userinfo']['request'] = async (context) => {
    if (!context.tokens.access_token) throw new TypeError('Invalid token response')

    const request = typeof provider.userinfo === 'object' && provider.userinfo.request 
    ? provider.userinfo.request(context)
    : oauth.userInfoRequest(authorizationServer, client, context.tokens.access_token).then(res => res.json())

    return request
  }

  return {
    ...provider,
    authorizationServer,
    client,
    cookies: undefined as any,
    jwt: undefined as any,
    checks: [],
    profile: undefined as any,
    authorization: { 
      url: authorizationUrl
    },
    token: {
      url: tokenUrl,
      conform: tokenConform
    },
    userinfo: {
      url: userinfoUrl,
      request: userinfoRequest
    }
  }
}

export async function transformOIDCProvider(
  provider: OIDCConfig<any>,
  _options: ProviderOptions
): Promise<InternalOIDCConfig> {
  return {
    ...provider,
    profile: undefined as any,
    authorizationServer: undefined as any,
    client: undefined as any,
    cookies: undefined as any,
    checks: [],
    jwt: undefined as any,
    authorization: undefined as any,
    token: undefined as any,
    userinfo: undefined as any
  }
}

export async function transformEmailProvider(
  provider: EmailConfig,
  _options: ProviderOptions
): Promise<InternalEmailConfig> {
  return { ...provider }
}

export async function transformCredentialsProvider(
  provider: CredentialsConfig,
  _options: ProviderOptions
): Promise<InternalCredentialsConfig> {
  return { ...provider }
}


async function getAuthorizationServer(
  provider: OAuth2Config<any> | OIDCConfig<any>,
  _options: ProviderOptions
): Promise<oauth.AuthorizationServer> {
  if (!provider.issuer) {
    return {
      issuer: 'authjs.dev',
    }
  }

  const issuer = new URL(provider.issuer)

  const discoveryResponse = await oauth.discoveryRequest(issuer)

  const as = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

  if (!as.authorization_endpoint) {
    throw new TypeError(
      "Authorization server did not provide an authorization endpoint."
    )
  }

  return as
}
