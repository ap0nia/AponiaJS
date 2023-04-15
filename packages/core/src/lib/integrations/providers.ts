import * as oauth from 'oauth4webapi'
import type { 
  CredentialsConfig,
  EmailConfig,
  OAuth2Config,
  OAuthUserConfig,
  OIDCConfig,
  Provider 
} from '@auth/core/providers'
import type {
  AnyInternalConfig,
  AnyInternalOAuthConfig,
  InternalCredentialsConfig,
  InternalEmailConfig,
  InternalOAuthConfig,
  InternalOIDCConfig 
} from '$lib/providers'
import type { Profile, TokenSet } from '@auth/core/types'

// FIXME: this is circular-ish because integration entry point imports `transformProviders` from this file
import type { InternalAuthConfig } from '.'

export async function transformProviders(provider: Provider, options: InternalAuthConfig): Promise<AnyInternalConfig> {
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
  options: InternalAuthConfig
): Promise<InternalOAuthConfig> {
  const providerOptions: OAuthUserConfig<any> = (provider as any).options

  const authorizationServer = await getAuthorizationServer(provider, options)

  const client: oauth.Client = {
    client_id: provider.clientId ?? providerOptions.clientId,
    client_secret: provider.clientSecret ?? providerOptions.clientSecret,
    ...provider.client,
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
    client_id: provider.clientId ?? providerOptions.clientId,
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
    : provider.userinfo?.url
    ? new URL(provider.userinfo.url)
    : authorizationServer.userinfo_endpoint
    ? new URL(authorizationServer.userinfo_endpoint)
    : provider.userinfo?.request
    ? new URL('aponia:Dummy URL since the provided request method will be used instead')
    : undefined

  if (!userinfoUrl) throw new TypeError('Invalid userinfo endpoint')

  const userinfoRequest: InternalOAuthConfig['userinfo']['request'] = async (context) => {
    if (!context.tokens.access_token) throw new TypeError('Invalid token response')

    const request = typeof provider.userinfo === 'object' && provider.userinfo.request 
    ? provider.userinfo.request(context)
    : oauth.userInfoRequest(authorizationServer, client, context.tokens.access_token).then(res => res.json())

    return request
  }

  authorizationServer.authorization_endpoint = authorizationUrl.toString()
  authorizationServer.token_endpoint = tokenUrl.toString()
  authorizationServer.userinfo_endpoint = userinfoUrl.toString()

  return {
    ...provider,
    authorizationServer,
    client,
    cookies: options.cookies,
    jwt: options.jwt,
    checks: provider.checks ?? ['pkce'],
    profile: provider.profile ?? defaultProfile,
    endpoints: {
      signin: `${options.pages.signIn}/${provider.id}`,
      signout: `${options.pages.signOut}/${provider.id}`,
      callback: `${options.pages.callback}/${provider.id}`
    },
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
  options: InternalAuthConfig
): Promise<InternalOIDCConfig> {
  const providerOptions: OAuthUserConfig<any> = (provider as any).options

  const authorizationServer = await getAuthorizationServer(provider, options)

  const client: oauth.Client = {
    client_id: provider.clientId ?? providerOptions.clientId,
    client_secret: provider.clientSecret ?? providerOptions.clientSecret,
    ...provider.client,
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
    client_id: provider.clientId ?? providerOptions.clientId,
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

  const tokenConform: InternalOIDCConfig['token']['conform'] = typeof provider.token === 'object'
    ? (provider.token as any).conform
    : (response) => response

  const userinfoUrl = typeof provider.userinfo === 'string'
    ? new URL(provider.userinfo)
    : provider.userinfo?.url
    ? new URL(provider.userinfo.url)
    : authorizationServer.userinfo_endpoint
    ? new URL(authorizationServer.userinfo_endpoint)
    : new URL(`aponia:Dummy URL since OIDC doesn't need to make another userinfo request`)


  const userinfoRequest: InternalOIDCConfig['userinfo']['request'] = async (context) => {
    if (!context.tokens.access_token) throw new TypeError('Invalid token response')
    try {
      const request = typeof provider.userinfo === 'object' && provider.userinfo.request 
      ? provider.userinfo.request(context)
      : oauth.userInfoRequest(authorizationServer, client, context.tokens.access_token).then(res => res.json())
      return request
    } catch(e) {
      console.log(`Error fetching userinfo: ${e}`)
      return {}
    }
  }

  return {
    ...provider,
    authorizationServer,
    client,
    cookies: options.cookies,
    jwt: options.jwt,
    checks: provider.checks ?? ['pkce'],
    profile: provider.profile ?? defaultProfile,
    endpoints: {
      signin: `${options.pages.signIn}/${provider.id}`,
      signout: `${options.pages.signOut}/${provider.id}`,
      callback: `${options.pages.callback}/${provider.id}`
    },
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

export async function transformEmailProvider(
  provider: EmailConfig,
  options: InternalAuthConfig
): Promise<InternalEmailConfig> {
  return { 
    ...provider,
    endpoints: {
      signin: `${options.pages.signIn}/${provider.id}`,
      signout: `${options.pages.signOut}/${provider.id}`,
      callback: `${options.pages.callback}/${provider.id}`
    },
  }
}

export async function transformCredentialsProvider(
  provider: CredentialsConfig,
  options: InternalAuthConfig
): Promise<InternalCredentialsConfig> {
  return { 
    ...provider,
    endpoints: {
      signin: `${options.pages.signIn}/${provider.id}`,
      signout: `${options.pages.signOut}/${provider.id}`,
      callback: `${options.pages.callback}/${provider.id}`
    },
  }
}

type MutableAuthorizationServer = {
  -readonly [K in keyof oauth.AuthorizationServer]: oauth.AuthorizationServer[K]
}

async function getAuthorizationServer(
  provider: OAuth2Config<any> | OIDCConfig<any>,
  _options: InternalAuthConfig
): Promise<MutableAuthorizationServer> {
  if (!provider.issuer) return { issuer: 'authjs.dev' }

  const issuer = new URL(provider.issuer)

  const discoveryResponse = await oauth.discoveryRequest(issuer)

  const as = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

  return as
}

/** 
 * Returns profile, raw profile and auth provider details
 */
export async function getProfile(
  OAuthProfile: Profile,
  provider: AnyInternalOAuthConfig,
  tokens: TokenSet,
) {
  try {
    const profile = await provider.profile(OAuthProfile, tokens)
    profile.email = profile.email?.toLowerCase()

    if (!profile.id) {
      throw new TypeError(
        `Profile id is missing in ${provider.name} OAuth profile response`
      )
    }

    return {
      profile,
      account: {
        provider: provider.id,
        type: provider.type,
        providerAccountId: profile.id.toString(),
        ...tokens,
      },
      OAuthProfile,
    }
  } catch (e) {
    // If we didn't get a response either there was a problem with the provider
    // response *or* the user cancelled the action with the provider.
    //
    // Unfortunately, we can't tell which - at least not in a way that works for
    // all providers, so we return an empty object; the user should then be
    // redirected back to the sign up page. We log the error to help developers
    // who might be trying to debug this when configuring a new provider.
    console.debug("getProfile error details", OAuthProfile)
    console.error(e)
  }
}

function defaultProfile(profile: any) {
  return {
    id: profile.sub ?? profile.id,
    name: profile.name ?? profile.nickname ?? profile.preferred_username ?? null,
    email: profile.email ?? null,
    image: profile.picture ?? null,
  }
}

