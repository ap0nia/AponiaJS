import * as oauth from 'oauth4webapi'
import type { Awaitable } from '$lib/utils/promise'
import type { Profile, TokenSet, User } from '@auth/core/types'
import type { CredentialsConfig, EmailConfig, OAuth2Config, OIDCConfig, Provider } from '@auth/core/providers'

/**
 * Providers passed to Auth.js must define one of these types.
 *
 * @see [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3)
 * @see [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
 * @see [Email or Passwordless Authentication](https://authjs.dev/concepts/oauth)
 * @see [Credentials-based Authentication](https://authjs.dev/concepts/credentials)
 */
export type ProviderType = "oidc" | "oauth" | "email" | "credentials"

/**
 * Required config options for all providers.
 */
interface ProviderConfig {
  /**
   * Unique identifier for the provider. Can appear in the URL.
   */
  id: string

  /**
   * Provider name. Can be displayed on auth buttons.
   */
  name: string

  /**
   * @see {@link ProviderType}
   */
  type: ProviderType
}

/**
 * Internally generated config for OAuth providers from Auth.js .
 */
export interface InternalOAuthConfig extends ProviderConfig {
  type: 'oauth'

  /**
   * OAuth Authorization Server.
   */
  authorizationServer: oauth.AuthorizationServer

  /**
   * Client to make requests.
   */
  client: oauth.Client

  /**
   * Receives the profile object returned by the OAuth provider, and returns a user object.
   */
  profile?: (profile: Profile, tokens: TokenSet) => Awaitable<User>

  /**
   * Additional data about the authorization endpoint.
   */
  authorization: { 

    /**
     * Full URL to authorization endpoint with search params.
     */
    url: URL
  }

  /**
   * Additional data about the token endpoint.
   */
  token: {

    /**
     * Full URL to token endpoint.
     */
    url: URL

    /**
     * Process the response from the token endpoint.
     */
    conform: (response: Response) => Awaitable<Response | undefined>
  }

  /**
   * Additional data about the userinfo endpoint.
   */
  userinfo: {

    /**
     * Full URL to userinfo endpoint.
     */
    url: URL

    /**
     * Make a request to the userinfo endpoint.
     */
    request: (
      context: { tokens: TokenSet, provider: InternalOAuthConfig | InternalOIDCConfig }
    ) => ReturnType<typeof getProfile>
  }
}

/**
 * Internally generated config for OIDC providers from Auth.js .
 */
export interface InternalOIDCConfig extends ProviderConfig {
  type: 'oidc'

  /**
   * OAuth Authorization Server.
   */
  authorizationServer: oauth.AuthorizationServer

  /**
   * Client to make requests.
   */
  client: oauth.Client

  /**
   * Receives the profile object returned by the OAuth provider, and returns a user object.
   */
  profile?: (profile: Profile, tokens: TokenSet) => Awaitable<User>

  /**
   * Additional data about the authorization endpoint.
   */
  authorization: { 

    /**
     * Full URL to authorization endpoint with search params.
     */
    url: URL
  }

  /**
   * Additional data about the token endpoint.
   */
  token: {

    /**
     * Full URL to token endpoint.
     */
    url: URL

    /**
     * Process the response from the token endpoint.
     */
    conform: (response: Response) => Awaitable<Response | undefined>
  }

  /**
   * Additional data about the userinfo endpoint.
   */
  userinfo: {

    /**
     * Full URL to userinfo endpoint.
     */
    url: URL

    /**
     * Make a request to the userinfo endpoint.
     */
    request: (
      context: { tokens: TokenSet, provider: InternalOAuthConfig | InternalOIDCConfig }
    ) => Awaitable<Profile>
  }
}

/**
 * Internally generated config for email authentication.
 */
export interface InternalEmailConfig extends ProviderConfig {
  type: 'email'
}

/**
 * Internally generated config for credentials authentication.
 */
export interface InternalCredentialsConfig extends ProviderConfig {
  type: 'credentials'
}

/**
 * Any internally generated config.
 */
export type AnyInternalConfig = 
  | InternalOAuthConfig 
  | InternalOIDCConfig 
  | InternalEmailConfig 
  | InternalCredentialsConfig

export async function transformProviders(provider: Provider): Promise<AnyInternalConfig> {
  switch (provider.type) {
    case 'oauth': 
      return transformOAuthProvider(provider)

    case 'oidc':
      return transformOIDCProvider(provider)

    case 'email':
      return transformEmailProvider(provider)

    case 'credentials':
      return transformCredentialsProvider(provider)

    default:
      throw new TypeError(`Invalid provider type: ${JSON.stringify(provider)}`)
  }
}

export async function transformOAuthProvider(provider: OAuth2Config<any>): Promise<InternalOAuthConfig> {
  const authorizationServer = await getAuthorizationServer(provider)

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

    const profile = await request

    const profileResult = await getProfile(profile, provider, context.tokens)

    return profileResult
  }

  return {
    ...provider,
    authorizationServer,
    client,
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

export async function transformOIDCProvider(provider: OIDCConfig<any>): Promise<InternalOIDCConfig> {
  return {
    ...provider,
    authorizationServer: undefined as any,
    client: undefined as any,
    authorization: undefined as any,
    token: undefined as any,
    userinfo: undefined as any
  }
}

export async function transformEmailProvider(provider: EmailConfig): Promise<InternalEmailConfig> {
  return { ...provider }
}

export async function transformCredentialsProvider(provider: CredentialsConfig): Promise<InternalCredentialsConfig> {
  return { ...provider }
}


async function getAuthorizationServer(provider: OAuth2Config<any> | OIDCConfig<any>): Promise<oauth.AuthorizationServer> {
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

/** 
 * Returns profile from an OAuth request, raw profile and auth provider details
 */
async function getProfile(
  OAuthProfile: Profile,
  provider: OAuth2Config<any> | OIDCConfig<any>,
  tokens: TokenSet,
) {
  try {
    const profile = await provider.profile?.(OAuthProfile, tokens) ?? defaultProfile(OAuthProfile)
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

function defaultProfile(profile: any): User {
  return {
    id: profile.sub ?? profile.id,
    name:
      profile.name ?? profile.nickname ?? profile.preferred_username ?? null,
    email: profile.email ?? null,
    image: profile.picture ?? null,
  }
}
