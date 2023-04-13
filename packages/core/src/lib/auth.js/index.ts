import { merge } from "$lib/utils/merge"
import type { Override } from "$lib/utils/override"
import type { Awaitable } from "$lib/utils/promise"
import type { Client, OAuth2TokenEndpointResponse, OpenIDTokenEndpointResponse } from "oauth4webapi"

interface OAuthProviderButtonStyles {
  logo: string
  logoDark: string
  bg: string
  bgDark: string
  text: string
  textDark: string
}

interface Profile {
  sub?: string | null
  name?: string | null
  email?: string | null
  image?: string | null
}

interface User {
  id: string
  name?: string | null
  email?: string | null
  image?: string | null
}

function defaultProfile(profile: any): User {
  return {
    id: profile.sub ?? profile.id,
    name: profile.name ?? profile.nickname ?? profile.preferred_username ?? null,
    email: profile.email ?? null,
    image: profile.picture ?? null,
  }
}

// TODO:
type AuthorizationParameters = any

type IssuerMetadata = any

type OAuthCallbackChecks = any

type OpenIDCallbackChecks = any

type PartialIssuer = Partial<Pick<IssuerMetadata, "jwks_endpoint" | "issuer">>

type CallbackParamsType = any

type OAuthChecks = OpenIDCallbackChecks | OAuthCallbackChecks

type TokenSet = Partial<OAuth2TokenEndpointResponse | OpenIDTokenEndpointResponse>

type UrlParams = Record<string, unknown>

interface InternalUrls {
  signinUrl: string
  callbackUrl: string
}

interface EndpointHandler<Profile extends UrlParams, Context = any, Result = any> {
  url?: string
  params?: Profile
  conform?: (response: Response) => Awaitable<Response | undefined>
  request?: (
    context: Context & { provider: OAuthConfigInternal<Profile> & InternalUrls }
  ) => Awaitable<Result>
}

type AuthorizationEndpointHandler = EndpointHandler<AuthorizationParameters>

type TokenEndpointHandler = EndpointHandler<
  UrlParams,
  {
    params: CallbackParamsType
    checks: OAuthChecks
  },
  {
    tokens: TokenSet
  }
>

type UserinfoEndpointHandler = EndpointHandler<UrlParams, { tokens: TokenSet }, Profile>

interface InternalEndpointMetadata {
  authorization?: { 
    url: URL
  }
  token?: {
    url: URL
    request?: TokenEndpointHandler["request"]
    conform?: TokenEndpointHandler["conform"]
  }
  userinfo?: { 
    url: URL;
    request?: UserinfoEndpointHandler["request"]
  }
}

type ProviderType = "oidc" | "oauth" | "email" | "credentials"

interface CommonProviderOptions {
  id: string
  name: string
  type: ProviderType
}

interface OAuth2Config<Profile> extends CommonProviderOptions, PartialIssuer {
  id: string
  name: string
  wellKnown?: string
  issuer?: string
  authorization?: string | AuthorizationEndpointHandler
  token?: string | TokenEndpointHandler
  userinfo?: string | UserinfoEndpointHandler
  type: "oauth"
  profile?: (profile: Profile, tokens: TokenSet) => Awaitable<User>
  checks?: ('pkce' | 'state' | 'none' | 'nonce')[]
  clientId?: string
  clientSecret?: string
  client?: Partial<Client>
  style?: OAuthProviderButtonStyles
  allowDangerousEmailAccountLinking?: boolean
  options?: OAuthUserConfig<Profile>
}

type InternalConfigOptions = { options?: Record<string, unknown> }

type AnyConfig<P = any> = OIDCConfig<P> | OAuth2Config<P>

type OAuthConfigInternal<Profile> = Override<
  OAuthConfig<Profile>, 
  Required<Pick<OAuthConfig<Profile>, "clientId" | "checks" | "profile">> & InternalEndpointMetadata
> 

/** 
 * @internal
 */
// prettier-ignore
type InternalProvider<T extends ProviderType = ProviderType> = InternalUrls & (
  T extends "oauth" ? OAuthConfigInternal<any> : 
  T extends "email" ? never /* ? EmailConfig */ :
  T extends "credentials" ? never /* ? CredentialsConfig */ : never
)

export type Provider<P extends Profile = Profile> = AnyConfig<P> & InternalConfigOptions

export type OIDCConfig<Profile> = Override<OAuth2Config<Profile>, { type: "oidc" }>

export type OAuthConfig<Profile> = OIDCConfig<Profile> | OAuth2Config<Profile>

export type OAuthUserConfig<Profile> = Override<
  Partial<OAuthConfig<Profile>>,
  Required<Pick<OAuthConfig<Profile>, "clientId" | "clientSecret">>
>

export type OIDCUserConfig<Profile> =
  Omit<Partial<OIDCConfig<Profile>>, "options" | "type"> &
  Required<Pick<OIDCConfig<Profile>, "clientId" | "clientSecret">>

export default function parseProviders(
  params: { providers: Provider[], url: URL }
): InternalProvider[] {
  const { url } = params

  const providers: InternalProvider[] = params.providers.map((provider) => {
    const { options: userOptions, ...defaultOptions } = provider

    const id = (userOptions?.id ?? defaultOptions.id) as string

    const mergedOptions = merge(defaultOptions, userOptions, {
      signinUrl: `${url}/signin/${id}`,
      callbackUrl: `${url}/callback/${id}`,
    })

    const internalProvider: InternalProvider = 
      provider.type === "oauth" || provider.type === "oidc" 
        ? normalizeOAuth(mergedOptions) 
        : mergedOptions

    return internalProvider
  })

  return providers
}

function normalizeOAuth(c: AnyConfig & InternalConfigOptions): OAuthConfigInternal<any> {
  const authorization = normalizeEndpoint<'authorization'>(c.authorization, c.issuer)

  if (authorization && !authorization.url?.searchParams.has("scope")) {
    authorization.url.searchParams.set("scope", "openid profile email")
  }

  const token = normalizeEndpoint<'token'>(c.token, c.issuer)

  const userinfo = normalizeEndpoint<'userinfo'>(c.userinfo, c.issuer)

  const wellKnown = c.issuer 
    ? c.wellKnown ?? `${c.issuer}/.well-known/openid-configuration`
    : c.wellKnown

  return {
    ...c,
    clientId: c.clientId ?? '',
    wellKnown,
    authorization,
    token,
    userinfo,
    checks: c.checks ?? ["pkce"],
    profile: c.profile ?? defaultProfile,
  }
}

function normalizeEndpoint<T extends keyof OAuthConfig<any>>(
  e?: OAuthConfig<any>[T],
  issuer?: string
): OAuthConfigInternal<any>[T] {
  if (!e && issuer) {
    return
  }

  if (typeof e === "string") {
    return { url: new URL(e) }
  }

  const url = new URL(e?.url ?? "https://authjs.dev")

  if (e?.params != null) {
    Object.entries(e.params).forEach(([key, value]) => {
      url.searchParams.set(key, key === 'claims' ? JSON.stringify(value) : String(value))
    })
  }

  return { url, request: e?.request, conform: e?.conform }
}
