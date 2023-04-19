import { OIDCProvider, mergeOIDCOptions } from '../core/oidc'
import type { OIDCDefaultConfig, OIDCUserConfig } from '../core/oidc'

export interface GoogleProfile extends Record<string, any> {
  aud: string
  azp: string
  email: string
  email_verified: boolean
  exp: number
  family_name: string
  given_name: string
  hd: string
  iat: number
  iss: string
  jti: string
  name: string
  nbf: number
  picture: string
  sub: string
}

export const GoogleOptions: OIDCDefaultConfig<GoogleProfile> = {
  id: 'google',
  issuer: 'https://accounts.google.com',
}

export function Google<TUser = GoogleProfile>(
  options: OIDCUserConfig<GoogleProfile, TUser>
): OIDCProvider<GoogleProfile, TUser> {
  return new OIDCProvider(mergeOIDCOptions(options, GoogleOptions))
}
