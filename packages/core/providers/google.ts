import { OIDCProvider, mergeOIDCOptions } from '../src/providers/oidc.js'
import type { OIDCDefaultConfig, OIDCUserConfig } from '../src/providers/oidc.js'

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

export function Google(options: OIDCUserConfig<GoogleProfile>): OIDCProvider<GoogleProfile> {
  return new OIDCProvider(mergeOIDCOptions(options, GoogleOptions))
}
