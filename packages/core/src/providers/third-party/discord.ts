import { OAuthProvider, mergeOAuthOptions } from "../core/oauth"
import type { OAuthDefaultConfig, OAuthUserConfig } from "../core/oauth"

/**
 * Corresponds to the user structure documented here:
 * https://discord.com/developers/docs/resources/user#user-object-user-structure
 */
export interface DiscordProfile extends Record<string, any> {
  /** the user's id (i.e. the numerical snowflake) */
  id: string
  /** the user's username, not unique across the platform */
  username: string
  /** the user's 4-digit discord-tag */
  discriminator: string
  /**
   * the user's avatar hash:
   * https://discord.com/developers/docs/reference#image-formatting
   */
  avatar: string | null
  /** whether the user belongs to an OAuth2 application */
  bot?: boolean
  /**
   * whether the user is an Official Discord System user (part of the urgent
   * message system)
   */
  system?: boolean
  /** whether the user has two factor enabled on their account */
  mfa_enabled: boolean
  /**
   * the user's banner hash:
   * https://discord.com/developers/docs/reference#image-formatting
   */
  banner: string | null

  /** the user's banner color encoded as an integer representation of hexadecimal color code */
  accent_color: number | null

  /**
   * the user's chosen language option:
   * https://discord.com/developers/docs/reference#locales
   */
  locale: string
  /** whether the email on this account has been verified */
  verified: boolean
  /** the user's email */
  email: string | null
  /**
   * the flags on a user's account:
   * https://discord.com/developers/docs/resources/user#user-object-user-flags
   */
  flags: number
  /**
   * the type of Nitro subscription on a user's account:
   * https://discord.com/developers/docs/resources/user#user-object-premium-types
   */
  premium_type: number
  /**
   * the public flags on a user's account:
   * https://discord.com/developers/docs/resources/user#user-object-user-flags
   */
  public_flags: number
  /** undocumented field; corresponds to the user's custom nickname */
  display_name: string | null
  /**
   * undocumented field; corresponds to the Discord feature where you can e.g.
   * put your avatar inside of an ice cube
   */
  avatar_decoration: string | null
  /**
   * undocumented field; corresponds to the premium feature where you can
   * select a custom banner color
   */
  banner_color: string | null
  /** undocumented field; the CDN URL of their profile picture */
  image_url: string
}

export const DiscordOptions: OAuthDefaultConfig<DiscordProfile> = {
  id: 'discord',
  endpoints: {
    authorization: {
      url: "https://discord.com/api/oauth2/authorize?scope=identify+email",
    },
    token: {
      url: "https://discord.com/api/oauth2/token",
    },
    userinfo: {
      url: "https://discord.com/api/users/@me",
    }
  }
}

export function Discord<TUser = DiscordProfile, TSession = TUser>(
  options: OAuthUserConfig<DiscordProfile, TUser, TSession>
): OAuthProvider<DiscordProfile, TUser, TSession> {
  return new OAuthProvider(mergeOAuthOptions(options, DiscordOptions))
}

