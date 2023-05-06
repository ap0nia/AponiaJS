import { randomString } from "../security/csrf.js";
import type { InternalRequest } from "../internal/request.js";
import type { InternalResponse } from "../internal/response.js";
import type { Awaitable, DeepPartial, Nullish, ProviderPages } from "../types.js";

/**
 * Internal configuration for the email provider.
 */
export interface EmailConfig {
  theme: any
  pages: ProviderPages
  getEmail?: (request: InternalRequest) => Awaitable<string | Nullish>
  onAuth?: (request: InternalRequest, args: any) => Awaitable<InternalResponse | Nullish>
  onVerify?: (request: InternalRequest, args: any) => Awaitable<InternalResponse | Nullish>
}

/**
 * User configuration for the email provider.
 */
export interface EmailUserConfig extends DeepPartial<EmailConfig> {}

/**
 * Email provider.
 */
export class EmailProvider {
  id = 'email' as const

  config: EmailConfig

  constructor(config: EmailUserConfig) {
    this.config = {
      ...config,
      theme: config.theme,
      pages: {
        login: {
          route: config.pages?.login?.route ?? `/auth/login/${this.id}`,
          methods: config.pages?.login?.methods ?? ['POST'],
        },
        callback: {
          route: config.pages?.callback?.route ?? `/auth/callback/${this.id}`,
          methods: config.pages?.callback?.methods ?? ['GET'],
          redirect: config.pages?.callback?.redirect ?? '/',
        }
      }
    }
  }

  setJwtOptions() {
    return this
  }

  setCookiesOptions() {
    return this
  }

  async login(request: InternalRequest): Promise<InternalResponse> {
    const email = await this.config.getEmail?.(request)

    // TODO: error
    if (!email) {
      return {}
    }

    const token = randomString()

    const escapedHost = request.url.host.replace(/\./g, "&#8203;.")

    const url = new URL(`${request.url.origin}/${this.config.pages.callback}`)

    url.searchParams.set("token", token)
    url.searchParams.set("email", email)

    const brandColor = this.config.theme.brandColor ?? "#346df1"
    const buttonText = this.config.theme.buttonText ?? "#fff"

    const color = {
      background: "#f9f9f9",
      text: "#444",
      mainBackground: "#fff",
      buttonBackground: brandColor,
      buttonBorder: brandColor,
      buttonText,
    }

    const html = `
    <body style="background: ${color.background};">
      <table width="100%" border="0" cellspacing="20" cellpadding="0" style="background: ${color.mainBackground}; max-width: 600px; margin: auto; border-radius: 10px;">
        <tr>
          <td align="center"
            style="padding: 10px 0px; font-size: 22px; font-family: Helvetica, Arial, sans-serif; color: ${color.text};">
            Sign in to <strong>${escapedHost}</strong>
          </td>
        </tr>
        <tr>
          <td align="center" style="padding: 20px 0;">
            <table border="0" cellspacing="0" cellpadding="0">
              <tr>
                <td align="center" style="border-radius: 5px;" bgcolor="${color.buttonBackground}">
                  <a href="${url}" target="_blank" style="font-size: 18px; font-family: Helvetica, Arial, sans-serif; color: ${color.buttonText}; text-decoration: none; border-radius: 5px; padding: 10px 20px; border: 1px solid ${color.buttonBorder}; display: inline-block; font-weight: bold;">
                    Sign in
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td align="center"
            style="padding: 0px 0px 10px 0px; font-size: 16px; line-height: 22px; font-family: Helvetica, Arial, sans-serif; color: ${color.text};">
            If you did not request this email you can safely ignore it.
          </td>
        </tr>
      </table>
    </body>
    `

    return await (this.config.onAuth?.(request, { html, email, token, provider: this })) ?? {}
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    const token = request.url.searchParams.get('token')
    const email = request.url.searchParams.get('email')
    return await (this.config.onVerify?.(request, { token, email })) ?? {}
  }
}

/**
 * Create a new email provider.
 */
export function Email(config: EmailUserConfig) {
  return new EmailProvider(config)
}
