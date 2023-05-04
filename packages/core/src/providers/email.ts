import type { InternalRequest } from "../internal/request.js";
import type { InternalResponse } from "../internal/response.js";

type Nullish = null | undefined | void

type Awaitable<T> = PromiseLike<T> | T

interface Pages {
  /**
   * Route for initial email login.
   */
  login: {
    route: string
    methods: string[]
  }

  /**
   * Callback route for email login verification.
   */
  callback: {
    route: string
    methods: string[]
  }
}

export interface EmailConfig<T> {
  /**
   * Extract the email from the initial request.
   */
  getEmail: (request: InternalRequest) => Awaitable<string | Nullish>

  /**
   * After getting the email, boilerplate is generated for the email.
   * Handle the user logging in, i.e. sending a verification email.
   */
  onAuth: (request: InternalRequest) => Awaitable<InternalResponse<T>>

  /**
   * Handle verifying the user, i.e. after the user clicks the verification link in the email.
   */
  onVerify: (request: InternalRequest, args: any) => Awaitable<InternalResponse<T>>

  /**
   * Pages.
   */
  pages?: Partial<Pages>
}

/**
 * Email provider (first-party only).
 */
export class EmailProvider<T> {
  id = 'email' as const

  onAuth: (request: InternalRequest, args: any) => Awaitable<InternalResponse<T>>

  onVerify: (request: InternalRequest, args: any) => Awaitable<InternalResponse<T>>

  pages: Pages

  theme: any

  getEmail: (request: InternalRequest) => Awaitable<string | Nullish>

  constructor(config: EmailConfig<T>) {
    this.getEmail = config.getEmail
    this.onAuth = config.onAuth
    this.onVerify = config.onVerify
    this.pages = {
      login: {
        route: config.pages?.login?.route ?? `/auth/login/${this.id}`,
        methods: config.pages?.login?.methods ?? ['POST'],
      },
      callback: {
        route: config.pages?.callback?.route ?? `/auth/callback/${this.id}`,
        methods: config.pages?.callback?.methods ?? ['GET'],
      }
    }
  }

  /**
   * Credentials doesn't use JWT.
   */
  setJwtOptions() {
    return this
  }

  /**
   * Credentials doesn't use cookies.
   */
  setCookiesOptions() {
    return this
  }

  async login(request: InternalRequest): Promise<InternalResponse> {
    const email = await this.getEmail(request)

    // TODO: error
    if (!email) {
      return {}
    }

    const token = randomString()

    const escapedHost = request.url.host.replace(/\./g, "&#8203;.")

    const url = new URL(`${request.url.origin}/${this.pages.callback}`)

    url.searchParams.set("token", token)
    url.searchParams.set("email", email)

    const brandColor = this.theme.brandColor ?? "#346df1"
    const buttonText = this.theme.buttonText ?? "#fff"

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

    return this.onAuth(request, { html, email, token, provider: this })
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    const token = request.url.searchParams.get('token')
    const email = request.url.searchParams.get('email')
    return this.onVerify(request, { token, email })
  }
}

export function Email<T>(config: EmailConfig<T>) {
  return new EmailProvider<T>(config)
}

/** 
 * Web compatible method to create a random string of a given length
 */
export function randomString(size: number = 32) {
  const i2hex = (i: number) => ("0" + i.toString(16)).slice(-2)
  const r = (a: string, i: number): string => a + i2hex(i)
  const bytes = crypto.getRandomValues(new Uint8Array(size))
  return Array.from(bytes).reduce(r, "")
}
