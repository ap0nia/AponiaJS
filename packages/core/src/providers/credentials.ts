import { JWTOptions } from "@auth/core/jwt";
import { InternalRequest } from "../internal/request";
import { InternalResponse } from "../internal/response";
import { InternalCookiesOptions } from "../security/cookie";

interface Pages {
  signIn: string
  signOut: string
  callback: string
}

export class CredentialsProvider<T> {
  type = 'credentials' as const

  jwt: JWTOptions

  cookies: InternalCookiesOptions

  pages: Pages

  constructor() {
    this.jwt = Object.create(null)
    this.cookies = Object.create(null)
    this.pages = Object.create(null)
  }

  setPages(pages: Partial<Pages>) {
    this.pages = {
      signIn: `${pages.signIn ?? '/auth/login'}/${this.type}`,
      signOut: `${pages.signOut ?? '/auth/logout'}/${this.type}`,
      callback: `${pages.callback ?? '/auth/callback'}/${this.type}`
    }
  }

  setCookiesOptions(options: InternalCookiesOptions) {
    this.cookies = options
  }

  setJWTOptions(options: JWTOptions) {
    this.jwt = options
  }

  async initialize() {}

  async signIn(request: InternalRequest): Promise<InternalResponse> {
    return {}
  }

  async callback(request: InternalRequest): Promise<InternalResponse> {
    return {}
  }

  async signOut(request: InternalRequest): Promise<InternalResponse> {
    return {}
  }
}
