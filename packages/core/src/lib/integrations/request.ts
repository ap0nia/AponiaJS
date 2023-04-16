import { parse } from "cookie"

export type InternalRequest = {
  request: Request
  url: URL
  cookies: Record<string, string>
  session?: any
  user?: any
}

export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { request, url, cookies }
}
