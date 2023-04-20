import { parse } from "cookie"

export interface InternalRequest<T = any> {
  user?: T
  request: Request
  url: URL
  cookies: Record<string, string>
}

export async function toInternalRequest(request: Request): Promise<InternalRequest> {
  const url = new URL(request.url)
  const cookies = parse(request.headers.get("Cookie") ?? "")
  return { request, url, cookies }
}
