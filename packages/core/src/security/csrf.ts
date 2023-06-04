/** 
 * Web compatible method to create a hash, using SHA256.
 */
export async function createHash(message: string) {
  const data = new TextEncoder().encode(message)

  const hash = await crypto.subtle.digest("SHA-256", data)

  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toString()
}

const sizedHex = (size: number) => ("0" + size.toString(16)).slice(-2)

const concatentateSizedHex = (previous: string, current: number): string => previous + sizedHex(current)

/** 
 * Web compatible method to create a random string of a given length.
 */
export function randomString(size: number = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(size))
  return Array.from(bytes).reduce(concatentateSizedHex, "")
}
