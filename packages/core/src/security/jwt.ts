import { EncryptJWT, jwtDecrypt } from "jose";
import type { JWTPayload } from "jose";
import { hkdf } from "@panva/hkdf";

type Awaitable<T> = T | PromiseLike<T>;

const DefaultMaxAge = 30 * 24 * 60 * 60;

const now = () => (Date.now() / 1000) | 0;

async function getDerivedEncryptionKey(secret: string) {
  const derivedEncryptionKey = await hkdf(
    "sha256",
    secret,
    "",
    "Auth.js Generated Encryption Key",
    32
  );
  return derivedEncryptionKey;
}

export interface JWTOptions {
  secret: string
  maxAge?: number
  encode?: (params: JWTEncodeParams) => Awaitable<string>
  decode?: <T>(params: JWTDecodeParams) => Awaitable<T | null>
}

export interface JWTEncodeParams<T = {}> {
  /**
   * The JWT payload.
   */
  token?: T

  /**
   * The secret used to encode the Auth.js issued JWT.
   */
  secret: string;

  /**
   * The maximum age of the Auth.js issued JWT in seconds.
   *
   * @default 30 * 24 * 30 * 60 // 30 days
   */
  maxAge?: number;
}

/**
 * Issues a JWT, encrypted using "A256GCM" by default.
 */
export async function encode<T extends Record<string, any> = {}>(params: JWTEncodeParams<T>) {
  const { token = {}, secret, maxAge = DefaultMaxAge } = params;

  const encryptionSecret = await getDerivedEncryptionKey(secret);

  const encodedToken = await new EncryptJWT(token)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(now() + maxAge)
    .setJti(crypto.randomUUID())
    .encrypt(encryptionSecret);

  return encodedToken;
}

export interface JWTDecodeParams {
  /**
   * The Auth.js issued JWT to be decoded
   */
  token?: string;

  /**
   * The secret used to decode the Auth.js issued JWT.
   */
  secret: string;
}

/**
 * Decodes an Auth.js issued JWT.
 */
export async function decode<T = {}>(params: JWTDecodeParams): Promise<(T & JWTPayload) | null> {
  const { token, secret } = params;

  if (token == null) return null;

  const encryptionSecret = await getDerivedEncryptionKey(secret);

  const { payload } = await jwtDecrypt(token, encryptionSecret, { clockTolerance: 15 });

  return payload as T & JWTPayload;
}
