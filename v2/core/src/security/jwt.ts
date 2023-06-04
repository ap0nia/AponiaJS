import { hkdf } from "@panva/hkdf";
import { EncryptJWT, jwtDecrypt, type JWTPayload } from "jose";
import type { Awaitable, Nullish } from "../types.js";

const oneDayInSeconds = 24 * 60 * 60;

const DefaultMaxAge = oneDayInSeconds;

const now = () => (Date.now() / 1000) | 0;

export interface JWTEncodeParams<T = {}> {
  token?: T
  secret: string;
  maxAge?: number;
}

export interface JWTDecodeParams {
  token?: string;
  secret: string;
}

export interface JWTOptions {
  secret: string
  maxAge?: number
  encode?: (params: JWTEncodeParams) => Awaitable<string>
  decode?: <T>(params: JWTDecodeParams) => Awaitable<T | Nullish>
}

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

export async function decode<T = {}>(params: JWTDecodeParams): Promise<(T & JWTPayload) | Nullish> {
  const { token, secret } = params;

  if (token == null) return null;

  const encryptionSecret = await getDerivedEncryptionKey(secret);

  const { payload } = await jwtDecrypt(token, encryptionSecret, { clockTolerance: 15 });

  return payload as T & JWTPayload;
}
