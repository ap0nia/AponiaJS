import { EncryptJWT, jwtDecrypt } from "jose";
import { hkdf } from "@panva/hkdf";
import { getSessionToken } from ".";
import type { User, Session } from '.'

const DEFAULT_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

const now = () => (Date.now() / 1000) | 0;

/**
 * Issues a JWT, encrypted using "A256GCM" by default.
 */
export async function encode<T extends Record<string, unknown> = {}>(params: JWTEncodeParams<T>) {
  const { token = {}, secret, maxAge = DEFAULT_MAX_AGE } = params;

  const encryptionSecret = await getDerivedEncryptionKey(secret);

  const encodedToken = await new EncryptJWT(token)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(now() + maxAge)
    .setJti(crypto.randomUUID())
    .encrypt(encryptionSecret);

  return encodedToken;
}

/**
 * Decodes an Auth.js issued JWT.
 */
export async function decode<T = {}>(params: JWTDecodeParams): Promise<T | null> {
  const { token, secret } = params;

  if (token == null) return null;

  const encryptionSecret = await getDerivedEncryptionKey(secret);

  const { payload } = await jwtDecrypt(token, encryptionSecret, { clockTolerance: 15 });

  return payload as T;
}

async function getDerivedEncryptionKey(secret: string) {
  const derivedEncryptionKey = await hkdf(
    "sha256",
    secret,
    "",
    "Aponia Auth",
    32
  );
  return derivedEncryptionKey;
}

export interface JWTEncodeParams<T extends Record<string, unknown> = {}> {
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

export interface JWT extends Record<string, unknown> {
  session: Session
  user: User
}

export interface TokenSessionConfig {
  secret: string
  maxAge?: number
}


export class TokenSession<T extends JWT = JWT> {
  config: TokenSessionConfig

  constructor(config: TokenSessionConfig) {
    this.config = config
  }

  async createSessionToken(session: T) {
    const token = await encode({ ...this.config, token: session })
    return token
  }

  async getRequestSession(request: Request) {
    const token = getSessionToken(request)

    const session = await decode<T>({ ...this.config, token })

    if (session == null) throw new Error()

    if (session.session.expires < new Date().getTime()) throw new Error()

    return session
  }

  async validateSession(session: T) {
    if (session.session.expires > new Date().getTime()) {
      return { session, token: null }
    }

    const token = await encode({ ...this.config, token: session })

    return { session, token }
  }

  async validateRequestSession(request: Request) {
    const session = await this.getRequestSession(request)

    const validSession = await this.validateSession(session)

    return validSession
  }
}
