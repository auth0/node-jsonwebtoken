/// <reference types="node" />

// Re-export all types
export * from './algorithms';
export * from './errors';
export * from './options';

// Import types for function declarations
import {
  SignOptions,
  VerifyOptions,
  DecodeOptions,
  Secret,
  PrivateKey,
  PublicKey,
  SignCallback,
  VerifyCallback,
  GetPublicKeyOrSecret,
  Jwt,
  JwtPayload
} from './options';

/**
 * Synchronously sign the given payload into a JSON Web Token string
 * @param payload - Payload to sign, could be an literal, buffer or string
 * @param secretOrPrivateKey - Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
 * @param options - Options for the signature
 * @returns The JSON Web Token string
 */
export function sign(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret | PrivateKey,
  options?: SignOptions,
): string;

/**
 * Asynchronously sign the given payload into a JSON Web Token string
 * @param payload - Payload to sign, could be an literal, buffer or string
 * @param secretOrPrivateKey - Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
 * @param options - Options for the signature
 * @param callback - Callback to get the encoded token on
 */
export function sign(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret | PrivateKey,
  callback: SignCallback,
): void;
export function sign(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret | PrivateKey,
  options: SignOptions,
  callback: SignCallback,
): void;

/**
 * Synchronously verify given token using a secret or a public key to get a decoded token
 * @param token - JWT string to verify
 * @param secretOrPublicKey - Either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
 * @param options - Options for the verification
 * @returns The decoded token.
 */
export function verify(
  token: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  options?: VerifyOptions & { complete?: false },
): JwtPayload | string;
export function verify(
  token: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  options?: VerifyOptions & { complete: true },
): Jwt;

/**
 * Asynchronously verify given token using a secret or a public key to get a decoded token
 * @param token - JWT string to verify
 * @param secretOrPublicKey - A string or buffer containing either the secret for HMAC algorithms,
 * or the PEM encoded public key for RSA and ECDSA. If jwt.verify is called asynchronous,
 * secretOrPublicKey can be a function that should fetch the secret or public key
 * @param options - Options for the verification
 * @param callback - Callback to get the decoded token on
 */
export function verify(
  token: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  callback?: VerifyCallback,
): void;
export function verify(
  token: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  options: VerifyOptions & { complete?: false },
  callback?: VerifyCallback<JwtPayload | string>,
): void;
export function verify(
  token: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  options: VerifyOptions & { complete: true },
  callback?: VerifyCallback<Jwt>,
): void;

/**
 * Returns the decoded payload without verifying if the signature is valid.
 * @param token - JWT string to decode
 * @param options - Options for decoding
 * @returns The decoded Token
 */
export function decode(token: string, options: DecodeOptions & { complete: true }): null | Jwt;
export function decode(token: string, options?: DecodeOptions): null | JwtPayload | string;

// Re-export error classes from the main export
export { JsonWebTokenError, TokenExpiredError, NotBeforeError } from './errors';