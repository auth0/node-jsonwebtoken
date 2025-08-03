import { KeyObject } from 'crypto';

export type Algorithm =
  | 'HS256' | 'HS384' | 'HS512'
  | 'RS256' | 'RS384' | 'RS512'
  | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384' | 'ES512' | 'ES256K'
  | 'EdDSA'
  | 'none';

export interface JwtHeader {
  alg: Algorithm;
  typ?: string;
  kid?: string;
  jku?: string;
  x5u?: string;
  x5t?: string;
  x5c?: string[];
  [key: string]: any;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: any;
}

export type Secret = string | Buffer | KeyObject | { key: string | Buffer; passphrase: string };
export type PublicKey = string | Buffer | KeyObject;

export interface SignOptions {
  algorithm?: Algorithm;
  expiresIn?: string | number;
  notBefore?: string | number;
  audience?: string | string[];
  issuer?: string;
  jwtid?: string;
  subject?: string;
  noTimestamp?: boolean;
  header?: object;
  keyid?: string;
  mutatePayload?: boolean;
  allowInsecureKeySizes?: boolean;
  allowInvalidAsymmetricKeyTypes?: boolean;
  allowInsecureNoneAlgorithm?: boolean;
  encoding?: string;
  // DoS Protection options
  maxTokenSize?: number;
  maxPayloadSize?: number;
  maxPayloadDepth?: number;
  maxClaimCount?: number;
  disableDoSProtection?: boolean;
}

export interface VerifyOptions {
  algorithms?: Algorithm[];
  audience?: string | RegExp | (string | RegExp)[];
  complete?: boolean;
  issuer?: string | string[];
  jwtid?: string;
  ignoreExpiration?: boolean;
  ignoreNotBefore?: boolean;
  subject?: string;
  clockTolerance?: number;
  maxAge?: string | number;
  clockTimestamp?: number;
  nonce?: string;
  allowInvalidAsymmetricKeyTypes?: boolean;
  allowInsecureKeySizes?: boolean;
  // Header validation options
  maxHeaderSize?: number; // Maximum header size in bytes (default: 8192)
  maxKidLength?: number; // Maximum kid parameter length (default: 1024)
  kidCharacterWhitelist?: RegExp; // Regex for allowed kid characters (default: /^[\w\-._~]+$/)
  disableHeaderValidation?: boolean; // Disable all header validation (default: false)
  // DoS Protection options
  maxTokenSize?: number;
  maxPayloadSize?: number;
  maxPayloadDepth?: number;
  maxClaimCount?: number;
  disableDoSProtection?: boolean;
}

export interface DecodeOptions {
  complete?: boolean;
  json?: boolean;
  // DoS Protection options
  maxTokenSize?: number;
  maxPayloadSize?: number;
  maxPayloadDepth?: number;
  maxClaimCount?: number;
  disableDoSProtection?: boolean;
}

export interface CompleteResult {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
}

export type GetPublicKeyOrSecret = (
  header: JwtHeader
) => Promise<Secret | PublicKey>;

// Callback types
export type SignCallback = (err: Error | null, token?: string) => void;
export type VerifyCallback = (err: VerifyErrors | null, decoded?: JwtPayload) => void;
export type VerifyCallbackComplete = (err: VerifyErrors | null, decoded?: CompleteResult) => void;

// Import actual error classes
import { JsonWebTokenError } from './lib/JsonWebTokenError.js';
import { NotBeforeError } from './lib/NotBeforeError.js';
import { TokenExpiredError } from './lib/TokenExpiredError.js';

export type VerifyErrors = JsonWebTokenError | NotBeforeError | TokenExpiredError;