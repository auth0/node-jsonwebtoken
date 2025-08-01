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
}

export interface DecodeOptions {
  complete?: boolean;
  json?: boolean;
}

export interface CompleteResult {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
}

export type GetPublicKeyOrSecret = (
  header: JwtHeader
) => Promise<Secret | PublicKey>;

// Import actual error classes
import { JsonWebTokenError } from './lib/JsonWebTokenError.js';
import { NotBeforeError } from './lib/NotBeforeError.js';
import { TokenExpiredError } from './lib/TokenExpiredError.js';

export type VerifyErrors = JsonWebTokenError | NotBeforeError | TokenExpiredError;