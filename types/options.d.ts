import { Algorithm } from './algorithms';
import { KeyObject } from 'crypto';

/**
 * JWT Header
 */
export interface JwtHeader {
  alg?: string | Algorithm;
  typ?: string;
  kid?: string;
  jku?: string;
  x5u?: string | string[];
  x5c?: string | string[];
  x5t?: string;
  'x5t#S256'?: string;
  x5cs?: string | string[];
  [header: string]: any;
}

/**
 * JWT Payload
 */
export interface JwtPayload {
  [key: string]: any;
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
}

/**
 * Complete JWT structure
 */
export interface Jwt {
  header: JwtHeader;
  payload: JwtPayload | string;
  signature: string;
}

/**
 * Options for signing a JWT
 */
export interface SignOptions {
  /**
   * Signature algorithm. Default: 'HS256'
   */
  algorithm?: Algorithm;
  
  /**
   * Expressed in seconds or a string describing a time span using vercel/ms
   * Eg: 60, "2 days", "10h", "7d"
   */
  expiresIn?: string | number;
  
  /**
   * Expressed in seconds or a string describing a time span using vercel/ms
   * Eg: 60, "2 days", "10h", "7d"
   */
  notBefore?: string | number;
  
  /**
   * Audience
   */
  audience?: string | string[];
  
  /**
   * Subject
   */
  subject?: string;
  
  /**
   * Issuer
   */
  issuer?: string;
  
  /**
   * JWT ID
   */
  jwtid?: string;
  
  /**
   * If true, the sign function will modify the payload object directly.
   * This is useful if you need a raw reference to the payload after claims
   * have been applied to it but before it has been encoded into a token.
   */
  mutatePayload?: boolean;
  
  /**
   * If true, will not include iat in the payload
   */
  noTimestamp?: boolean;
  
  /**
   * Additional header fields
   */
  header?: JwtHeader;
  
  /**
   * Encoding for the token
   */
  encoding?: string;
  
  /**
   * Key ID hint
   */
  keyid?: string;
  
  /**
   * Allow keys smaller than 2048 bits for RSA
   * @deprecated This option is insecure and should not be used
   */
  allowInsecureKeySizes?: boolean;
  
  /**
   * Allow invalid asymmetric key types
   * @deprecated This option is insecure and should not be used
   */
  allowInvalidAsymmetricKeyTypes?: boolean;
}

/**
 * Options for verifying a JWT
 */
export interface VerifyOptions {
  /**
   * List of allowed algorithms
   */
  algorithms?: Algorithm[];
  
  /**
   * Audience(s) to check against
   */
  audience?: string | RegExp | Array<string | RegExp>;
  
  /**
   * Clock timestamp in seconds to use as the current time
   */
  clockTimestamp?: number;
  
  /**
   * Number of seconds to tolerate when checking nbf and exp claims
   */
  clockTolerance?: number;
  
  /**
   * Return an object with decoded header, payload and signature instead of only the payload
   */
  complete?: boolean;
  
  /**
   * Issuer(s) to check against
   */
  issuer?: string | string[];
  
  /**
   * If true, do not validate the expiration of the token
   */
  ignoreExpiration?: boolean;
  
  /**
   * If true, do not validate the not before of the token
   */
  ignoreNotBefore?: boolean;
  
  /**
   * JWT ID to check against
   */
  jwtid?: string;
  
  /**
   * Nonce value to check against for OpenID tokens
   */
  nonce?: string;
  
  /**
   * Subject to check against
   */
  subject?: string;
  
  /**
   * Maximum age of the token in seconds or timespan string
   */
  maxAge?: string | number;
  
  /**
   * Allow invalid asymmetric key types
   * @deprecated This option is insecure and should not be used
   */
  allowInvalidAsymmetricKeyTypes?: boolean;
}

/**
 * Options for decoding a JWT
 */
export interface DecodeOptions {
  /**
   * Return an object with decoded header, payload and signature
   */
  complete?: boolean;
  
  /**
   * Force JSON.parse on the payload even if the header doesn't contain "typ":"JWT"
   */
  json?: boolean;
}

/**
 * Secret key type used for signing/verification
 */
export type Secret =
  | string
  | Buffer
  | KeyObject
  | { key: string | Buffer; passphrase: string };

/**
 * Private key type used for signing
 */
export type PrivateKey =
  | string
  | Buffer
  | KeyObject
  | { key: string | Buffer; passphrase: string };

/**
 * Public key type used for verification
 */
export type PublicKey =
  | string
  | Buffer
  | KeyObject;

/**
 * Callback for sign function
 */
export type SignCallback = (
  err: Error | null, 
  encoded: string | undefined
) => void;

/**
 * Callback for verify function
 */
export type VerifyCallback<T = JwtPayload | string> = (
  err: VerifyErrors | null,
  decoded: T | undefined,
) => void;

/**
 * Callback for getting public key or secret dynamically
 */
export type SigningKeyCallback = (
  err: any,
  signingKey?: Secret
) => void;

/**
 * Function to get public key or secret based on the JWT header
 */
export type GetPublicKeyOrSecret = (
  header: JwtHeader,
  callback: SigningKeyCallback
) => void;

/**
 * Union type for all verification-related errors
 */
export type VerifyErrors = import('./errors').VerifyErrors;