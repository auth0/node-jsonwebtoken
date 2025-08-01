/**
 * Supported JWT signing algorithms
 */
export type Algorithm =
  // HMAC algorithms
  | 'HS256' | 'HS384' | 'HS512'
  // RSA algorithms
  | 'RS256' | 'RS384' | 'RS512'
  // RSA-PSS algorithms
  | 'PS256' | 'PS384' | 'PS512'
  // ECDSA algorithms
  | 'ES256' | 'ES384' | 'ES512'
  // Additional ECDSA curves
  | 'ES256K'
  // EdDSA algorithms (Ed25519 and Ed448)
  | 'EdDSA'
  // No signature
  | 'none';

export type HmacAlgorithm = 'HS256' | 'HS384' | 'HS512';
export type RsaAlgorithm = 'RS256' | 'RS384' | 'RS512';
export type PssAlgorithm = 'PS256' | 'PS384' | 'PS512';
export type EcdsaAlgorithm = 'ES256' | 'ES384' | 'ES512' | 'ES256K';
export type EddsaAlgorithm = 'EdDSA';
export type AsymmetricAlgorithm = RsaAlgorithm | PssAlgorithm | EcdsaAlgorithm | EddsaAlgorithm;

/**
 * Algorithm to key type mapping
 */
export interface AlgorithmKeyTypeMap {
  HS256: 'secret';
  HS384: 'secret';
  HS512: 'secret';
  RS256: 'rsa';
  RS384: 'rsa';
  RS512: 'rsa';
  PS256: 'rsa' | 'rsa-pss';
  PS384: 'rsa' | 'rsa-pss';
  PS512: 'rsa' | 'rsa-pss';
  ES256: 'ec';
  ES384: 'ec';
  ES512: 'ec';
  ES256K: 'ec';
  EdDSA: 'ed25519' | 'ed448';
  none: 'none';
}