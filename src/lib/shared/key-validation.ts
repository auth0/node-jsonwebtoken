import { KeyObject } from 'crypto';
import { JsonWebTokenError } from '../JsonWebTokenError.js';
import { validateAndNormalizeKey, validateBufferContent } from './encoding-validation.js';

// Minimum key length for HMAC algorithms (in bytes)
// Note: We use a lower limit for compatibility, but recommend at least 32 bytes
export const MIN_HMAC_KEY_LENGTH = 1; // At least 1 byte, but 32+ bytes recommended

// Public key format patterns
const PUBLIC_KEY_PATTERNS = [
  /-----BEGIN PUBLIC KEY-----/,
  /-----BEGIN RSA PUBLIC KEY-----/,
  /-----BEGIN EC PUBLIC KEY-----/,
  /-----BEGIN CERTIFICATE-----/,
  /-----BEGIN X509 CERTIFICATE-----/,
  /-----BEGIN OPENSSH PUBLIC KEY-----/,
  // Also check for common JWK public key indicators
  /"kty"\s*:\s*"RSA"/,
  /"kty"\s*:\s*"EC"/,
  /"kty"\s*:\s*"OKP"/,
  // Check for public key specific fields in JWK
  /"n"\s*:.*"e"\s*:/,  // RSA public key components
  /"x"\s*:.*"y"\s*:/,  // EC public key components
  /"x"\s*:.*"crv"\s*:/, // EdDSA public key components
];

// Private key format patterns (to distinguish from public)
const PRIVATE_KEY_PATTERNS = [
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
  /"d"\s*:/, // Private key component in JWK
];

/**
 * Detects if a string contains a public key
 */
export function isPublicKeyFormat(key: string): boolean {
  // First check if it's explicitly a private key
  for (const pattern of PRIVATE_KEY_PATTERNS) {
    if (pattern.test(key)) {
      return false;
    }
  }
  
  // Then check for public key patterns
  for (const pattern of PUBLIC_KEY_PATTERNS) {
    if (pattern.test(key)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Validates that a key is appropriate for HMAC algorithms
 */
export function validateHMACKey(key: string | Buffer | KeyObject): void {
  // Check KeyObject type
  if (key instanceof KeyObject) {
    if (key.type !== 'secret') {
      throw new JsonWebTokenError(
        'Invalid key type for HMAC algorithm. HMAC requires a symmetric secret key, but an asymmetric key was provided.'
      );
    }
    return;
  }
  
  // Check string keys for public key formats
  if (typeof key === 'string') {
    if (isPublicKeyFormat(key)) {
      throw new JsonWebTokenError(
        'Invalid key for HMAC algorithm. Public keys cannot be used as HMAC secrets.'
      );
    }
    
    // Check for empty strings
    if (!key || !key.trim()) {
      throw new JsonWebTokenError(
        'Invalid key for HMAC algorithm. Key must not be empty.'
      );
    }
    
    // Validate and normalize the key (checks for null bytes and control chars)
    const normalizedKey = validateAndNormalizeKey(key, 'HMAC key');
    
    // Check minimum length (in bytes when converted to Buffer)
    const keyLength = Buffer.byteLength(normalizedKey, 'utf8');
    if (keyLength < MIN_HMAC_KEY_LENGTH) {
      throw new JsonWebTokenError(
        `Invalid key for HMAC algorithm. Key must be at least ${MIN_HMAC_KEY_LENGTH} bytes (${MIN_HMAC_KEY_LENGTH * 8} bits). Actual: ${keyLength} bytes.`
      );
    }
  }
  
  // Check Buffer keys
  if (Buffer.isBuffer(key)) {
    if (key.length === 0) {
      throw new JsonWebTokenError(
        'Invalid key for HMAC algorithm. Key buffer must not be empty.'
      );
    }
    
    // Validate buffer content for null bytes
    validateBufferContent(key, 'HMAC key');
    
    if (key.length < MIN_HMAC_KEY_LENGTH) {
      throw new JsonWebTokenError(
        `Invalid key for HMAC algorithm. Key must be at least ${MIN_HMAC_KEY_LENGTH} bytes (${MIN_HMAC_KEY_LENGTH * 8} bits). Actual: ${key.length} bytes.`
      );
    }
  }
}

/**
 * Validates that the algorithm matches the key type
 */
export function validateAlgorithmKeyMatch(algorithm: string, key: string | Buffer | KeyObject): void {
  const isHMACAlgorithm = ['HS256', 'HS384', 'HS512'].includes(algorithm);
  const isAsymmetricAlgorithm = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 
                                  'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'].includes(algorithm);
  
  if (isHMACAlgorithm) {
    // For HMAC algorithms, ensure the key is not a public key
    if (typeof key === 'string') {
      if (isPublicKeyFormat(key)) {
        throw new JsonWebTokenError(
          `Algorithm "${algorithm}" requires a secret key, but a public key was provided.`
        );
      }
      // Additional validation for string keys will be done in validateHMACKey
    }
    
    if (key instanceof KeyObject && key.type !== 'secret') {
      throw new JsonWebTokenError(
        `Algorithm "${algorithm}" requires a secret key, but a ${key.type} key was provided.`
      );
    }
  }
  
  if (isAsymmetricAlgorithm) {
    // For asymmetric algorithms, ensure the key is not obviously a symmetric key
    if (key instanceof KeyObject && key.type === 'secret') {
      throw new JsonWebTokenError(
        `Algorithm "${algorithm}" requires an asymmetric key, but a symmetric secret key was provided.`
      );
    }
  }
}