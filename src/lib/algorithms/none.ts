import { AlgorithmImplementation, SecretOrKey } from './types.js';

/**
 * Implementation of the 'none' algorithm as specified in RFC 7519.
 * 
 * WARNING: This algorithm provides NO SECURITY and should only be used
 * in specific scenarios where the JWT is already secured by other means.
 * 
 * This implementation requires explicit opt-in via the allowInsecureNoneAlgorithm
 * option to prevent accidental usage.
 */
export const none: AlgorithmImplementation = {
  sign(message: string | Buffer, key: SecretOrKey): string {
    // The 'none' algorithm produces an empty signature
    return '';
  },
  
  verify(message: string | Buffer, signature: string, key: SecretOrKey): boolean {
    // For 'none' algorithm, signature must be empty
    return signature === '';
  }
};