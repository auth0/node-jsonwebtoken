import { createHmac, timingSafeEqual, createSecretKey, KeyObject } from 'crypto';
import { Buffer } from 'buffer';
import { AlgorithmImplementation, SecretOrKey } from './types.js';
import { base64urlEscape, base64urlUnescape } from '../jwt-core.js';

function normalizeSecret(key: SecretOrKey): Buffer | import('crypto').KeyObject {
  if (key instanceof Buffer) {
    return createSecretKey(key);
  }
  
  if (typeof key === 'string') {
    return createSecretKey(Buffer.from(key));
  }
  
  if (key instanceof KeyObject) {
    if (key.type !== 'secret') {
      throw new TypeError('Invalid secret key type');
    }
    return key;
  }
  
  throw new TypeError('Invalid key type');
}

function createHmacSigner(bits: string): AlgorithmImplementation {
  return {
    sign(message: string | Buffer, key: SecretOrKey): string {
      const secret = normalizeSecret(key);
      const hmac = createHmac('sha' + bits, secret);
      hmac.update(message);
      const signature = hmac.digest('base64');
      return base64urlEscape(signature);
    },
    
    verify(message: string | Buffer, signature: string, key: SecretOrKey): boolean {
      const secret = normalizeSecret(key);
      const computedSignature = this.sign(message, secret);
      
      // Convert both signatures to buffers for timing-safe comparison
      const sig1 = Buffer.from(signature);
      const sig2 = Buffer.from(computedSignature);
      
      // Check length first (not timing sensitive info)
      if (sig1.length !== sig2.length) {
        return false;
      }
      
      return timingSafeEqual(sig1, sig2);
    }
  };
}

export const HS256 = createHmacSigner('256');
export const HS384 = createHmacSigner('384');
export const HS512 = createHmacSigner('512');