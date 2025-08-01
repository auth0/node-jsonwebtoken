import { createSign, createVerify, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { Buffer } from 'buffer';
import { AlgorithmImplementation, SecretOrKey } from './types.js';
import { base64urlEscape, base64urlUnescape } from '../jwt-core.js';

function normalizeKey(key: SecretOrKey, forSigning: boolean): KeyObject {
  if (key instanceof KeyObject) {
    return key;
  }
  
  if (Buffer.isBuffer(key) || typeof key === 'string') {
    return forSigning ? createPrivateKey(key) : createPublicKey(key);
  }
  
  if (typeof key === 'object' && 'key' in key) {
    return forSigning ? createPrivateKey(key) : createPublicKey(key);
  }
  
  throw new TypeError('Invalid key type');
}

function createRsaSigner(bits: string): AlgorithmImplementation {
  const algorithm = 'RSA-SHA' + bits;
  
  return {
    sign(message: string | Buffer, key: SecretOrKey): string {
      const privateKey = normalizeKey(key, true);
      const signer = createSign(algorithm);
      signer.update(message);
      const signature = signer.sign(privateKey, 'base64');
      return base64urlEscape(signature);
    },
    
    verify(message: string | Buffer, signature: string, key: SecretOrKey): boolean {
      const publicKey = normalizeKey(key, false);
      const verifier = createVerify(algorithm);
      verifier.update(message);
      // Convert base64url signature back to base64
      const base64Signature = base64urlUnescape(signature);
      return verifier.verify(publicKey, base64Signature, 'base64');
    }
  };
}

export const RS256 = createRsaSigner('256');
export const RS384 = createRsaSigner('384');
export const RS512 = createRsaSigner('512');