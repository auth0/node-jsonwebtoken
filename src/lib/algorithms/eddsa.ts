import { sign as cryptoSign, verify as cryptoVerify, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
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

export const EdDSA: AlgorithmImplementation = {
  sign(message: string | Buffer, key: SecretOrKey): string {
    const privateKey = normalizeKey(key, true);
    
    // Validate key type for EdDSA
    const keyType = privateKey.asymmetricKeyType;
    if (!keyType || !['ed25519', 'ed448', 'x25519', 'x448'].includes(keyType)) {
      throw new Error('Invalid key for EdDSA algorithm');
    }
    
    const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
    const signature = cryptoSign(null, messageBuffer, privateKey);
    return base64urlEscape(signature.toString('base64'));
  },
  
  verify(message: string | Buffer, signature: string, key: SecretOrKey): boolean {
    const publicKey = normalizeKey(key, false);
    
    // Validate key type for EdDSA
    const keyType = publicKey.asymmetricKeyType;
    if (!keyType || !['ed25519', 'ed448', 'x25519', 'x448'].includes(keyType)) {
      throw new Error('Invalid key for EdDSA algorithm');
    }
    
    const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
    const signatureBuffer = Buffer.from(base64urlUnescape(signature), 'base64');
    
    return cryptoVerify(null, messageBuffer, publicKey, signatureBuffer);
  }
};