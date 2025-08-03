import { createSign, createVerify, createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { Buffer } from 'buffer';
import { AlgorithmImplementation, SecretOrKey } from './types.js';
import { base64urlEscape, base64urlUnescape } from '../jwt-core.js';
import { derToJose, joseToDer } from './ecdsa-sig-formatter.js';
import { validateCryptographicParameters, validateECDSASignatureComponents } from '../shared/crypto-validation.js';

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

function createEcdsaSigner(bits: string): AlgorithmImplementation {
  const algorithm = 'SHA' + bits;
  const algoName = 'ES' + bits;
  
  return {
    sign(message: string | Buffer, key: SecretOrKey): string {
      const privateKey = normalizeKey(key, true);
      
      // Validate key parameters
      validateCryptographicParameters(privateKey, algoName);
      
      const signer = createSign(algorithm);
      signer.update(message);
      const derSignature = signer.sign(privateKey);
      // Convert DER format to Jose format
      return derToJose(derSignature, algoName);
    },
    
    verify(message: string | Buffer, signature: string, key: SecretOrKey): boolean {
      const publicKey = normalizeKey(key, false);
      
      // Validate key and signature parameters
      validateCryptographicParameters(publicKey, algoName, signature);
      
      const verifier = createVerify(algorithm);
      verifier.update(message);
      
      // Convert Jose format signature to DER format
      const derSignature = joseToDer(signature, algoName);
      
      return verifier.verify(publicKey, derSignature);
    }
  };
}

// Special case for secp256k1 curve
function createEcdsaK1Signer(): AlgorithmImplementation {
  const algorithm = 'SHA256';
  const algoName = 'ES256K';
  
  return {
    sign(message: string | Buffer, key: SecretOrKey): string {
      const privateKey = normalizeKey(key, true);
      
      // Validate key parameters
      validateCryptographicParameters(privateKey, algoName);
      
      const signer = createSign(algorithm);
      signer.update(message);
      const derSignature = signer.sign(privateKey);
      // Convert DER format to Jose format
      return derToJose(derSignature, algoName);
    },
    
    verify(message: string | Buffer, signature: string, key: SecretOrKey): boolean {
      const publicKey = normalizeKey(key, false);
      
      // Validate key and signature parameters
      validateCryptographicParameters(publicKey, algoName, signature);
      
      const verifier = createVerify(algorithm);
      verifier.update(message);
      
      // Convert Jose format signature to DER format
      const derSignature = joseToDer(signature, algoName);
      
      return verifier.verify(publicKey, derSignature);
    }
  };
}

export const ES256 = createEcdsaSigner('256');
export const ES384 = createEcdsaSigner('384');
export const ES512 = createEcdsaSigner('512');
export const ES256K = createEcdsaK1Signer();