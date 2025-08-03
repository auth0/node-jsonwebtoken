import { describe, it, expect, beforeEach } from '@jest/globals';
import jwt from '../../src/index.js';
import { JsonWebTokenError } from '../../src/lib/JsonWebTokenError.js';
import {
  validateRSAKeyParameters,
  validateECPoint,
  validateSignatureFormat,
  validateECDSASignatureComponents,
  validateCryptographicParameters,
  validateEdDSAKey
} from '../../src/lib/shared/crypto-validation.js';
import { createPrivateKey, createPublicKey, KeyObject, generateKeyPairSync } from 'crypto';
import { Buffer } from 'buffer';
import fs from 'fs';
import path from 'path';

describe('Cryptographic Validation', () => {
  const payload = { data: 'test', iat: Math.floor(Date.now() / 1000) };
  
  describe('RSA Key Parameter Validation', () => {
    it('should accept standard RSA public exponents', () => {
      // Generate RSA key with standard exponent (65537)
      const { privateKey, publicKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicExponent: 65537
      });
      
      expect(() => validateRSAKeyParameters(publicKey)).not.toThrow();
      expect(() => validateRSAKeyParameters(privateKey)).not.toThrow();
    });

    it('should skip validation for non-RSA keys', () => {
      // Generate EC key
      const { publicKey: ecKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      // Should return early without throwing
      expect(() => validateRSAKeyParameters(ecKey)).not.toThrow();
      
      // Generate EdDSA key if supported
      try {
        const { publicKey: edKey } = generateKeyPairSync('ed25519');
        expect(() => validateRSAKeyParameters(edKey)).not.toThrow();
      } catch (err: any) {
        // Skip if EdDSA not supported
      }
    });

    it('should warn about unusual RSA public exponents', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Generate RSA key with unusual but valid exponent
      const { publicKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicExponent: 7 // Unusual but valid
      });
      
      validateRSAKeyParameters(publicKey);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('unusual public exponent: 7')
      );
      
      consoleSpy.mockRestore();
    });

    it('should reject RSA keys with public exponent 1', () => {
      // We can't actually generate a key with exponent 1 using crypto.generateKeyPairSync
      // as it will throw an error. So we'll mock this scenario
      const mockKey = {
        asymmetricKeyType: 'rsa',
        asymmetricKeyDetails: {
          publicExponent: 1
        }
      } as any as KeyObject;
      
      expect(() => validateRSAKeyParameters(mockKey)).toThrow(
        'Invalid RSA key: public exponent cannot be 1'
      );
    });

    it('should reject RSA keys with even public exponent', () => {
      const mockKey = {
        asymmetricKeyType: 'rsa',
        asymmetricKeyDetails: {
          publicExponent: 4
        }
      } as any as KeyObject;
      
      expect(() => validateRSAKeyParameters(mockKey)).toThrow(
        'Invalid RSA key: public exponent must be odd'
      );
    });

    it('should handle RSA keys with very large public exponent', () => {
      // Test line 76: exponent > Number.MAX_SAFE_INTEGER
      const mockKey = {
        asymmetricKeyType: 'rsa',
        asymmetricKeyDetails: {
          publicExponent: BigInt(Number.MAX_SAFE_INTEGER) + 1n
        }
      } as any as KeyObject;
      
      // Should not throw - large exponents are allowed
      expect(() => validateRSAKeyParameters(mockKey)).not.toThrow();
    });
  });

  describe('EC Point Validation', () => {
    it('should accept valid EC public keys', () => {
      // Generate valid EC keys
      const { publicKey: p256Key } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      const { publicKey: p384Key } = generateKeyPairSync('ec', {
        namedCurve: 'P-384'
      });
      const { publicKey: p521Key } = generateKeyPairSync('ec', {
        namedCurve: 'P-521'
      });
      
      expect(() => validateECPoint(p256Key, 'prime256v1')).not.toThrow();
      expect(() => validateECPoint(p384Key, 'secp384r1')).not.toThrow();
      expect(() => validateECPoint(p521Key, 'secp521r1')).not.toThrow();
    });

    it('should skip validation for unknown curves', () => {
      const { publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      // Should not throw for unknown curve
      expect(() => validateECPoint(publicKey, 'unknown-curve')).not.toThrow();
      
      // Test with a curve name that has publicKey details but no params
      const mockKey = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: { publicKey: 'mock' },
        export: () => Buffer.from('test')
      } as any as KeyObject;
      
      expect(() => validateECPoint(mockKey, 'brainpoolP256r1')).not.toThrow();
    });

    it('should handle non-EC keys gracefully', () => {
      const { publicKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048
      });
      
      expect(() => validateECPoint(publicKey, 'prime256v1')).not.toThrow();
    });

    it('should handle EC keys without publicKey details', () => {
      const mockKey = {
        asymmetricKeyType: 'ec'
        // No asymmetricKeyDetails or publicKey
      } as any as KeyObject;
      
      expect(() => validateECPoint(mockKey, 'prime256v1')).not.toThrow();
    });

    it('should reject EC points with coordinates outside the field', () => {
      // Mock key that exports specific DER data
      const mockKey = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: { publicKey: 'mock' },
        export: () => {
          // Create a fake DER with point data that has coordinates exceeding field size
          const buffer = Buffer.alloc(100);
          buffer[30] = 0x04; // Uncompressed point marker
          // Set x coordinate to all 0xFF (exceeds p for P-256)
          buffer.fill(0xff, 31, 63);
          // Set y coordinate
          buffer.fill(0x01, 63, 95);
          return buffer;
        }
      } as any as KeyObject;
      
      expect(() => validateECPoint(mockKey, 'prime256v1'))
        .toThrow('Invalid EC key: point coordinates are outside the field');
    });

    it('should reject EC point at infinity', () => {
      // Mock key that exports specific DER data with point at infinity
      const mockKey = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: { publicKey: 'mock' },
        export: () => {
          // Create a fake DER with point at infinity (0,0)
          const buffer = Buffer.alloc(100);
          // Place the uncompressed point marker at position where it can be found
          // with enough space for x and y coordinates (32 bytes each for P-256)
          buffer[20] = 0x04; // Uncompressed point marker
          // x and y coordinates (21-52 and 53-84) are already 0 by Buffer.alloc
          return buffer;
        }
      } as any as KeyObject;
      
      expect(() => validateECPoint(mockKey, 'prime256v1'))
        .toThrow('Invalid EC key: point at infinity is not allowed');
    });

    it('should accept EC points where only one coordinate is zero', () => {
      // Test branch coverage for line 160: x === 0n && y === 0n
      // Case 1: x is zero but y is not
      const mockKeyXZero = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: { publicKey: 'mock' },
        export: () => {
          const buffer = Buffer.alloc(100);
          buffer[20] = 0x04; // Uncompressed point marker
          // x is zero (21-52)
          // y is non-zero (53-84)
          buffer.fill(0x01, 53, 85);
          return buffer;
        }
      } as any as KeyObject;
      
      // Should not throw - not point at infinity
      expect(() => validateECPoint(mockKeyXZero, 'prime256v1')).not.toThrow();
      
      // Case 2: y is zero but x is not
      const mockKeyYZero = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: { publicKey: 'mock' },
        export: () => {
          const buffer = Buffer.alloc(100);
          buffer[20] = 0x04; // Uncompressed point marker
          // x is non-zero (21-52)
          buffer.fill(0x01, 21, 53);
          // y is zero (53-84)
          return buffer;
        }
      } as any as KeyObject;
      
      expect(() => validateECPoint(mockKeyYZero, 'prime256v1')).not.toThrow();
    });

    it('should handle EC keys with compressed or different format points', () => {
      // Mock key without uncompressed point marker
      const mockKey = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: { publicKey: 'mock' },
        export: () => {
          // DER without 0x04 marker (compressed or different format)
          const buffer = Buffer.alloc(50);
          buffer.fill(0x02); // Compressed point marker
          return buffer;
        }
      } as any as KeyObject;
      
      // Should skip validation if can't find uncompressed point
      expect(() => validateECPoint(mockKey, 'prime256v1')).not.toThrow();
    });

    it('should handle export errors gracefully', () => {
      const mockKey = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: { publicKey: 'mock' },
        export: () => {
          throw new Error('Export failed');
        }
      } as any as KeyObject;
      
      // Should catch and skip validation
      expect(() => validateECPoint(mockKey, 'prime256v1')).not.toThrow();
    });
  });

  describe('Signature Format Validation', () => {
    it('should accept valid ECDSA signatures', () => {
      // Valid base64url signatures of correct length
      const es256Sig = 'X'.repeat(86); // 64 bytes = 86 base64url chars (rounded up)
      const es384Sig = 'Y'.repeat(128); // 96 bytes = 128 base64url chars
      const es512Sig = 'Z'.repeat(176); // 132 bytes = 176 base64url chars
      
      expect(() => validateSignatureFormat(es256Sig, 'ES256')).not.toThrow();
      expect(() => validateSignatureFormat(es384Sig, 'ES384')).not.toThrow();
      expect(() => validateSignatureFormat(es512Sig, 'ES512')).not.toThrow();
    });

    it('should reject signatures with trailing data', () => {
      const validSig = 'A'.repeat(86);
      const sigWithTrailing = validSig + 'EXTRA';
      
      expect(() => validateSignatureFormat(sigWithTrailing, 'ES256')).toThrow(
        /signature has trailing data/
      );
    });

    it('should reject signatures with invalid characters', () => {
      const invalidSig = 'A'.repeat(85) + '!'; // ! is not valid base64url
      
      expect(() => validateSignatureFormat(invalidSig, 'ES256')).toThrow(
        'Invalid signature format: contains non-base64url characters'
      );
    });

    it('should skip validation for non-ECDSA algorithms', () => {
      const rsaSig = 'A'.repeat(1000); // Very long signature
      
      expect(() => validateSignatureFormat(rsaSig, 'RS256')).not.toThrow();
    });

    it('should skip validation when signature is missing', () => {
      expect(() => validateSignatureFormat('', 'ES256')).not.toThrow();
      expect(() => validateSignatureFormat(null as any, 'ES256')).not.toThrow();
      expect(() => validateSignatureFormat(undefined as any, 'ES256')).not.toThrow();
    });

    it('should skip validation when algorithm is missing', () => {
      const validSig = 'A'.repeat(86);
      expect(() => validateSignatureFormat(validSig, '')).not.toThrow();
      expect(() => validateSignatureFormat(validSig, null as any)).not.toThrow();
      expect(() => validateSignatureFormat(validSig, undefined as any)).not.toThrow();
    });

    it('should skip validation for unknown ECDSA algorithms', () => {
      // Test line 190: algorithm starts with ES but is not in SIGNATURE_LENGTHS
      const validSig = 'A'.repeat(100);
      expect(() => validateSignatureFormat(validSig, 'ES999')).not.toThrow();
      expect(() => validateSignatureFormat(validSig, 'ESXYZ')).not.toThrow();
    });
  });

  describe('ECDSA Signature Component Validation', () => {
    it('should accept valid signature components', () => {
      // Valid 32-byte values for ES256
      const r = Buffer.from('a'.repeat(32));
      const s = Buffer.from('b'.repeat(32));
      
      expect(() => validateECDSASignatureComponents(r, s, 'ES256')).not.toThrow();
    });

    it('should reject zero r or s values', () => {
      const zeroBuffer = Buffer.alloc(32);
      const validBuffer = Buffer.from('a'.repeat(32));
      
      expect(() => validateECDSASignatureComponents(zeroBuffer, validBuffer, 'ES256'))
        .toThrow('Invalid ECDSA signature: r or s is zero');
      
      expect(() => validateECDSASignatureComponents(validBuffer, zeroBuffer, 'ES256'))
        .toThrow('Invalid ECDSA signature: r or s is zero');
    });

    it('should reject incorrect component lengths', () => {
      const shortBuffer = Buffer.from('a'.repeat(31));
      const validBuffer = Buffer.from('b'.repeat(32));
      
      expect(() => validateECDSASignatureComponents(shortBuffer, validBuffer, 'ES256'))
        .toThrow('Invalid ECDSA signature: incorrect component lengths');
    });

    it('should reject r or s values exceeding curve order', () => {
      // For P-256, n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
      // Create a value that exceeds this
      const tooLarge = Buffer.from('ff'.repeat(32), 'hex');
      const validBuffer = Buffer.from('01'.repeat(32), 'hex');
      
      expect(() => validateECDSASignatureComponents(tooLarge, validBuffer, 'ES256'))
        .toThrow('Invalid ECDSA signature: r or s exceeds curve order');
    });

    it('should reject r or s values exceeding curve order for ES256K', () => {
      // Test line 252: ES256K curve validation
      // For secp256k1, n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
      const tooLarge = Buffer.from('ff'.repeat(32), 'hex');
      const validBuffer = Buffer.from('01'.repeat(32), 'hex');
      
      expect(() => validateECDSASignatureComponents(tooLarge, validBuffer, 'ES256K'))
        .toThrow('Invalid ECDSA signature: r or s exceeds curve order');
      
      expect(() => validateECDSASignatureComponents(validBuffer, tooLarge, 'ES256K'))
        .toThrow('Invalid ECDSA signature: r or s exceeds curve order');
    });

    it('should skip validation for unknown algorithms', () => {
      const r = Buffer.from('a'.repeat(32));
      const s = Buffer.from('b'.repeat(32));
      
      // Should not throw for unknown algorithm
      expect(() => validateECDSASignatureComponents(r, s, 'UNKNOWN')).not.toThrow();
      expect(() => validateECDSASignatureComponents(r, s, '')).not.toThrow();
    });

    it('should handle valid component lengths for algorithms without curve params', () => {
      // Test branch coverage for line 252: curveName && EC_CURVE_PARAMS[curveName]
      // Tests the case where we get a curveName from the switch but it's not in EC_CURVE_PARAMS
      
      // HS512 has total 64 bytes, so 32 bytes per component
      const r = Buffer.from('a'.repeat(32));
      const s = Buffer.from('b'.repeat(32));
      
      // HS512 is in SIGNATURE_LENGTHS but not an ECDSA algorithm, so no curve mapping
      expect(() => validateECDSASignatureComponents(r, s, 'HS512')).not.toThrow();
    });
  });

  describe('JWT Integration with Crypto Validation', () => {
    let validECKey: any;
    let validRSAKey: any;
    
    beforeEach(() => {
      validECKey = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      validRSAKey = generateKeyPairSync('rsa', {
        modulusLength: 2048
      });
    });

    it('should create and verify tokens with valid EC keys', async () => {
      const token = await jwt.sign(payload, validECKey.privateKey, { algorithm: 'ES256' });
      expect(token).toBeTruthy();
      
      const decoded = await jwt.verify(token, validECKey.publicKey, { algorithms: ['ES256'] });
      expect(decoded).toMatchObject(payload);
    });

    it('should create and verify tokens with valid RSA keys', async () => {
      const token = await jwt.sign(payload, validRSAKey.privateKey, { algorithm: 'RS256' });
      expect(token).toBeTruthy();
      
      const decoded = await jwt.verify(token, validRSAKey.publicKey, { algorithms: ['RS256'] });
      expect(decoded).toMatchObject(payload);
    });

    it('should reject verification of tokens with trailing signature data', async () => {
      const token = await jwt.sign(payload, validECKey.privateKey, { algorithm: 'ES256' });
      const tokenWithTrailing = token + 'EXTRA';
      
      await expect(jwt.verify(tokenWithTrailing, validECKey.publicKey, { algorithms: ['ES256'] }))
        .rejects.toThrow(/signature has trailing data/);
    });

    it('should reject tokens with invalid signature characters', async () => {
      const token = await jwt.sign(payload, validECKey.privateKey, { algorithm: 'ES256' });
      // Replace last character with invalid base64url character
      const invalidToken = token.slice(0, -1) + '!';
      
      await expect(jwt.verify(invalidToken, validECKey.publicKey, { algorithms: ['ES256'] }))
        .rejects.toThrow(/contains non-base64url characters/);
    });
  });

  describe('EdDSA Key Validation', () => {
    it('should accept valid EdDSA keys', () => {
      try {
        const { privateKey: ed25519Key, publicKey: ed25519PubKey } = generateKeyPairSync('ed25519');
        const { privateKey: ed448Key, publicKey: ed448PubKey } = generateKeyPairSync('ed448');
        
        expect(() => validateEdDSAKey(ed25519Key)).not.toThrow();
        expect(() => validateEdDSAKey(ed25519PubKey)).not.toThrow();
        expect(() => validateEdDSAKey(ed448Key)).not.toThrow();
        expect(() => validateEdDSAKey(ed448PubKey)).not.toThrow();
      } catch (err: any) {
        // Skip if EdDSA not supported
        if (err.code === 'ERR_OSSL_EC_CURVE_INVALID') {
          return;
        }
        throw err;
      }
    });

    it('should skip validation for non-EdDSA keys', () => {
      const { publicKey: rsaKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048
      });
      const { publicKey: ecKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      // Should return early without throwing
      expect(() => validateEdDSAKey(rsaKey)).not.toThrow();
      expect(() => validateEdDSAKey(ecKey)).not.toThrow();
    });
  });

  describe('Main Validation Function', () => {
    it('should skip validation when key is missing', () => {
      expect(() => validateCryptographicParameters(undefined, 'ES256', 'signature')).not.toThrow();
      expect(() => validateCryptographicParameters(null as any, 'ES256', 'signature')).not.toThrow();
    });

    it('should skip validation when algorithm is missing', () => {
      const { publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      expect(() => validateCryptographicParameters(publicKey, undefined, 'signature')).not.toThrow();
      expect(() => validateCryptographicParameters(publicKey, null as any, 'signature')).not.toThrow();
      expect(() => validateCryptographicParameters(publicKey, '', 'signature')).not.toThrow();
    });

    it('should validate all components when provided', () => {
      const { publicKey: rsaKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicExponent: 65537
      });
      const { publicKey: ecKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      // Should not throw for valid keys
      expect(() => validateCryptographicParameters(rsaKey, 'RS256')).not.toThrow();
      expect(() => validateCryptographicParameters(ecKey, 'ES256')).not.toThrow();
      
      // With signature
      const validSig = 'A'.repeat(86);
      expect(() => validateCryptographicParameters(ecKey, 'ES256', validSig)).not.toThrow();
    });

    it('should handle EC keys with unknown algorithm mapping', () => {
      const { publicKey: ecKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      // Should not throw for EC key with unknown algorithm (no curve mapping)
      expect(() => validateCryptographicParameters(ecKey, 'UNKNOWN_EC')).not.toThrow();
    });
  });

  describe('Edge Cases and Attack Scenarios', () => {
    it('should handle keys without asymmetricKeyDetails gracefully', () => {
      const mockKey = {
        asymmetricKeyType: 'rsa'
        // No asymmetricKeyDetails
      } as any as KeyObject;
      
      expect(() => validateRSAKeyParameters(mockKey)).not.toThrow();
    });

    it('should handle malformed EC public key data', () => {
      const mockKey = {
        asymmetricKeyType: 'ec',
        export: () => Buffer.from('invalid-data')
      } as any as KeyObject;
      
      expect(() => validateECPoint(mockKey, 'prime256v1')).not.toThrow();
    });

    it('should validate signature format for ES256K', () => {
      const validSig = 'A'.repeat(86);
      expect(() => validateSignatureFormat(validSig, 'ES256K')).not.toThrow();
      
      const invalidSig = validSig + 'EXTRA';
      expect(() => validateSignatureFormat(invalidSig, 'ES256K'))
        .toThrow(/signature has trailing data/);
    });

    it('should handle EdDSA keys', () => {
      // EdDSA is supported in Node.js 12+
      try {
        const { privateKey, publicKey } = generateKeyPairSync('ed25519');
        
        expect(() => validateCryptographicParameters(privateKey, 'EdDSA')).not.toThrow();
        expect(() => validateCryptographicParameters(publicKey, 'EdDSA')).not.toThrow();
      } catch (err: any) {
        // Skip test if EdDSA is not supported
        if (err.code === 'ERR_OSSL_EC_CURVE_INVALID') {
          return;
        }
        throw err;
      }
    });
  });

  describe('Performance and Compatibility', () => {
    it('should not significantly impact JWT verification performance', async () => {
      const iterations = 100;
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      const token = await jwt.sign(payload, privateKey, { algorithm: 'ES256' });
      
      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        await jwt.verify(token, publicKey, { algorithms: ['ES256'] });
      }
      const elapsed = Date.now() - start;
      
      // Should complete 100 verifications in reasonable time (< 1 second)
      expect(elapsed).toBeLessThan(1000);
    });

    it('should maintain backward compatibility with existing tokens', async () => {
      // Create a token without the new validations
      // This simulates tokens created before the security enhancements
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      // Directly use the algorithm implementation to bypass validations during signing
      const { ES256 } = await import('../../src/lib/algorithms/ecdsa.js');
      const message = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url') + '.' +
                     Buffer.from(JSON.stringify(payload)).toString('base64url');
      
      // Create signature without validations
      const signature = ES256.sign(message, privateKey);
      const token = message + '.' + signature;
      
      // Should still verify with validations enabled
      const decoded = await jwt.verify(token, publicKey, { algorithms: ['ES256'] });
      expect(decoded).toMatchObject(payload);
    });
  });
});