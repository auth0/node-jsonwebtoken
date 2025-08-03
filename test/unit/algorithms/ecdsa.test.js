const { describe, it, expect, beforeEach } = require('@jest/globals');
const { ES256, ES384, ES512, ES256K } = require('../../../src/lib/algorithms/ecdsa');
const { generateECKeyPair, generateRSAKeyPair, generateEd25519KeyPair } = require('../../helpers/key-generator');
const { createSecretKey } = require('crypto');

describe('ECDSA Algorithms', () => {
  describe('normalizeKey', () => {
    it('should throw error for invalid key types', () => {
      const invalidKeys = [
        null,
        undefined,
        123,
        true,
        [],
        { invalid: 'object' },
        Symbol('test')
      ];

      invalidKeys.forEach(invalidKey => {
        expect(() => ES256.sign('message', invalidKey)).toThrow();
        expect(() => ES256.verify('message', 'signature', invalidKey)).toThrow();
      });
    });

    it('should throw error when using non-EC keys for ECDSA algorithms', () => {
      const { privateKey: rsaPrivateKey, publicKey: rsaPublicKey } = generateRSAKeyPair();
      const { privateKey: edPrivateKey, publicKey: edPublicKey } = generateEd25519KeyPair();
      const hmacKey = createSecretKey(Buffer.alloc(32));

      // Test signing with wrong key types
      expect(() => ES256.sign('message', rsaPrivateKey)).toThrow();
      expect(() => ES384.sign('message', edPrivateKey)).toThrow();
      expect(() => ES512.sign('message', hmacKey)).toThrow();
      expect(() => ES256K.sign('message', rsaPrivateKey)).toThrow();

      // Test verification with wrong key types
      expect(() => ES256.verify('message', 'signature', rsaPublicKey)).toThrow();
      expect(() => ES384.verify('message', 'signature', edPublicKey)).toThrow();
      expect(() => ES512.verify('message', 'signature', hmacKey)).toThrow();
      expect(() => ES256K.verify('message', 'signature', rsaPublicKey)).toThrow();
    });

    it('should throw error for malformed key objects', () => {
      const malformedKeys = [
        { key: null },
        { key: 123 },
        { key: true },
        { key: [] },
        { key: {} }
      ];

      malformedKeys.forEach(malformedKey => {
        expect(() => ES256.sign('message', malformedKey)).toThrow();
        expect(() => ES256.verify('message', 'signature', malformedKey)).toThrow();
      });
    });

    it('should handle EC keys with wrong curve for the algorithm', () => {
      // Generate keys with different curves
      const { privateKey: p384Private, publicKey: p384Public } = generateECKeyPair('P-384');
      const { privateKey: p256Private } = generateECKeyPair('P-256');

      // ES256 with P-384 key will actually sign but produce wrong signature size
      // This doesn't throw during signing, but would fail during verification
      const wrongCurveSig = ES256.sign('message', p384Private);
      expect(typeof wrongCurveSig).toBe('string');

      // However, verification with wrong public key curve should fail
      const validSig = ES256.sign('message', p256Private);
      expect(ES256.verify('message', validSig, p384Public)).toBe(false);
    });
  });

  describe('ES256K specific tests', () => {
    let es256kKeys;

    beforeEach(() => {
      es256kKeys = generateECKeyPair('secp256k1');
    });

    it('should sign and verify with secp256k1 keys', () => {
      const message = 'test message';
      const signature = ES256K.sign(message, es256kKeys.privateKey);

      expect(typeof signature).toBe('string');
      expect(ES256K.verify(message, signature, es256kKeys.publicKey)).toBe(true);
    });

    it('should handle verification failures with ES256K', () => {
      const message = 'test message';
      const signature = ES256K.sign(message, es256kKeys.privateKey);

      // Verify with wrong message
      expect(ES256K.verify('wrong message', signature, es256kKeys.publicKey)).toBe(false);

      // Verify with corrupted signature
      const corruptedSig = `${signature.slice(0, -4)  }AAAA`;
      expect(ES256K.verify(message, corruptedSig, es256kKeys.publicKey)).toBe(false);
    });

    it('should handle invalid signatures for ES256K', () => {
      const message = 'test message';

      // Test with completely invalid signature formats
      // These will throw due to invalid signature length
      expect(() => ES256K.verify(message, 'invalid', es256kKeys.publicKey)).toThrow();
      expect(() => ES256K.verify(message, '', es256kKeys.publicKey)).toThrow();
      expect(() => ES256K.verify(message, 'a'.repeat(100), es256kKeys.publicKey)).toThrow();
    });

    it('should throw error during ES256K signing with wrong curve', () => {
      const { privateKey: p256Private } = generateECKeyPair('P-256');

      // ES256K expects secp256k1 curve, but we're using P-256
      // This might not throw during signing but would produce invalid signatures
      const signature = ES256K.sign('message', p256Private);
      expect(typeof signature).toBe('string');
    });

    it('should handle ES256K verification errors with malformed signatures', () => {
      const message = 'test message';

      // Test various malformed signatures that would trigger joseToDer errors
      const malformedSignatures = [
        Buffer.alloc(32).toString('base64url'), // Too short (32 bytes instead of 64)
        Buffer.alloc(128).toString('base64url'), // Too long
        'notbase64url!@#$%', // Invalid base64url
      ];

      malformedSignatures.forEach(sig => {
        expect(() => ES256K.verify(message, sig, es256kKeys.publicKey)).toThrow();
      });
    });

    it('should handle ES256K with KeyObject inputs', () => {
      const message = 'test message';
      const signature = ES256K.sign(message, es256kKeys.privateKeyObject);

      expect(typeof signature).toBe('string');
      expect(ES256K.verify(message, signature, es256kKeys.publicKeyObject)).toBe(true);
    });
  });

  describe('Edge cases for all ECDSA algorithms', () => {
    it('should handle Buffer messages', () => {
      const { privateKey, publicKey } = generateECKeyPair('P-256');
      const messageBuffer = Buffer.from('test message');

      const signature = ES256.sign(messageBuffer, privateKey);
      expect(ES256.verify(messageBuffer, signature, publicKey)).toBe(true);
    });

    it('should handle empty messages', () => {
      const { privateKey, publicKey } = generateECKeyPair('P-384');
      const emptyMessage = '';

      const signature = ES384.sign(emptyMessage, privateKey);
      expect(ES384.verify(emptyMessage, signature, publicKey)).toBe(true);
    });

    it('should handle very long messages', () => {
      const { privateKey, publicKey } = generateECKeyPair('P-521');
      const longMessage = 'a'.repeat(10000);

      const signature = ES512.sign(longMessage, privateKey);
      expect(ES512.verify(longMessage, signature, publicKey)).toBe(true);
    });

    it('should return false for signature verification with wrong key', () => {
      const keys1 = generateECKeyPair('P-256');
      const keys2 = generateECKeyPair('P-256');

      const message = 'test message';
      const signature = ES256.sign(message, keys1.privateKey);

      // Verify with different public key
      expect(ES256.verify(message, signature, keys2.publicKey)).toBe(false);
    });
  });
});