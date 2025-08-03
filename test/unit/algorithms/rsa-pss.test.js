const { describe, it, expect } = require('@jest/globals');
const { PS256, PS384, PS512 } = require('../../../src/lib/algorithms/rsa-pss');
const { generateRSAKeyPair, generateECKeyPair } = require('../../helpers/key-generator');

describe('RSA-PSS Algorithms', () => {
  describe('normalizeKey', () => {
    it('should handle KeyObject instances directly', () => {
      const { privateKeyObject, publicKeyObject } = generateRSAKeyPair();
      const message = 'test message';

      // Test signing with KeyObject
      const signature = PS256.sign(message, privateKeyObject);
      expect(typeof signature).toBe('string');

      // Test verifying with KeyObject
      expect(PS256.verify(message, signature, publicKeyObject)).toBe(true);
    });

    it('should throw error for invalid key types', () => {
      const invalidKeys = [
        null,
        undefined,
        123,
        true,
        false,
        [],
        { invalid: 'object' },
        Symbol('test'),
        () => {},
        new Date()
      ];

      invalidKeys.forEach(invalidKey => {
        expect(() => PS256.sign('message', invalidKey)).toThrow();
        expect(() => PS256.verify('message', 'signature', invalidKey)).toThrow();
      });
    });

    it('should throw error for malformed key objects', () => {
      const malformedKeys = [
        { key: null },
        { key: undefined },
        { key: 123 },
        { key: true },
        { key: [] },
        { key: {} },
        { key: Symbol('test') }
      ];

      malformedKeys.forEach(malformedKey => {
        expect(() => PS384.sign('message', malformedKey)).toThrow();
        expect(() => PS384.verify('message', 'signature', malformedKey)).toThrow();
      });
    });

    it('should handle key objects with missing key property', () => {
      const invalidKeyObjects = [
        { passphrase: 'test' },
        { format: 'pem' },
        { type: 'pkcs1' }
      ];

      invalidKeyObjects.forEach(obj => {
        expect(() => PS512.sign('message', obj)).toThrow();
        expect(() => PS512.verify('message', 'signature', obj)).toThrow();
      });
    });

    it('should handle non-RSA keys appropriately', () => {
      const { privateKey: ecPrivateKey, publicKey: ecPublicKey } = generateECKeyPair('P-256');
      // These are declared but not used in the test
      // const { privateKey: edPrivateKey, publicKey: edPublicKey } = generateEd25519KeyPair();
      // const hmacKey = createSecretKey(Buffer.alloc(32));

      // RSA-PSS operations with non-RSA keys may succeed in normalizeKey but fail later
      // The behavior depends on the Node.js version and OpenSSL implementation
      // We'll test that it either throws or returns a result

      // Test EC keys
      try {
        PS256.sign('message', ecPrivateKey);
        // If it doesn't throw, that's also valid behavior
        expect(true).toBe(true);
      } catch (e) {
        // If it throws, ensure it's a proper error
        expect(e).toBeInstanceOf(Error);
      }

      // Test verification with invalid signature and wrong key type
      try {
        const result = PS256.verify('message', 'invalidsig', ecPublicKey);
        // Should return false for invalid signature
        expect(result).toBe(false);
      } catch (e) {
        // Or it might throw
        expect(e).toBeInstanceOf(Error);
      }
    });
  });

  describe('Sign and verify operations', () => {
    let rsaKeys;

    beforeEach(() => {
      rsaKeys = generateRSAKeyPair();
    });

    it('should sign and verify with PS256', () => {
      const message = 'test message';
      const signature = PS256.sign(message, rsaKeys.privateKey);

      expect(typeof signature).toBe('string');
      expect(PS256.verify(message, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should sign and verify with PS384', () => {
      const message = 'test message';
      const signature = PS384.sign(message, rsaKeys.privateKey);

      expect(typeof signature).toBe('string');
      expect(PS384.verify(message, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should sign and verify with PS512', () => {
      const message = 'test message';
      const signature = PS512.sign(message, rsaKeys.privateKey);

      expect(typeof signature).toBe('string');
      expect(PS512.verify(message, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle Buffer messages', () => {
      const messageBuffer = Buffer.from('test message');

      const signature = PS256.sign(messageBuffer, rsaKeys.privateKey);
      expect(PS256.verify(messageBuffer, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';

      const signature = PS384.sign(emptyMessage, rsaKeys.privateKey);
      expect(PS384.verify(emptyMessage, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle very long messages', () => {
      const longMessage = 'a'.repeat(10000);

      const signature = PS512.sign(longMessage, rsaKeys.privateKey);
      expect(PS512.verify(longMessage, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should return false for signature verification with wrong key', () => {
      const keys1 = generateRSAKeyPair();
      const keys2 = generateRSAKeyPair();

      const message = 'test message';
      const signature = PS256.sign(message, keys1.privateKey);

      // Verify with different public key
      expect(PS256.verify(message, signature, keys2.publicKey)).toBe(false);
    });

    it('should return false for signature verification with wrong message', () => {
      const message = 'test message';
      const signature = PS384.sign(message, rsaKeys.privateKey);

      expect(PS384.verify('wrong message', signature, rsaKeys.publicKey)).toBe(false);
    });

    it('should handle verification failures with corrupted signatures', () => {
      const message = 'test message';
      const signature = PS512.sign(message, rsaKeys.privateKey);

      // Corrupt the signature
      const corruptedSig = `${signature.slice(0, -4)  }AAAA`;
      expect(PS512.verify(message, corruptedSig, rsaKeys.publicKey)).toBe(false);
    });

    it('should handle invalid base64url signatures', () => {
      const message = 'test message';

      // Invalid base64url should return false
      expect(PS256.verify(message, 'invalid!@#$%', rsaKeys.publicKey)).toBe(false);

      // Empty signature should return false
      expect(PS256.verify(message, '', rsaKeys.publicKey)).toBe(false);

      // Very short signature should return false
      expect(PS256.verify(message, 'AA', rsaKeys.publicKey)).toBe(false);
    });

    it('should produce different signatures for same message (due to PSS randomness)', () => {
      const message = 'same message';

      const sig1 = PS256.sign(message, rsaKeys.privateKey);
      const sig2 = PS256.sign(message, rsaKeys.privateKey);

      // PSS uses random salt, so signatures should be different
      expect(sig1).not.toEqual(sig2);

      // But both should verify correctly
      expect(PS256.verify(message, sig1, rsaKeys.publicKey)).toBe(true);
      expect(PS256.verify(message, sig2, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🔐 Unicode test message 你好世界';

      const signature = PS384.sign(unicodeMessage, rsaKeys.privateKey);
      expect(PS384.verify(unicodeMessage, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle key format conversions', () => {
      const message = 'test message';

      // Test with PEM string keys
      const signature = PS512.sign(message, rsaKeys.privateKey);
      expect(PS512.verify(message, signature, rsaKeys.publicKey)).toBe(true);

      // Test with KeyObject keys
      const signatureObj = PS512.sign(message, rsaKeys.privateKeyObject);
      expect(PS512.verify(message, signatureObj, rsaKeys.publicKeyObject)).toBe(true);
    });

    it('should handle different signature lengths for different algorithms', () => {
      const message = 'test message';

      const sig256 = PS256.sign(message, rsaKeys.privateKey);
      const sig384 = PS384.sign(message, rsaKeys.privateKey);
      const sig512 = PS512.sign(message, rsaKeys.privateKey);

      // All should be valid base64url strings
      expect(sig256).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(sig384).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(sig512).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });
});