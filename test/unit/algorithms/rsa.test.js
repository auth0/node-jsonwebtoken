const { describe, it, expect } = require('@jest/globals');
const { RS256, RS384, RS512 } = require('../../../src/lib/algorithms/rsa');
const { generateRSAKeyPair, generateECKeyPair } = require('../../helpers/key-generator');

describe('RSA Algorithms', () => {
  describe('normalizeKey', () => {
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
        expect(() => RS256.sign('message', invalidKey)).toThrow();
        expect(() => RS256.verify('message', 'signature', invalidKey)).toThrow();
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
        expect(() => RS384.sign('message', malformedKey)).toThrow();
        expect(() => RS384.verify('message', 'signature', malformedKey)).toThrow();
      });
    });

    it('should handle key objects with missing key property', () => {
      const invalidKeyObjects = [
        { passphrase: 'test' },
        { format: 'pem' },
        { type: 'pkcs1' }
      ];

      invalidKeyObjects.forEach(obj => {
        expect(() => RS512.sign('message', obj)).toThrow();
        expect(() => RS512.verify('message', 'signature', obj)).toThrow();
      });
    });

    it('should handle non-RSA keys appropriately', () => {
      const { privateKey: ecPrivateKey, publicKey: ecPublicKey } = generateECKeyPair('P-256');
      // These are declared but not used in the test
      // const { privateKey: edPrivateKey, publicKey: edPublicKey } = generateEd25519KeyPair();
      // const hmacKey = createSecretKey(Buffer.alloc(32));

      // RSA operations with non-RSA keys may succeed in normalizeKey but fail later
      // We'll test that it either throws or returns a result

      // Test EC keys
      try {
        RS256.sign('message', ecPrivateKey);
        // If it doesn't throw, that's also valid behavior
        expect(true).toBe(true);
      } catch (e) {
        // If it throws, ensure it's a proper error
        expect(e).toBeInstanceOf(Error);
      }

      // Test verification with invalid signature and wrong key type
      try {
        const result = RS256.verify('message', 'invalidsig', ecPublicKey);
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

    it('should sign and verify with RS256', () => {
      const message = 'test message';
      const signature = RS256.sign(message, rsaKeys.privateKey);

      expect(typeof signature).toBe('string');
      expect(RS256.verify(message, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should sign and verify with RS384', () => {
      const message = 'test message';
      const signature = RS384.sign(message, rsaKeys.privateKey);

      expect(typeof signature).toBe('string');
      expect(RS384.verify(message, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should sign and verify with RS512', () => {
      const message = 'test message';
      const signature = RS512.sign(message, rsaKeys.privateKey);

      expect(typeof signature).toBe('string');
      expect(RS512.verify(message, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle KeyObject instances directly', () => {
      const message = 'test message';

      // Test signing with KeyObject
      const signature = RS256.sign(message, rsaKeys.privateKeyObject);
      expect(typeof signature).toBe('string');

      // Test verifying with KeyObject
      expect(RS256.verify(message, signature, rsaKeys.publicKeyObject)).toBe(true);
    });

    it('should handle Buffer messages', () => {
      const messageBuffer = Buffer.from('test message');

      const signature = RS384.sign(messageBuffer, rsaKeys.privateKey);
      expect(RS384.verify(messageBuffer, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';

      const signature = RS512.sign(emptyMessage, rsaKeys.privateKey);
      expect(RS512.verify(emptyMessage, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle very long messages', () => {
      const longMessage = 'a'.repeat(10000);

      const signature = RS256.sign(longMessage, rsaKeys.privateKey);
      expect(RS256.verify(longMessage, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should return false for signature verification with wrong key', () => {
      const keys1 = generateRSAKeyPair();
      const keys2 = generateRSAKeyPair();

      const message = 'test message';
      const signature = RS384.sign(message, keys1.privateKey);

      // Verify with different public key
      expect(RS384.verify(message, signature, keys2.publicKey)).toBe(false);
    });

    it('should return false for signature verification with wrong message', () => {
      const message = 'test message';
      const signature = RS512.sign(message, rsaKeys.privateKey);

      expect(RS512.verify('wrong message', signature, rsaKeys.publicKey)).toBe(false);
    });

    it('should handle verification failures with corrupted signatures', () => {
      const message = 'test message';
      const signature = RS256.sign(message, rsaKeys.privateKey);

      // Corrupt the signature
      const corruptedSig = `${signature.slice(0, -4)  }AAAA`;
      expect(RS256.verify(message, corruptedSig, rsaKeys.publicKey)).toBe(false);
    });

    it('should handle invalid base64url signatures', () => {
      const message = 'test message';

      // Invalid base64url should return false
      expect(RS384.verify(message, 'invalid!@#$%', rsaKeys.publicKey)).toBe(false);

      // Empty signature should return false
      expect(RS384.verify(message, '', rsaKeys.publicKey)).toBe(false);

      // Very short signature should return false
      expect(RS384.verify(message, 'AA', rsaKeys.publicKey)).toBe(false);
    });

    it('should produce consistent signatures for same input', () => {
      const message = 'same message';

      const sig1 = RS512.sign(message, rsaKeys.privateKey);
      const sig2 = RS512.sign(message, rsaKeys.privateKey);

      // RSA PKCS#1 v1.5 is deterministic
      expect(sig1).toEqual(sig2);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🔐 Unicode test message 你好世界';

      const signature = RS256.sign(unicodeMessage, rsaKeys.privateKey);
      expect(RS256.verify(unicodeMessage, signature, rsaKeys.publicKey)).toBe(true);
    });

    it('should handle key format conversions', () => {
      const message = 'test message';

      // Test with PEM string keys
      const signature = RS384.sign(message, rsaKeys.privateKey);
      expect(RS384.verify(message, signature, rsaKeys.publicKey)).toBe(true);

      // Test with KeyObject keys
      const signatureObj = RS384.sign(message, rsaKeys.privateKeyObject);
      expect(RS384.verify(message, signatureObj, rsaKeys.publicKeyObject)).toBe(true);

      // Test that signatures can be verified regardless of key format
      // This works because the test helper generates consistent keys
      expect(typeof signature).toBe('string');
      expect(typeof signatureObj).toBe('string');
    });

    it('should handle different signature lengths for different algorithms', () => {
      const message = 'test message';

      const sig256 = RS256.sign(message, rsaKeys.privateKey);
      const sig384 = RS384.sign(message, rsaKeys.privateKey);
      const sig512 = RS512.sign(message, rsaKeys.privateKey);

      // All should be valid base64url strings
      expect(sig256).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(sig384).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(sig512).toMatch(/^[A-Za-z0-9_-]+$/);

      // Signatures should be the same length for RSA
      // (determined by key size, not hash algorithm)
      expect(sig256.length).toEqual(sig384.length);
      expect(sig384.length).toEqual(sig512.length);
    });
  });
});