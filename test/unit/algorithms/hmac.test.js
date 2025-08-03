const { describe, it, expect } = require('@jest/globals');
const { HS256, HS384, HS512 } = require('../../../src/lib/algorithms/hmac');
const { generateRSAKeyPair, generateECKeyPair } = require('../../helpers/key-generator');
const { createSecretKey } = require('crypto');

describe('HMAC Algorithms', () => {
  describe('normalizeSecret', () => {
    it('should handle Buffer to KeyObject conversion', () => {
      const buffer = Buffer.from('secret');
      const message = 'test message';

      // Test that Buffer is converted to KeyObject internally
      const signature = HS256.sign(message, buffer);
      expect(typeof signature).toBe('string');
      expect(HS256.verify(message, signature, buffer)).toBe(true);
    });

    it('should handle string to Buffer to KeyObject conversion', () => {
      const stringKey = 'my-secret-key';
      const message = 'test message';

      // Test that string is converted to Buffer then to KeyObject
      const signature = HS384.sign(message, stringKey);
      expect(typeof signature).toBe('string');
      expect(HS384.verify(message, signature, stringKey)).toBe(true);
    });

    it('should handle KeyObject instances directly', () => {
      const secretKey = createSecretKey(Buffer.from('secret'));
      const message = 'test message';

      // Test signing with KeyObject
      const signature = HS512.sign(message, secretKey);
      expect(typeof signature).toBe('string');

      // Test verifying with KeyObject
      expect(HS512.verify(message, signature, secretKey)).toBe(true);
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
        expect(() => HS256.sign('message', invalidKey)).toThrow('Invalid key type');
        expect(() => HS256.verify('message', 'signature', invalidKey)).toThrow('Invalid key type');
      });
    });

    it('should throw error for non-secret KeyObject types', () => {
      const { privateKeyObject, publicKeyObject } = generateRSAKeyPair();
      const { privateKeyObject: ecPrivate, publicKeyObject: ecPublic } = generateECKeyPair('P-256');

      // RSA keys
      expect(() => HS256.sign('message', privateKeyObject)).toThrow('Invalid key type for HMAC algorithm. HMAC requires a symmetric secret key, but an asymmetric key was provided.');
      expect(() => HS256.verify('message', 'signature', publicKeyObject)).toThrow('Invalid key type for HMAC algorithm. HMAC requires a symmetric secret key, but an asymmetric key was provided.');

      // EC keys
      expect(() => HS384.sign('message', ecPrivate)).toThrow('Invalid key type for HMAC algorithm. HMAC requires a symmetric secret key, but an asymmetric key was provided.');
      expect(() => HS384.verify('message', 'signature', ecPublic)).toThrow('Invalid key type for HMAC algorithm. HMAC requires a symmetric secret key, but an asymmetric key was provided.');
    });
  });

  describe('Sign and verify operations', () => {
    let secretBuffer;
    let secretString;
    let secretKeyObject;

    beforeEach(() => {
      // Create a buffer without null bytes for testing
      // Using a fixed pattern to avoid random null bytes
      secretBuffer = Buffer.from('a'.repeat(32));
      secretString = 'test-secret-key';
      secretKeyObject = createSecretKey(secretBuffer);
    });

    it('should sign and verify with HS256', () => {
      const message = 'test message';
      const signature = HS256.sign(message, secretBuffer);

      expect(typeof signature).toBe('string');
      expect(HS256.verify(message, signature, secretBuffer)).toBe(true);
    });

    it('should sign and verify with HS384', () => {
      const message = 'test message';
      const signature = HS384.sign(message, secretString);

      expect(typeof signature).toBe('string');
      expect(HS384.verify(message, signature, secretString)).toBe(true);
    });

    it('should sign and verify with HS512', () => {
      const message = 'test message';
      const signature = HS512.sign(message, secretKeyObject);

      expect(typeof signature).toBe('string');
      expect(HS512.verify(message, signature, secretKeyObject)).toBe(true);
    });

    it('should handle Buffer messages', () => {
      const messageBuffer = Buffer.from('test message');

      const signature = HS256.sign(messageBuffer, secretBuffer);
      expect(HS256.verify(messageBuffer, signature, secretBuffer)).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';

      const signature = HS384.sign(emptyMessage, secretString);
      expect(HS384.verify(emptyMessage, signature, secretString)).toBe(true);
    });

    it('should handle very long messages', () => {
      const longMessage = 'a'.repeat(10000);

      const signature = HS512.sign(longMessage, secretKeyObject);
      expect(HS512.verify(longMessage, signature, secretKeyObject)).toBe(true);
    });

    it('should return false for signature verification with wrong key', () => {
      const key1 = 'secret1';
      const key2 = 'secret2';

      const message = 'test message';
      const signature = HS256.sign(message, key1);

      // Verify with different key
      expect(HS256.verify(message, signature, key2)).toBe(false);
    });

    it('should return false for signature verification with wrong message', () => {
      const message = 'test message';
      const signature = HS384.sign(message, secretString);

      expect(HS384.verify('wrong message', signature, secretString)).toBe(false);
    });

    it('should return false for corrupted signatures', () => {
      const message = 'test message';
      const signature = HS512.sign(message, secretKeyObject);

      // Corrupt the signature
      const corruptedSig = `${signature.slice(0, -4)  }AAAA`;
      expect(HS512.verify(message, corruptedSig, secretKeyObject)).toBe(false);
    });

    it('should return false for signatures with different lengths', () => {
      const message = 'test message';
      const validSignature = HS256.sign(message, secretBuffer);

      // Test with shorter signature
      expect(HS256.verify(message, 'short', secretBuffer)).toBe(false);

      // Test with longer signature
      const longerSig = `${validSignature  }extra`;
      expect(HS256.verify(message, longerSig, secretBuffer)).toBe(false);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🔐 Unicode test message 你好世界';

      const signature = HS384.sign(unicodeMessage, secretString);
      expect(HS384.verify(unicodeMessage, signature, secretString)).toBe(true);
    });

    it('should produce consistent signatures for same input', () => {
      const message = 'same message';

      const sig1 = HS256.sign(message, secretBuffer);
      const sig2 = HS256.sign(message, secretBuffer);

      // HMAC is deterministic, so signatures should be the same
      expect(sig1).toEqual(sig2);
    });

    it('should handle different key formats producing same result', () => {
      const message = 'test message';
      const keyString = 'secret';
      const keyBuffer = Buffer.from(keyString);
      const keyObject = createSecretKey(keyBuffer);

      // All three should produce the same signature
      const sig1 = HS512.sign(message, keyString);
      const sig2 = HS512.sign(message, keyBuffer);
      const sig3 = HS512.sign(message, keyObject);

      expect(sig1).toEqual(sig2);
      expect(sig2).toEqual(sig3);
    });

    it('should use timing-safe comparison for signature verification', () => {
      const message = 'test message';
      const signature = HS256.sign(message, secretBuffer);

      // The verify method uses timingSafeEqual internally
      // This test ensures the code path is covered
      expect(HS256.verify(message, signature, secretBuffer)).toBe(true);

      // Test with different signature to ensure false path
      expect(HS256.verify(message, 'different', secretBuffer)).toBe(false);
    });

    it('should reject empty secret', () => {
      const emptySecret = '';
      const message = 'test message';

      // Empty secret should be rejected
      expect(() => HS384.sign(message, emptySecret)).toThrow('Invalid key for HMAC algorithm. Key must not be empty.');
      expect(() => HS384.verify(message, 'signature', emptySecret)).toThrow('Invalid key for HMAC algorithm. Key must not be empty.');
    });
  });
});