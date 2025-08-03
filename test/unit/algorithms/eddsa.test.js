const { describe, it, expect, beforeEach } = require('@jest/globals');
const { EdDSA } = require('../../../src/lib/algorithms/eddsa');
const { generateEd25519KeyPair, generateRSAKeyPair, generateECKeyPair } = require('../../helpers/key-generator');
const { generateKeyPairSync, createSecretKey } = require('crypto');

describe('EdDSA Algorithm', () => {
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
        expect(() => EdDSA.sign('message', invalidKey)).toThrow();
        expect(() => EdDSA.verify('message', 'signature', invalidKey)).toThrow();
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
        expect(() => EdDSA.sign('message', malformedKey)).toThrow();
        expect(() => EdDSA.verify('message', 'signature', malformedKey)).toThrow();
      });
    });

    it('should handle key objects with missing key property', () => {
      const invalidKeyObjects = [
        { passphrase: 'test' },
        { format: 'pem' },
        { type: 'pkcs1' }
      ];

      invalidKeyObjects.forEach(obj => {
        expect(() => EdDSA.sign('message', obj)).toThrow();
        expect(() => EdDSA.verify('message', 'signature', obj)).toThrow();
      });
    });
  });

  describe('Key type validation', () => {
    it('should throw error when using RSA keys', () => {
      const { privateKey: rsaPrivateKey, publicKey: rsaPublicKey } = generateRSAKeyPair();

      expect(() => EdDSA.sign('message', rsaPrivateKey))
        .toThrow('Invalid key for EdDSA algorithm');
      expect(() => EdDSA.verify('message', 'signature', rsaPublicKey))
        .toThrow('Invalid key for EdDSA algorithm');
    });

    it('should throw error when using EC keys', () => {
      const { privateKey: ecPrivateKey, publicKey: ecPublicKey } = generateECKeyPair('P-256');

      expect(() => EdDSA.sign('message', ecPrivateKey))
        .toThrow('Invalid key for EdDSA algorithm');
      expect(() => EdDSA.verify('message', 'signature', ecPublicKey))
        .toThrow('Invalid key for EdDSA algorithm');
    });

    it('should throw error when using HMAC secret keys', () => {
      const hmacKey = createSecretKey(Buffer.alloc(32));

      expect(() => EdDSA.sign('message', hmacKey))
        .toThrow('Invalid key for EdDSA algorithm');
      expect(() => EdDSA.verify('message', 'signature', hmacKey))
        .toThrow('Invalid key for EdDSA algorithm');
    });

    it('should work with Ed25519 keys', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const message = 'test message';

      const signature = EdDSA.sign(message, privateKey);
      expect(typeof signature).toBe('string');
      expect(EdDSA.verify(message, signature, publicKey)).toBe(true);
    });

    it('should work with Ed448 keys', () => {
      // Generate Ed448 key pair
      const { publicKey, privateKey } = generateKeyPairSync('ed448', {
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });

      const message = 'test message';
      const signature = EdDSA.sign(message, privateKey);
      expect(typeof signature).toBe('string');
      expect(EdDSA.verify(message, signature, publicKey)).toBe(true);
    });

    it('should throw error when using X25519 keys for signing', () => {
      // X25519 is for key agreement, not signing
      try {
        const { privateKey } = generateKeyPairSync('x25519', {
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
          }
        });

        // X25519 keys should not work for signing
        expect(() => EdDSA.sign('message', privateKey)).toThrow();
      } catch (e) {
        // If key generation itself fails (older Node versions), that's expected
        expect(e.message).toMatch(/x25519|not supported/i);
      }
    });

    it('should throw error when using X448 keys for signing', () => {
      // X448 is for key agreement, not signing
      try {
        const { privateKey } = generateKeyPairSync('x448', {
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
          }
        });

        // X448 keys should not work for signing
        expect(() => EdDSA.sign('message', privateKey)).toThrow();
      } catch (e) {
        // If key generation itself fails (older Node versions), that's expected
        expect(e.message).toMatch(/x448|not supported/i);
      }
    });
  });

  describe('Sign and verify operations', () => {
    let ed25519Keys;
    let ed448Keys;

    beforeEach(() => {
      ed25519Keys = generateEd25519KeyPair();

      // Generate Ed448 keys
      const { publicKey, privateKey } = generateKeyPairSync('ed448', {
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
      ed448Keys = { publicKey, privateKey };
    });

    it('should handle Buffer messages', () => {
      const messageBuffer = Buffer.from('test message');

      const signature = EdDSA.sign(messageBuffer, ed25519Keys.privateKey);
      expect(EdDSA.verify(messageBuffer, signature, ed25519Keys.publicKey)).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';

      const signature = EdDSA.sign(emptyMessage, ed25519Keys.privateKey);
      expect(EdDSA.verify(emptyMessage, signature, ed25519Keys.publicKey)).toBe(true);
    });

    it('should handle very long messages', () => {
      const longMessage = 'a'.repeat(10000);

      const signature = EdDSA.sign(longMessage, ed448Keys.privateKey);
      expect(EdDSA.verify(longMessage, signature, ed448Keys.publicKey)).toBe(true);
    });

    it('should return false for signature verification with wrong key', () => {
      const keys1 = generateEd25519KeyPair();
      const keys2 = generateEd25519KeyPair();

      const message = 'test message';
      const signature = EdDSA.sign(message, keys1.privateKey);

      // Verify with different public key
      expect(EdDSA.verify(message, signature, keys2.publicKey)).toBe(false);
    });

    it('should return false for signature verification with wrong message', () => {
      const message = 'test message';
      const signature = EdDSA.sign(message, ed25519Keys.privateKey);

      expect(EdDSA.verify('wrong message', signature, ed25519Keys.publicKey)).toBe(false);
    });

    it('should return false for corrupted signatures', () => {
      const message = 'test message';
      const signature = EdDSA.sign(message, ed25519Keys.privateKey);

      // Corrupt the signature
      const corruptedSig = `${signature.slice(0, -4)  }AAAA`;
      expect(EdDSA.verify(message, corruptedSig, ed25519Keys.publicKey)).toBe(false);
    });

    it('should handle invalid base64url signatures', () => {
      const message = 'test message';

      // Invalid base64url should return false
      expect(EdDSA.verify(message, 'invalid!@#$%', ed25519Keys.publicKey)).toBe(false);

      // Empty signature should return false
      expect(EdDSA.verify(message, '', ed25519Keys.publicKey)).toBe(false);

      // Very short signature should return false
      expect(EdDSA.verify(message, 'AA', ed25519Keys.publicKey)).toBe(false);
    });

    it('should work with KeyObject inputs', () => {
      const message = 'test message';
      const signature = EdDSA.sign(message, ed25519Keys.privateKeyObject);

      expect(typeof signature).toBe('string');
      expect(EdDSA.verify(message, signature, ed25519Keys.publicKeyObject)).toBe(true);
    });

    it('should produce different signatures for different messages', () => {
      const message1 = 'message 1';
      const message2 = 'message 2';

      const sig1 = EdDSA.sign(message1, ed25519Keys.privateKey);
      const sig2 = EdDSA.sign(message2, ed25519Keys.privateKey);

      expect(sig1).not.toEqual(sig2);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🔐 Unicode test message 你好世界';

      const signature = EdDSA.sign(unicodeMessage, ed448Keys.privateKey);
      expect(EdDSA.verify(unicodeMessage, signature, ed448Keys.publicKey)).toBe(true);
    });
  });
});