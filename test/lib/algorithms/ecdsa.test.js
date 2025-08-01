const { describe, it } = require('@jest/globals');
const { ES256, ES384, ES512, ES256K } = require('../../../dist/lib/algorithms/ecdsa');
const { createPrivateKey, createPublicKey } = require('crypto');
const fs = require('fs');
const path = require('path');

describe('ECDSA Algorithms', () => {
  const testMessage = 'test message to sign';

  // Load test keys for different curves
  const es256PrivateKey = fs.readFileSync(path.join(__dirname, '../../ecdsa-private.pem'));
  const es256PublicKey = fs.readFileSync(path.join(__dirname, '../../ecdsa-public.pem'));
  const es384PrivateKey = fs.readFileSync(path.join(__dirname, '../../secp384r1-private.pem'));
  const es384PublicKey = fs.readFileSync(path.join(__dirname, '../../secp384r1-public.pem'));
  const es512PrivateKey = fs.readFileSync(path.join(__dirname, '../../secp521r1-private.pem'));
  const es512PublicKey = fs.readFileSync(path.join(__dirname, '../../secp521r1-public.pem'));
  const es256kPrivateKey = fs.readFileSync(path.join(__dirname, '../../secp256k1-private.pem'));
  const es256kPublicKey = fs.readFileSync(path.join(__dirname, '../../secp256k1-public.pem'));
  const invalidPublicKey = fs.readFileSync(path.join(__dirname, '../../ecdsa-public-invalid.pem'));

  describe('ES256', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = ES256.sign(testMessage, es256PrivateKey);
      expect(typeof signature).toBe('string');
      expect(signature).not.toContain('+');
      expect(signature).not.toContain('/');
      expect(signature).not.toContain('=');

      const isValid = ES256.verify(testMessage, signature, es256PublicKey);
      expect(isValid).toBe(true);
    });

    it('should produce probabilistic signatures (different each time)', () => {
      const signature1 = ES256.sign(testMessage, es256PrivateKey);
      const signature2 = ES256.sign(testMessage, es256PrivateKey);

      // ECDSA signatures should be different even for the same message
      expect(signature1).not.toBe(signature2);

      // But both should verify correctly
      expect(ES256.verify(testMessage, signature1, es256PublicKey)).toBe(true);
      expect(ES256.verify(testMessage, signature2, es256PublicKey)).toBe(true);
    });

    it('should work with KeyObjects', () => {
      const privateKey = createPrivateKey(es256PrivateKey);
      const publicKey = createPublicKey(es256PublicKey);

      const signature = ES256.sign(testMessage, privateKey);
      const isValid = ES256.verify(testMessage, signature, publicKey);
      expect(isValid).toBe(true);
    });

    it('should work with Buffer messages', () => {
      const messageBuffer = Buffer.from(testMessage);
      const signature = ES256.sign(messageBuffer, es256PrivateKey);
      const isValid = ES256.verify(messageBuffer, signature, es256PublicKey);
      expect(isValid).toBe(true);
    });

    it('should reject tampered signatures', () => {
      const signature = ES256.sign(testMessage, es256PrivateKey);
      const tamperedSignature = `${signature.slice(0, -1)  }X`;

      const isValid = ES256.verify(testMessage, tamperedSignature, es256PublicKey);
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong public key', () => {
      const signature = ES256.sign(testMessage, es256PrivateKey);

      const isValid = ES256.verify(testMessage, signature, invalidPublicKey);
      expect(isValid).toBe(false);
    });

    it('should have fixed signature length', () => {
      // ES256 signatures should always be 64 bytes (base64url encoded)
      const signature = ES256.sign(testMessage, es256PrivateKey);
      const decoded = Buffer.from(signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      expect(decoded.length).toBe(64);
    });
  });

  describe('ES384', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = ES384.sign(testMessage, es384PrivateKey);
      const isValid = ES384.verify(testMessage, signature, es384PublicKey);
      expect(isValid).toBe(true);
    });

    it('should produce probabilistic signatures', () => {
      const signature1 = ES384.sign(testMessage, es384PrivateKey);
      const signature2 = ES384.sign(testMessage, es384PrivateKey);

      expect(signature1).not.toBe(signature2);
      expect(ES384.verify(testMessage, signature1, es384PublicKey)).toBe(true);
      expect(ES384.verify(testMessage, signature2, es384PublicKey)).toBe(true);
    });

    it('should have fixed signature length', () => {
      // ES384 signatures should always be 96 bytes (base64url encoded)
      const signature = ES384.sign(testMessage, es384PrivateKey);
      const decoded = Buffer.from(signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      expect(decoded.length).toBe(96);
    });

    it('should not be compatible with ES256', () => {
      const signature384 = ES384.sign(testMessage, es384PrivateKey);

      // This will throw because signature length is wrong
      expect(() => ES256.verify(testMessage, signature384, es256PublicKey)).toThrow();
    });
  });

  describe('ES512', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = ES512.sign(testMessage, es512PrivateKey);
      const isValid = ES512.verify(testMessage, signature, es512PublicKey);
      expect(isValid).toBe(true);
    });

    it('should produce probabilistic signatures', () => {
      const signature1 = ES512.sign(testMessage, es512PrivateKey);
      const signature2 = ES512.sign(testMessage, es512PrivateKey);

      expect(signature1).not.toBe(signature2);
      expect(ES512.verify(testMessage, signature1, es512PublicKey)).toBe(true);
      expect(ES512.verify(testMessage, signature2, es512PublicKey)).toBe(true);
    });

    it('should have fixed signature length', () => {
      // ES512 signatures should always be 132 bytes (base64url encoded)
      const signature = ES512.sign(testMessage, es512PrivateKey);
      const decoded = Buffer.from(signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      expect(decoded.length).toBe(132);
    });

    it('should not be compatible with ES256 or ES384', () => {
      const signature512 = ES512.sign(testMessage, es512PrivateKey);

      expect(() => ES256.verify(testMessage, signature512, es256PublicKey)).toThrow();
      expect(() => ES384.verify(testMessage, signature512, es384PublicKey)).toThrow();
    });
  });

  describe('ES256K (secp256k1)', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = ES256K.sign(testMessage, es256kPrivateKey);
      const isValid = ES256K.verify(testMessage, signature, es256kPublicKey);
      expect(isValid).toBe(true);
    });

    it('should produce probabilistic signatures', () => {
      const signature1 = ES256K.sign(testMessage, es256kPrivateKey);
      const signature2 = ES256K.sign(testMessage, es256kPrivateKey);

      expect(signature1).not.toBe(signature2);
      expect(ES256K.verify(testMessage, signature1, es256kPublicKey)).toBe(true);
      expect(ES256K.verify(testMessage, signature2, es256kPublicKey)).toBe(true);
    });

    it('should have same signature length as ES256', () => {
      // ES256K signatures should also be 64 bytes
      const signature = ES256K.sign(testMessage, es256kPrivateKey);
      const decoded = Buffer.from(signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      expect(decoded.length).toBe(64);
    });

    it('should not be compatible with ES256 despite same signature length', () => {
      const signatureK = ES256K.sign(testMessage, es256kPrivateKey);

      const isValid = ES256.verify(testMessage, signatureK, es256PublicKey);
      expect(isValid).toBe(false);
    });
  });

  describe('Cross-algorithm compatibility', () => {
    it('should not allow verification across different ECDSA algorithms', () => {
      const algorithms = [
        { name: 'ES256', impl: ES256, privateKey: es256PrivateKey, publicKey: es256PublicKey },
        { name: 'ES384', impl: ES384, privateKey: es384PrivateKey, publicKey: es384PublicKey },
        { name: 'ES512', impl: ES512, privateKey: es512PrivateKey, publicKey: es512PublicKey },
        { name: 'ES256K', impl: ES256K, privateKey: es256kPrivateKey, publicKey: es256kPublicKey }
      ];

      algorithms.forEach(({ name: alg1, impl: impl1, privateKey: key1 }) => {
        const signature = impl1.sign(testMessage, key1);

        algorithms.forEach(({ name: alg2, impl: impl2, publicKey: key2 }) => {
          if (alg1 === alg2) {
            const isValid = impl2.verify(testMessage, signature, key2);
            expect(isValid).toBe(true);
          } else {
            // Different algorithms should either fail or return false
            try {
              const isValid = impl2.verify(testMessage, signature, key2);
              expect(isValid).toBe(false);
            } catch (e) {
              // Expected for different signature lengths
              expect(e.message).toMatch(/Invalid signature length|Invalid DER signature/);
            }
          }
        });
      });
    });
  });

  describe('Edge cases', () => {
    it('should handle very long messages', () => {
      const longMessage = 'x'.repeat(10000);
      const signature = ES256.sign(longMessage, es256PrivateKey);
      const isValid = ES256.verify(longMessage, signature, es256PublicKey);
      expect(isValid).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';
      const signature = ES256.sign(emptyMessage, es256PrivateKey);
      const isValid = ES256.verify(emptyMessage, signature, es256PublicKey);
      expect(isValid).toBe(true);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🚀 Unicode test 测试 テスト';
      const signature = ES256.sign(unicodeMessage, es256PrivateKey);
      const isValid = ES256.verify(unicodeMessage, signature, es256PublicKey);
      expect(isValid).toBe(true);
    });
  });

  describe('DER/Jose format conversion', () => {
    it('should properly convert between DER and Jose formats', () => {
      // This is implicitly tested by sign/verify, but let's be explicit
      const signature = ES256.sign(testMessage, es256PrivateKey);

      // The signature should be in Jose format (base64url, no DER structure)
      expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);

      // Should not contain DER SEQUENCE tag
      const decoded = Buffer.from(signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      expect(decoded[0]).not.toBe(0x30); // SEQUENCE tag
    });
  });
});