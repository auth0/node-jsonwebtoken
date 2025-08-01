const { describe, it, beforeEach } = require('@jest/globals');
const { PS256, PS384, PS512 } = require('../../../dist/lib/algorithms/rsa-pss');
const { createPrivateKey, createPublicKey } = require('crypto');
const fs = require('fs');
const path = require('path');

describe('RSA-PSS Algorithms', () => {
  const testMessage = 'test message to sign';

  // Load test keys
  const privateKeyPem = fs.readFileSync(path.join(__dirname, '../../rsa-pss-private.pem'));
  const publicKeyPem = fs.readFileSync(path.join(__dirname, '../../pub.pem'));
  const wrongPublicKeyPem = fs.readFileSync(path.join(__dirname, '../../invalid_pub.pem'));

  // Use regular RSA keys as PSS also works with them
  const rsaPrivateKeyPem = fs.readFileSync(path.join(__dirname, '../../priv.pem'));
  const rsaPublicKeyPem = fs.readFileSync(path.join(__dirname, '../../pub.pem'));

  describe('PS256', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = PS256.sign(testMessage, rsaPrivateKeyPem);
      expect(typeof signature).toBe('string');
      expect(signature).not.toContain('+');
      expect(signature).not.toContain('/');
      expect(signature).not.toContain('=');

      const isValid = PS256.verify(testMessage, signature, rsaPublicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should produce probabilistic signatures (different each time)', () => {
      const signature1 = PS256.sign(testMessage, rsaPrivateKeyPem);
      const signature2 = PS256.sign(testMessage, rsaPrivateKeyPem);

      // PSS signatures should be different even for the same message
      expect(signature1).not.toBe(signature2);

      // But both should verify correctly
      expect(PS256.verify(testMessage, signature1, rsaPublicKeyPem)).toBe(true);
      expect(PS256.verify(testMessage, signature2, rsaPublicKeyPem)).toBe(true);
    });

    it('should work with Buffer messages', () => {
      const messageBuffer = Buffer.from(testMessage);
      const signature = PS256.sign(messageBuffer, rsaPrivateKeyPem);
      const isValid = PS256.verify(messageBuffer, signature, rsaPublicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should work with KeyObjects', () => {
      const privateKey = createPrivateKey(rsaPrivateKeyPem);
      const publicKey = createPublicKey(rsaPublicKeyPem);

      const signature = PS256.sign(testMessage, privateKey);
      const isValid = PS256.verify(testMessage, signature, publicKey);
      expect(isValid).toBe(true);
    });

    it('should reject tampered signatures', () => {
      const signature = PS256.sign(testMessage, rsaPrivateKeyPem);
      const tamperedSignature = `${signature.slice(0, -1)  }X`;

      const isValid = PS256.verify(testMessage, tamperedSignature, rsaPublicKeyPem);
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong public key', () => {
      const signature = PS256.sign(testMessage, rsaPrivateKeyPem);

      const isValid = PS256.verify(testMessage, signature, wrongPublicKeyPem);
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong message', () => {
      const signature = PS256.sign(testMessage, rsaPrivateKeyPem);

      const isValid = PS256.verify('different message', signature, rsaPublicKeyPem);
      expect(isValid).toBe(false);
    });
  });

  describe('PS384', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = PS384.sign(testMessage, rsaPrivateKeyPem);
      const isValid = PS384.verify(testMessage, signature, rsaPublicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should produce probabilistic signatures', () => {
      const signature1 = PS384.sign(testMessage, rsaPrivateKeyPem);
      const signature2 = PS384.sign(testMessage, rsaPrivateKeyPem);

      expect(signature1).not.toBe(signature2);
      expect(PS384.verify(testMessage, signature1, rsaPublicKeyPem)).toBe(true);
      expect(PS384.verify(testMessage, signature2, rsaPublicKeyPem)).toBe(true);
    });

    it('should not be compatible with PS256', () => {
      const signature384 = PS384.sign(testMessage, rsaPrivateKeyPem);

      const isValid = PS256.verify(testMessage, signature384, rsaPublicKeyPem);
      expect(isValid).toBe(false);
    });
  });

  describe('PS512', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = PS512.sign(testMessage, rsaPrivateKeyPem);
      const isValid = PS512.verify(testMessage, signature, rsaPublicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should produce probabilistic signatures', () => {
      const signature1 = PS512.sign(testMessage, rsaPrivateKeyPem);
      const signature2 = PS512.sign(testMessage, rsaPrivateKeyPem);

      expect(signature1).not.toBe(signature2);
      expect(PS512.verify(testMessage, signature1, rsaPublicKeyPem)).toBe(true);
      expect(PS512.verify(testMessage, signature2, rsaPublicKeyPem)).toBe(true);
    });

    it('should not be compatible with PS256 or PS384', () => {
      const signature512 = PS512.sign(testMessage, rsaPrivateKeyPem);

      expect(PS256.verify(testMessage, signature512, rsaPublicKeyPem)).toBe(false);
      expect(PS384.verify(testMessage, signature512, rsaPublicKeyPem)).toBe(false);
    });
  });

  describe('PSS vs PKCS#1 v1.5 signatures', () => {
    const { RS256 } = require('../../../dist/lib/algorithms/rsa');

    it('PSS signatures should not verify with PKCS#1 v1.5', () => {
      const pssSignature = PS256.sign(testMessage, rsaPrivateKeyPem);
      const isValid = RS256.verify(testMessage, pssSignature, rsaPublicKeyPem);
      expect(isValid).toBe(false);
    });

    it('PKCS#1 v1.5 signatures should not verify with PSS', () => {
      const rsaSignature = RS256.sign(testMessage, rsaPrivateKeyPem);
      const isValid = PS256.verify(testMessage, rsaSignature, rsaPublicKeyPem);
      expect(isValid).toBe(false);
    });
  });

  describe('Cross-algorithm compatibility', () => {
    it('should not allow verification across different PSS algorithms', () => {
      const algorithms = [
        { name: 'PS256', impl: PS256 },
        { name: 'PS384', impl: PS384 },
        { name: 'PS512', impl: PS512 }
      ];

      algorithms.forEach(({ name: alg1, impl: impl1 }) => {
        const signature = impl1.sign(testMessage, rsaPrivateKeyPem);

        algorithms.forEach(({ name: alg2, impl: impl2 }) => {
          const isValid = impl2.verify(testMessage, signature, rsaPublicKeyPem);

          if (alg1 === alg2) {
            expect(isValid).toBe(true);
          } else {
            expect(isValid).toBe(false);
          }
        });
      });
    });
  });

  describe('Edge cases', () => {
    it('should handle very long messages', () => {
      const longMessage = 'x'.repeat(10000);
      const signature = PS256.sign(longMessage, rsaPrivateKeyPem);
      const isValid = PS256.verify(longMessage, signature, rsaPublicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';
      const signature = PS256.sign(emptyMessage, rsaPrivateKeyPem);
      const isValid = PS256.verify(emptyMessage, signature, rsaPublicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🚀 Unicode test 测试 テスト';
      const signature = PS256.sign(unicodeMessage, rsaPrivateKeyPem);
      const isValid = PS256.verify(unicodeMessage, signature, rsaPublicKeyPem);
      expect(isValid).toBe(true);
    });
  });
});