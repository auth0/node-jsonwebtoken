const { describe, it, beforeEach } = require('@jest/globals');
const { RS256, RS384, RS512 } = require('../../../dist/lib/algorithms/rsa');
const { createPrivateKey, createPublicKey, KeyObject } = require('crypto');
const fs = require('fs');
const path = require('path');

describe('RSA Algorithms', () => {
  const testMessage = 'test message to sign';

  // Load test keys
  const privateKeyPem = fs.readFileSync(path.join(__dirname, '../../priv.pem'));
  const publicKeyPem = fs.readFileSync(path.join(__dirname, '../../pub.pem'));
  const wrongPublicKeyPem = fs.readFileSync(path.join(__dirname, '../../invalid_pub.pem'));

  describe('RS256', () => {
    it('should sign with private key and verify with public key (PEM strings)', () => {
      const signature = RS256.sign(testMessage, privateKeyPem);
      expect(typeof signature).toBe('string');
      expect(signature).not.toContain('+');
      expect(signature).not.toContain('/');
      expect(signature).not.toContain('=');

      const isValid = RS256.verify(testMessage, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should sign with private key and verify with public key (Buffers)', () => {
      const signature = RS256.sign(testMessage, privateKeyPem);
      const isValid = RS256.verify(testMessage, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should sign with private key and verify with public key (KeyObjects)', () => {
      const privateKey = createPrivateKey(privateKeyPem);
      const publicKey = createPublicKey(publicKeyPem);

      const signature = RS256.sign(testMessage, privateKey);
      const isValid = RS256.verify(testMessage, signature, publicKey);
      expect(isValid).toBe(true);
    });

    it('should work with key objects from string', () => {
      const privateKey = createPrivateKey(privateKeyPem.toString());
      const publicKey = createPublicKey(publicKeyPem.toString());

      const signature = RS256.sign(testMessage, privateKey);
      const isValid = RS256.verify(testMessage, signature, publicKey);
      expect(isValid).toBe(true);
    });

    it('should work with Buffer messages', () => {
      const messageBuffer = Buffer.from(testMessage);
      const signature = RS256.sign(messageBuffer, privateKeyPem);
      const isValid = RS256.verify(messageBuffer, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should reject tampered signatures', () => {
      const signature = RS256.sign(testMessage, privateKeyPem);
      const tamperedSignature = `${signature.slice(0, -1)  }X`;

      const isValid = RS256.verify(testMessage, tamperedSignature, publicKeyPem);
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong public key', () => {
      const signature = RS256.sign(testMessage, privateKeyPem);

      const isValid = RS256.verify(testMessage, signature, wrongPublicKeyPem);
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong message', () => {
      const signature = RS256.sign(testMessage, privateKeyPem);

      const isValid = RS256.verify('different message', signature, publicKeyPem);
      expect(isValid).toBe(false);
    });

    it('should throw on invalid key type', () => {
      expect(() => {
        RS256.sign(testMessage, 'not a key');
      }).toThrow();
    });

    it('should handle key objects with passphrase', () => {
      const privateKeyObj = {
        key: privateKeyPem.toString(),
        passphrase: 'test' // Even though our test key doesn't have a passphrase
      };

      expect(() => {
        const signature = RS256.sign(testMessage, privateKeyObj);
        const isValid = RS256.verify(testMessage, signature, publicKeyPem);
        expect(isValid).toBe(true);
      }).not.toThrow();
    });
  });

  describe('RS384', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = RS384.sign(testMessage, privateKeyPem);
      const isValid = RS384.verify(testMessage, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should produce different signature than RS256', () => {
      const signature256 = RS256.sign(testMessage, privateKeyPem);
      const signature384 = RS384.sign(testMessage, privateKeyPem);

      expect(signature384).not.toBe(signature256);
    });

    it('should not be compatible with RS256', () => {
      const signature384 = RS384.sign(testMessage, privateKeyPem);

      const isValid = RS256.verify(testMessage, signature384, publicKeyPem);
      expect(isValid).toBe(false);
    });
  });

  describe('RS512', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = RS512.sign(testMessage, privateKeyPem);
      const isValid = RS512.verify(testMessage, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should produce different signature than RS256 and RS384', () => {
      const signature256 = RS256.sign(testMessage, privateKeyPem);
      const signature384 = RS384.sign(testMessage, privateKeyPem);
      const signature512 = RS512.sign(testMessage, privateKeyPem);

      expect(signature512).not.toBe(signature256);
      expect(signature512).not.toBe(signature384);
    });

    it('should not be compatible with RS256 or RS384', () => {
      const signature512 = RS512.sign(testMessage, privateKeyPem);

      expect(RS256.verify(testMessage, signature512, publicKeyPem)).toBe(false);
      expect(RS384.verify(testMessage, signature512, publicKeyPem)).toBe(false);
    });
  });

  describe('Cross-algorithm compatibility', () => {
    it('should not allow verification across different RSA algorithms', () => {
      const algorithms = [
        { name: 'RS256', impl: RS256 },
        { name: 'RS384', impl: RS384 },
        { name: 'RS512', impl: RS512 }
      ];

      algorithms.forEach(({ name: alg1, impl: impl1 }) => {
        const signature = impl1.sign(testMessage, privateKeyPem);

        algorithms.forEach(({ name: alg2, impl: impl2 }) => {
          const isValid = impl2.verify(testMessage, signature, publicKeyPem);

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
      const signature = RS256.sign(longMessage, privateKeyPem);
      const isValid = RS256.verify(longMessage, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';
      const signature = RS256.sign(emptyMessage, privateKeyPem);
      const isValid = RS256.verify(emptyMessage, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🚀 Unicode test 测试 テスト';
      const signature = RS256.sign(unicodeMessage, privateKeyPem);
      const isValid = RS256.verify(unicodeMessage, signature, publicKeyPem);
      expect(isValid).toBe(true);
    });
  });
});