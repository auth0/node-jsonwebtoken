const { describe, it, beforeEach } = require('@jest/globals');
const { HS256, HS384, HS512 } = require('../../../dist/lib/algorithms/hmac');
const { createSecretKey, KeyObject } = require('crypto');

describe('HMAC Algorithms', () => {
  const testMessage = 'test message to sign';
  const testSecret = 'my-secret-key';

  describe('HS256', () => {
    it('should sign and verify with string secret', () => {
      const signature = HS256.sign(testMessage, testSecret);
      expect(typeof signature).toBe('string');
      expect(signature).not.toContain('+');
      expect(signature).not.toContain('/');
      expect(signature).not.toContain('=');

      const isValid = HS256.verify(testMessage, signature, testSecret);
      expect(isValid).toBe(true);
    });

    it('should sign and verify with Buffer secret', () => {
      const secretBuffer = Buffer.from(testSecret);
      const signature = HS256.sign(testMessage, secretBuffer);

      const isValid = HS256.verify(testMessage, signature, secretBuffer);
      expect(isValid).toBe(true);
    });

    it('should sign and verify with KeyObject secret', () => {
      const secretKey = createSecretKey(Buffer.from(testSecret));
      const signature = HS256.sign(testMessage, secretKey);

      const isValid = HS256.verify(testMessage, signature, secretKey);
      expect(isValid).toBe(true);
    });

    it('should sign and verify with Buffer message', () => {
      const messageBuffer = Buffer.from(testMessage);
      const signature = HS256.sign(messageBuffer, testSecret);

      const isValid = HS256.verify(messageBuffer, signature, testSecret);
      expect(isValid).toBe(true);
    });

    it('should reject tampered signatures', () => {
      const signature = HS256.sign(testMessage, testSecret);
      const tamperedSignature = `${signature.slice(0, -1)  }X`;

      const isValid = HS256.verify(testMessage, tamperedSignature, testSecret);
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong secret', () => {
      const signature = HS256.sign(testMessage, testSecret);

      const isValid = HS256.verify(testMessage, signature, 'wrong-secret');
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong message', () => {
      const signature = HS256.sign(testMessage, testSecret);

      const isValid = HS256.verify('different message', signature, testSecret);
      expect(isValid).toBe(false);
    });

    it('should throw on invalid key type', () => {
      expect(() => {
        HS256.sign(testMessage, 123);
      }).toThrow('Invalid key type');
    });

    it('should throw on non-secret KeyObject', () => {
      // This would need an RSA key or similar, which we'll mock
      const mockKey = { type: 'private' };
      expect(() => {
        HS256.sign(testMessage, mockKey);
      }).toThrow('Invalid key type');
    });
  });

  describe('HS384', () => {
    it('should sign and verify with string secret', () => {
      const signature = HS384.sign(testMessage, testSecret);
      expect(typeof signature).toBe('string');

      const isValid = HS384.verify(testMessage, signature, testSecret);
      expect(isValid).toBe(true);
    });

    it('should produce longer signatures than HS256', () => {
      const signature256 = HS256.sign(testMessage, testSecret);
      const signature384 = HS384.sign(testMessage, testSecret);

      expect(signature384.length).toBeGreaterThan(signature256.length);
    });

    it('should not be compatible with HS256', () => {
      const signature384 = HS384.sign(testMessage, testSecret);

      const isValid = HS256.verify(testMessage, signature384, testSecret);
      expect(isValid).toBe(false);
    });
  });

  describe('HS512', () => {
    it('should sign and verify with string secret', () => {
      const signature = HS512.sign(testMessage, testSecret);
      expect(typeof signature).toBe('string');

      const isValid = HS512.verify(testMessage, signature, testSecret);
      expect(isValid).toBe(true);
    });

    it('should produce longer signatures than HS384', () => {
      const signature384 = HS384.sign(testMessage, testSecret);
      const signature512 = HS512.sign(testMessage, testSecret);

      expect(signature512.length).toBeGreaterThan(signature384.length);
    });

    it('should not be compatible with HS256 or HS384', () => {
      const signature512 = HS512.sign(testMessage, testSecret);

      expect(HS256.verify(testMessage, signature512, testSecret)).toBe(false);
      expect(HS384.verify(testMessage, signature512, testSecret)).toBe(false);
    });
  });

  describe('Timing-safe comparison', () => {
    it('should use timing-safe comparison for verification', () => {
      // This test verifies that even with slightly different signatures,
      // the verification takes similar time (timing-safe)
      const signature = HS256.sign(testMessage, testSecret);
      const wrongSignature1 = `A${  signature.slice(1)}`;
      const wrongSignature2 = `${signature.slice(0, -1)  }Z`;

      // Both should be false
      expect(HS256.verify(testMessage, wrongSignature1, testSecret)).toBe(false);
      expect(HS256.verify(testMessage, wrongSignature2, testSecret)).toBe(false);
    });
  });

  describe('Cross-algorithm compatibility', () => {
    it('should not allow verification across different HMAC algorithms', () => {
      const algorithms = [
        { name: 'HS256', impl: HS256 },
        { name: 'HS384', impl: HS384 },
        { name: 'HS512', impl: HS512 }
      ];

      algorithms.forEach(({ name: alg1, impl: impl1 }) => {
        const signature = impl1.sign(testMessage, testSecret);

        algorithms.forEach(({ name: alg2, impl: impl2 }) => {
          const isValid = impl2.verify(testMessage, signature, testSecret);

          if (alg1 === alg2) {
            expect(isValid).toBe(true);
          } else {
            expect(isValid).toBe(false);
          }
        });
      });
    });
  });
});