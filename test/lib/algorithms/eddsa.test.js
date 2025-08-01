const { describe, it } = require('@jest/globals');
const { EdDSA } = require('../../../dist/lib/algorithms/eddsa');
const { createPrivateKey, createPublicKey } = require('crypto');
const fs = require('fs');
const path = require('path');

describe('EdDSA Algorithm', () => {
  const testMessage = 'test message to sign';

  // Load test keys for Ed25519 and Ed448
  const ed25519PrivateKey = fs.readFileSync(path.join(__dirname, '../../ed25519-private.pem'));
  const ed25519PublicKey = fs.readFileSync(path.join(__dirname, '../../ed25519-public.pem'));
  const ed448PrivateKey = fs.readFileSync(path.join(__dirname, '../../ed448-private.pem'));
  const ed448PublicKey = fs.readFileSync(path.join(__dirname, '../../ed448-public.pem'));

  // Load an RSA key to test invalid key type
  const rsaPrivateKey = fs.readFileSync(path.join(__dirname, '../../priv.pem'));
  const rsaPublicKey = fs.readFileSync(path.join(__dirname, '../../pub.pem'));

  describe('Ed25519', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = EdDSA.sign(testMessage, ed25519PrivateKey);
      expect(typeof signature).toBe('string');
      expect(signature).not.toContain('+');
      expect(signature).not.toContain('/');
      expect(signature).not.toContain('=');

      const isValid = EdDSA.verify(testMessage, signature, ed25519PublicKey);
      expect(isValid).toBe(true);
    });

    it('should produce deterministic signatures (same each time)', () => {
      const signature1 = EdDSA.sign(testMessage, ed25519PrivateKey);
      const signature2 = EdDSA.sign(testMessage, ed25519PrivateKey);

      // EdDSA signatures should be deterministic - same message produces same signature
      expect(signature1).toBe(signature2);
    });

    it('should work with KeyObjects', () => {
      const privateKey = createPrivateKey(ed25519PrivateKey);
      const publicKey = createPublicKey(ed25519PublicKey);

      const signature = EdDSA.sign(testMessage, privateKey);
      const isValid = EdDSA.verify(testMessage, signature, publicKey);
      expect(isValid).toBe(true);
    });

    it('should work with Buffer messages', () => {
      const messageBuffer = Buffer.from(testMessage);
      const signature = EdDSA.sign(messageBuffer, ed25519PrivateKey);
      const isValid = EdDSA.verify(messageBuffer, signature, ed25519PublicKey);
      expect(isValid).toBe(true);
    });

    it('should reject tampered signatures', () => {
      const signature = EdDSA.sign(testMessage, ed25519PrivateKey);
      const tamperedSignature = `${signature.slice(0, -1)  }X`;

      const isValid = EdDSA.verify(testMessage, tamperedSignature, ed25519PublicKey);
      expect(isValid).toBe(false);
    });

    it('should reject signatures with wrong message', () => {
      const signature = EdDSA.sign(testMessage, ed25519PrivateKey);

      const isValid = EdDSA.verify('different message', signature, ed25519PublicKey);
      expect(isValid).toBe(false);
    });

    it('should have fixed signature length for Ed25519', () => {
      // Ed25519 signatures should always be 64 bytes
      const signature = EdDSA.sign(testMessage, ed25519PrivateKey);
      const decoded = Buffer.from(signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      expect(decoded.length).toBe(64);
    });
  });

  describe('Ed448', () => {
    it('should sign with private key and verify with public key', () => {
      const signature = EdDSA.sign(testMessage, ed448PrivateKey);
      const isValid = EdDSA.verify(testMessage, signature, ed448PublicKey);
      expect(isValid).toBe(true);
    });

    it('should produce deterministic signatures', () => {
      const signature1 = EdDSA.sign(testMessage, ed448PrivateKey);
      const signature2 = EdDSA.sign(testMessage, ed448PrivateKey);

      // Ed448 signatures should also be deterministic
      expect(signature1).toBe(signature2);
    });

    it('should have fixed signature length for Ed448', () => {
      // Ed448 signatures should always be 114 bytes
      const signature = EdDSA.sign(testMessage, ed448PrivateKey);
      const decoded = Buffer.from(signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      expect(decoded.length).toBe(114);
    });

    it('should not be compatible with Ed25519', () => {
      const signature448 = EdDSA.sign(testMessage, ed448PrivateKey);

      const isValid = EdDSA.verify(testMessage, signature448, ed25519PublicKey);
      expect(isValid).toBe(false);
    });
  });

  describe('Invalid key types', () => {
    it('should throw when signing with non-EdDSA private key', () => {
      expect(() => {
        EdDSA.sign(testMessage, rsaPrivateKey);
      }).toThrow('Invalid key for EdDSA algorithm');
    });

    it('should throw when verifying with non-EdDSA public key', () => {
      const signature = EdDSA.sign(testMessage, ed25519PrivateKey);

      expect(() => {
        EdDSA.verify(testMessage, signature, rsaPublicKey);
      }).toThrow('Invalid key for EdDSA algorithm');
    });

    it('should handle key objects with invalid types', () => {
      const rsaPrivKey = createPrivateKey(rsaPrivateKey);
      const rsaPubKey = createPublicKey(rsaPublicKey);

      expect(() => {
        EdDSA.sign(testMessage, rsaPrivKey);
      }).toThrow('Invalid key for EdDSA algorithm');

      const signature = EdDSA.sign(testMessage, ed25519PrivateKey);
      expect(() => {
        EdDSA.verify(testMessage, signature, rsaPubKey);
      }).toThrow('Invalid key for EdDSA algorithm');
    });
  });

  describe('Cross-curve compatibility', () => {
    it('should not allow Ed25519 signatures to verify with Ed448 keys', () => {
      const signature25519 = EdDSA.sign(testMessage, ed25519PrivateKey);
      const isValid = EdDSA.verify(testMessage, signature25519, ed448PublicKey);
      expect(isValid).toBe(false);
    });

    it('should not allow Ed448 signatures to verify with Ed25519 keys', () => {
      const signature448 = EdDSA.sign(testMessage, ed448PrivateKey);
      const isValid = EdDSA.verify(testMessage, signature448, ed25519PublicKey);
      expect(isValid).toBe(false);
    });
  });

  describe('Edge cases', () => {
    it('should handle very long messages', () => {
      const longMessage = 'x'.repeat(10000);
      const signature = EdDSA.sign(longMessage, ed25519PrivateKey);
      const isValid = EdDSA.verify(longMessage, signature, ed25519PublicKey);
      expect(isValid).toBe(true);
    });

    it('should handle empty messages', () => {
      const emptyMessage = '';
      const signature = EdDSA.sign(emptyMessage, ed25519PrivateKey);
      const isValid = EdDSA.verify(emptyMessage, signature, ed25519PublicKey);
      expect(isValid).toBe(true);
    });

    it('should handle unicode messages', () => {
      const unicodeMessage = '🚀 Unicode test 测试 テスト';
      const signature = EdDSA.sign(unicodeMessage, ed25519PrivateKey);
      const isValid = EdDSA.verify(unicodeMessage, signature, ed25519PublicKey);
      expect(isValid).toBe(true);
    });

    it('should handle binary data', () => {
      const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      const signature = EdDSA.sign(binaryData, ed25519PrivateKey);
      const isValid = EdDSA.verify(binaryData, signature, ed25519PublicKey);
      expect(isValid).toBe(true);
    });
  });

  describe('Deterministic signature property', () => {
    it('should produce same signature for same message with Ed25519', () => {
      const signatures = [];
      for (let i = 0; i < 10; i++) {
        signatures.push(EdDSA.sign(testMessage, ed25519PrivateKey));
      }

      // All signatures should be identical
      const firstSig = signatures[0];
      signatures.forEach(sig => {
        expect(sig).toBe(firstSig);
      });
    });

    it('should produce different signatures for different messages', () => {
      const message1 = 'message 1';
      const message2 = 'message 2';

      const signature1 = EdDSA.sign(message1, ed25519PrivateKey);
      const signature2 = EdDSA.sign(message2, ed25519PrivateKey);

      expect(signature1).not.toBe(signature2);
    });
  });
});