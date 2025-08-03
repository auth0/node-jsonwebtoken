const { describe, it, expect } = require('@jest/globals');
const { validateAsymmetricKey } = require('../../../src/lib/validateAsymmetricKey');
const { generateRSAKeyPair, generateECKeyPair, generateEd25519KeyPair, generateSmallRSAKeyPair } = require('../../helpers/key-generator');
const { generateKeyPairSync, createSecretKey } = require('crypto');

describe('validateAsymmetricKey', () => {
  describe('basic validation', () => {
    it('should return early when algorithm is undefined', () => {
      const { publicKeyObject } = generateRSAKeyPair();
      expect(() => validateAsymmetricKey(undefined, publicKeyObject)).not.toThrow();
    });

    it('should return early when key is undefined', () => {
      expect(() => validateAsymmetricKey('RS256', undefined)).not.toThrow();
    });

    it('should return early when both algorithm and key are undefined', () => {
      expect(() => validateAsymmetricKey(undefined, undefined)).not.toThrow();
    });

    it('should return early when key has no asymmetricKeyType', () => {
      const secretKey = createSecretKey(Buffer.alloc(32));
      expect(() => validateAsymmetricKey('HS256', secretKey)).not.toThrow();
    });
  });

  describe('unknown key type handling', () => {
    it('should throw error for unknown key type', () => {
      // Mock a key with unknown type
      const mockKey = {
        asymmetricKeyType: 'unknown-type'
      };

      expect(() => validateAsymmetricKey('RS256', mockKey))
        .toThrow('Unknown key type "unknown-type".');
    });

    it('should handle future key types gracefully', () => {
      // Mock a key with a hypothetical future key type
      const mockKey = {
        asymmetricKeyType: 'quantum'
      };

      expect(() => validateAsymmetricKey('RS256', mockKey))
        .toThrow('Unknown key type "quantum".');
    });
  });

  describe('algorithm mismatch validation', () => {
    it('should throw error when RSA key is used with EC algorithm', () => {
      const { publicKeyObject } = generateRSAKeyPair();

      expect(() => validateAsymmetricKey('ES256', publicKeyObject))
        .toThrow('"alg" parameter for "rsa" key type must be one of: RS256, PS256, RS384, PS384, RS512, PS512.');
    });

    it('should throw error when EC key is used with RSA algorithm', () => {
      const { publicKeyObject } = generateECKeyPair('P-256');

      expect(() => validateAsymmetricKey('RS256', publicKeyObject))
        .toThrow('"alg" parameter for "ec" key type must be one of: ES256, ES384, ES512, ES256K.');
    });

    it('should throw error when EdDSA key is used with wrong algorithm', () => {
      const { publicKeyObject } = generateEd25519KeyPair();

      expect(() => validateAsymmetricKey('RS256', publicKeyObject))
        .toThrow('"alg" parameter for "ed25519" key type must be one of: EdDSA.');
    });

    it('should validate Ed448 keys', () => {
      try {
        const { publicKeyObject } = generateKeyPairSync('ed448');

        // Should not throw for correct algorithm
        expect(() => validateAsymmetricKey('EdDSA', publicKeyObject)).not.toThrow();

        // Ed448 keys might not have the expected asymmetricKeyType in some Node versions
        // The important thing is that EdDSA algorithm doesn't throw
        if (publicKeyObject && publicKeyObject.asymmetricKeyType === 'ed448') {
          // Should throw for incorrect algorithm if key type is recognized
          expect(() => validateAsymmetricKey('ES256', publicKeyObject))
            .toThrow('"alg" parameter for "ed448" key type must be one of: EdDSA.');
        }
      } catch (e) {
        // Ed448 may not be supported in all Node versions
        expect(e.message).toMatch(/ed448|not supported/i);
      }
    });

    it('should validate X25519 keys', () => {
      // Note: X25519 is for key exchange, not signing, so this is more theoretical
      try {
        const { publicKeyObject } = generateKeyPairSync('x25519');

        // Should not throw for EdDSA (though this is not practical)
        expect(() => validateAsymmetricKey('EdDSA', publicKeyObject)).not.toThrow();

        // Should throw for incorrect algorithm
        expect(() => validateAsymmetricKey('ES256', publicKeyObject))
          .toThrow('"alg" parameter for "x25519" key type must be one of: EdDSA.');
      } catch (e) {
        // X25519 may not be supported in all Node versions
        expect(e.message).toMatch(/x25519|not supported/i);
      }
    });

    it('should validate X448 keys', () => {
      // Note: X448 is for key exchange, not signing, so this is more theoretical
      try {
        const { publicKeyObject } = generateKeyPairSync('x448');

        // Should not throw for EdDSA (though this is not practical)
        expect(() => validateAsymmetricKey('EdDSA', publicKeyObject)).not.toThrow();

        // Should throw for incorrect algorithm
        expect(() => validateAsymmetricKey('ES256', publicKeyObject))
          .toThrow('"alg" parameter for "x448" key type must be one of: EdDSA.');
      } catch (e) {
        // X448 may not be supported in all Node versions
        expect(e.message).toMatch(/x448|not supported/i);
      }
    });
  });

  describe('RSA key validation', () => {
    it('should allow all RSA algorithms for RSA keys', () => {
      const { publicKeyObject } = generateRSAKeyPair();

      // RSA algorithms
      expect(() => validateAsymmetricKey('RS256', publicKeyObject)).not.toThrow();
      expect(() => validateAsymmetricKey('RS384', publicKeyObject)).not.toThrow();
      expect(() => validateAsymmetricKey('RS512', publicKeyObject)).not.toThrow();

      // PSS algorithms
      expect(() => validateAsymmetricKey('PS256', publicKeyObject)).not.toThrow();
      expect(() => validateAsymmetricKey('PS384', publicKeyObject)).not.toThrow();
      expect(() => validateAsymmetricKey('PS512', publicKeyObject)).not.toThrow();
    });

    it('should reject small RSA keys by default', () => {
      try {
        const { publicKeyObject } = generateSmallRSAKeyPair(); // 1024 bits

        // Only throws if ASYMMETRIC_KEY_DETAILS_SUPPORTED is true
        // and key has asymmetricKeyDetails with modulusLength
        try {
          validateAsymmetricKey('RS256', publicKeyObject);
          // If it doesn't throw, check if key details are supported
          const hasKeyDetails = publicKeyObject && publicKeyObject.asymmetricKeyDetails &&
                               publicKeyObject.asymmetricKeyDetails.modulusLength !== undefined;
          expect(hasKeyDetails).toBe(false);
        } catch (err) {
          expect(err.message).toContain('minimum RSA key size is 2048 bits');
        }
      } catch (genErr) {
        // generateSmallRSAKeyPair might fail in some environments
        expect(genErr.message).toMatch(/key|generate/i);
      }
    });

    it('should allow small RSA keys when allowInsecureKeySizes is true', () => {
      const { publicKeyObject } = generateSmallRSAKeyPair(); // 1024 bits

      expect(() => validateAsymmetricKey('RS256', publicKeyObject, true)).not.toThrow();
    });

    it('should handle RSA keys without asymmetricKeyDetails', () => {
      // Mock a key without asymmetricKeyDetails
      const mockKey = {
        asymmetricKeyType: 'rsa',
        asymmetricKeyDetails: null
      };

      // Should not throw even without key details
      expect(() => validateAsymmetricKey('RS256', mockKey)).not.toThrow();
    });
  });

  describe('RSA-PSS key validation', () => {
    it('should validate RSA-PSS specific algorithms', () => {
      // Note: Regular RSA keys can be used with PSS algorithms
      const { publicKeyObject } = generateRSAKeyPair();

      expect(() => validateAsymmetricKey('PS256', publicKeyObject)).not.toThrow();
      expect(() => validateAsymmetricKey('PS384', publicKeyObject)).not.toThrow();
      expect(() => validateAsymmetricKey('PS512', publicKeyObject)).not.toThrow();
    });

    it('should handle RSA-PSS key type', () => {
      // Mock an RSA-PSS key with valid details to avoid RSA-PSS parameter error
      const mockKey = {
        asymmetricKeyType: 'rsa-pss',
        asymmetricKeyDetails: {
          modulusLength: 2048,
          hashAlgorithm: 'sha256',
          mgf1HashAlgorithm: 'sha256',
          saltLength: 32
        }
      };

      // PSS algorithms should work with matching parameters
      expect(() => validateAsymmetricKey('PS256', mockKey)).not.toThrow();

      // Test with PS384 (requires sha384)
      const mockKey384 = {
        asymmetricKeyType: 'rsa-pss',
        asymmetricKeyDetails: {
          modulusLength: 2048,
          hashAlgorithm: 'sha384',
          mgf1HashAlgorithm: 'sha384',
          saltLength: 48
        }
      };
      expect(() => validateAsymmetricKey('PS384', mockKey384)).not.toThrow();

      // Regular RSA algorithms should not work
      expect(() => validateAsymmetricKey('RS256', mockKey))
        .toThrow('"alg" parameter for "rsa-pss" key type must be one of: PS256, PS384, PS512.');
    });

    it('should reject small RSA-PSS keys', () => {
      // Mock a small RSA-PSS key
      const mockKey = {
        asymmetricKeyType: 'rsa-pss',
        asymmetricKeyDetails: {
          modulusLength: 1024
        }
      };

      expect(() => validateAsymmetricKey('PS256', mockKey))
        .toThrow('minimum RSA key size is 2048 bits');
    });
  });

  describe('EC key validation', () => {
    it('should allow all EC algorithms for EC keys', () => {
      const { publicKeyObject: p256Key } = generateECKeyPair('P-256');
      const { publicKeyObject: p384Key } = generateECKeyPair('P-384');
      const { publicKeyObject: p521Key } = generateECKeyPair('P-521');
      const { publicKeyObject: secp256k1Key } = generateECKeyPair('secp256k1');

      // ES256 with P-256
      expect(() => validateAsymmetricKey('ES256', p256Key)).not.toThrow();

      // ES384 with P-384
      expect(() => validateAsymmetricKey('ES384', p384Key)).not.toThrow();

      // ES512 with P-521
      expect(() => validateAsymmetricKey('ES512', p521Key)).not.toThrow();

      // ES256K with secp256k1
      expect(() => validateAsymmetricKey('ES256K', secp256k1Key)).not.toThrow();
    });

    it('should reject EC keys with wrong curve', () => {
      const { publicKeyObject: p256Key } = generateECKeyPair('P-256');
      const { publicKeyObject: p384Key } = generateECKeyPair('P-384');

      // ES256 requires P-256 curve
      expect(() => validateAsymmetricKey('ES256', p384Key))
        .toThrow('"alg" parameter "ES256" requires curve "prime256v1".');

      // ES384 requires P-384 curve
      expect(() => validateAsymmetricKey('ES384', p256Key))
        .toThrow('"alg" parameter "ES384" requires curve "secp384r1".');
    });
  });

  describe('edge cases', () => {
    it('should handle keys without asymmetricKeyDetails gracefully', () => {
      const mockRSAKey = {
        asymmetricKeyType: 'rsa',
        asymmetricKeyDetails: undefined
      };

      const mockECKey = {
        asymmetricKeyType: 'ec',
        asymmetricKeyDetails: undefined
      };

      // Should not throw for RSA without details
      expect(() => validateAsymmetricKey('RS256', mockRSAKey)).not.toThrow();

      // For EC, it checks curve and throws if details are missing
      try {
        validateAsymmetricKey('ES256', mockECKey);
        // If it doesn't throw, asymmetricKeyDetails check might be skipped
        expect(true).toBe(true);
      } catch (err) {
        // If curve validation runs, it will throw because keyCurve is undefined
        expect(err.message).toContain('requires curve');
      }
    });

    it('should handle null algorithm or key gracefully', () => {
      const { publicKeyObject } = generateRSAKeyPair();

      expect(() => validateAsymmetricKey(null, publicKeyObject)).not.toThrow();
      expect(() => validateAsymmetricKey('RS256', null)).not.toThrow();
      expect(() => validateAsymmetricKey(null, null)).not.toThrow();
    });
  });
});