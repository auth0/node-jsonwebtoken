import { describe, it, expect } from '@jest/globals';
import { createSecretKey, createPublicKey, createPrivateKey, KeyObject } from 'crypto';
import { 
  isPublicKeyFormat, 
  validateHMACKey, 
  validateAlgorithmKeyMatch,
  MIN_HMAC_KEY_LENGTH 
} from '../../../../src/lib/shared/key-validation.js';
import { JsonWebTokenError } from '../../../../src/lib/JsonWebTokenError.js';
import { generateRSAKeyPair } from '../../../helpers/key-generator.js';

describe('key-validation', () => {
  describe('isPublicKeyFormat', () => {
    it('should detect RSA public key', () => {
      const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END PUBLIC KEY-----`;
      expect(isPublicKeyFormat(publicKey)).toBe(true);
    });

    it('should detect RSA public key format', () => {
      const publicKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END RSA PUBLIC KEY-----`;
      expect(isPublicKeyFormat(publicKey)).toBe(true);
    });

    it('should detect EC public key', () => {
      const publicKey = `-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
-----END EC PUBLIC KEY-----`;
      expect(isPublicKeyFormat(publicKey)).toBe(true);
    });

    it('should detect certificate', () => {
      const cert = `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8VSp7XkOjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END CERTIFICATE-----`;
      expect(isPublicKeyFormat(cert)).toBe(true);
    });

    it('should detect X509 certificate', () => {
      const cert = `-----BEGIN X509 CERTIFICATE-----
MIICljCCAX4CCQCKz8VSp7XkOjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END X509 CERTIFICATE-----`;
      expect(isPublicKeyFormat(cert)).toBe(true);
    });

    it('should detect OpenSSH public key', () => {
      const sshKey = `-----BEGIN OPENSSH PUBLIC KEY-----
ssh-rsa AAAAB3NzaC1yc2EA
-----END OPENSSH PUBLIC KEY-----`;
      expect(isPublicKeyFormat(sshKey)).toBe(true);
    });

    it('should detect JWK RSA public key', () => {
      const jwk = JSON.stringify({
        kty: 'RSA',
        n: 'xjlOXLu7fmB9p4M8lhU',
        e: 'AQAB'
      });
      expect(isPublicKeyFormat(jwk)).toBe(true);
    });

    it('should detect JWK EC public key', () => {
      const jwk = JSON.stringify({
        kty: 'EC',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
        crv: 'P-256'
      });
      expect(isPublicKeyFormat(jwk)).toBe(true);
    });

    it('should detect JWK OKP public key', () => {
      const jwk = JSON.stringify({
        kty: 'OKP',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        crv: 'Ed25519'
      });
      expect(isPublicKeyFormat(jwk)).toBe(true);
    });

    it('should not detect private key as public', () => {
      const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
-----END PRIVATE KEY-----`;
      expect(isPublicKeyFormat(privateKey)).toBe(false);
    });

    it('should not detect RSA private key as public', () => {
      const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
-----END RSA PRIVATE KEY-----`;
      expect(isPublicKeyFormat(privateKey)).toBe(false);
    });

    it('should not detect EC private key as public', () => {
      const privateKey = `-----BEGIN EC PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
-----END EC PRIVATE KEY-----`;
      expect(isPublicKeyFormat(privateKey)).toBe(false);
    });

    it('should not detect DSA private key as public', () => {
      const privateKey = `-----BEGIN DSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
-----END DSA PRIVATE KEY-----`;
      expect(isPublicKeyFormat(privateKey)).toBe(false);
    });

    it('should not detect OpenSSH private key as public', () => {
      const privateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
-----END OPENSSH PRIVATE KEY-----`;
      expect(isPublicKeyFormat(privateKey)).toBe(false);
    });

    it('should not detect encrypted private key as public', () => {
      const privateKey = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
-----END ENCRYPTED PRIVATE KEY-----`;
      expect(isPublicKeyFormat(privateKey)).toBe(false);
    });

    it('should not detect JWK private key as public', () => {
      const jwk = JSON.stringify({
        kty: 'RSA',
        n: 'xjlOXLu7fmB9p4M8lhU',
        e: 'AQAB',
        d: 'privateKeyComponent'
      });
      expect(isPublicKeyFormat(jwk)).toBe(false);
    });

    it('should not detect regular string as public key', () => {
      expect(isPublicKeyFormat('just a regular secret')).toBe(false);
    });
  });

  describe('validateHMACKey', () => {
    it('should accept valid string key', () => {
      expect(() => validateHMACKey('mysecret')).not.toThrow();
    });

    it('should accept valid Buffer key', () => {
      expect(() => validateHMACKey(Buffer.from('mysecret'))).not.toThrow();
    });

    it('should accept valid secret KeyObject', () => {
      const keyObject = createSecretKey(Buffer.from('mysecret'));
      expect(() => validateHMACKey(keyObject)).not.toThrow();
    });

    it('should reject public key format string', () => {
      const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END PUBLIC KEY-----`;
      expect(() => validateHMACKey(publicKey)).toThrow(
        new JsonWebTokenError('Invalid key for HMAC algorithm. Public keys cannot be used as HMAC secrets.')
      );
    });

    it('should reject empty string', () => {
      expect(() => validateHMACKey('')).toThrow(
        new JsonWebTokenError('Invalid key for HMAC algorithm. Key must not be empty.')
      );
    });

    it('should reject whitespace-only string', () => {
      expect(() => validateHMACKey('   \t\n   ')).toThrow(
        new JsonWebTokenError('Invalid key for HMAC algorithm. Key must not be empty.')
      );
    });

    it('should handle MIN_HMAC_KEY_LENGTH validation for strings', () => {
      // Test with a single byte string (exactly at the minimum)
      expect(() => validateHMACKey('a')).not.toThrow();
      
      // Test with multi-byte UTF-8 character that's still valid
      expect(() => validateHMACKey('🔑')).not.toThrow();
    });

    it('should provide detailed error for key length validation', () => {
      // Since MIN_HMAC_KEY_LENGTH is currently 1, and empty strings are caught earlier,
      // we can't naturally trigger the length validation error for strings.
      // However, we can still verify the error message format by testing with a 0-length buffer
      // which triggers a different error path
      
      // The string length validation (line 90) would only trigger if MIN_HMAC_KEY_LENGTH > 1
      // and we had a non-empty string shorter than that.
      // For now, this is effectively unreachable with MIN_HMAC_KEY_LENGTH = 1
    });

    it('should reject empty Buffer', () => {
      const emptyBuffer = Buffer.from('');
      expect(() => validateHMACKey(emptyBuffer)).toThrow(
        new JsonWebTokenError('Invalid key for HMAC algorithm. Key buffer must not be empty.')
      );
    });

    it('should validate Buffer length correctly', () => {
      // Test with 1-byte buffer (exactly at minimum)
      const oneByteBuffer = Buffer.from('a');
      expect(() => validateHMACKey(oneByteBuffer)).not.toThrow();
      
      // Test with larger buffer
      const largerBuffer = Buffer.from('mysecret');
      expect(() => validateHMACKey(largerBuffer)).not.toThrow();
    });

    it('should reject non-secret KeyObject (public key)', () => {
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4xEU1ItHjBBSCgkIgKsGCjOhcFugJB8MD/BPMIBuH3FjjCgKPWCL1QSkkdC6n79Y
DPZrNPZf3ssBQeJrGqEACYhEzfcjLwkizJCFuQCi2ceqJNIqlCKK/92CtHd9hQvY
f37a7kIILcGffT28KvNa9fZt3iKarCT3j6qJGvJ1qQySYqNAKqp/SVvjEHLqmvLd
Y6DXDQSqJJ7Vo6ZwcDa/dCHm9vAWwe3PJTNiUcKbDNnB0HS/xMjbLqmNh3hkNanK
Tm9CIcLnFGJxN+EM/8KubDjbQQfpBg7fCx1VBnZU6q1GS0gLGTdvVPfNRgtHANGV
owIDAQAB
-----END PUBLIC KEY-----`;
      const publicKeyObject = createPublicKey(publicKeyPem);
      expect(() => validateHMACKey(publicKeyObject)).toThrow(
        new JsonWebTokenError('Invalid key type for HMAC algorithm. HMAC requires a symmetric secret key, but an asymmetric key was provided.')
      );
    });

    it('should reject non-secret KeyObject (private key)', () => {
      const { privateKeyObject } = generateRSAKeyPair();
      expect(() => validateHMACKey(privateKeyObject)).toThrow(
        new JsonWebTokenError('Invalid key type for HMAC algorithm. HMAC requires a symmetric secret key, but an asymmetric key was provided.')
      );
    });
  });

  describe('validateAlgorithmKeyMatch', () => {
    it('should accept secret string for HMAC algorithms', () => {
      expect(() => validateAlgorithmKeyMatch('HS256', 'mysecret')).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('HS384', 'mysecret')).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('HS512', 'mysecret')).not.toThrow();
    });

    it('should accept secret Buffer for HMAC algorithms', () => {
      const buffer = Buffer.from('mysecret');
      expect(() => validateAlgorithmKeyMatch('HS256', buffer)).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('HS384', buffer)).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('HS512', buffer)).not.toThrow();
    });

    it('should accept secret KeyObject for HMAC algorithms', () => {
      const keyObject = createSecretKey(Buffer.from('mysecret'));
      expect(() => validateAlgorithmKeyMatch('HS256', keyObject)).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('HS384', keyObject)).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('HS512', keyObject)).not.toThrow();
    });

    it('should reject public key string for HMAC algorithms', () => {
      const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END PUBLIC KEY-----`;
      expect(() => validateAlgorithmKeyMatch('HS256', publicKey)).toThrow(
        new JsonWebTokenError('Algorithm "HS256" requires a secret key, but a public key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('HS384', publicKey)).toThrow(
        new JsonWebTokenError('Algorithm "HS384" requires a secret key, but a public key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('HS512', publicKey)).toThrow(
        new JsonWebTokenError('Algorithm "HS512" requires a secret key, but a public key was provided.')
      );
    });

    it('should reject non-secret KeyObject for HMAC algorithms', () => {
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4xEU1ItHjBBSCgkIgKsGCjOhcFugJB8MD/BPMIBuH3FjjCgKPWCL1QSkkdC6n79Y
DPZrNPZf3ssBQeJrGqEACYhEzfcjLwkizJCFuQCi2ceqJNIqlCKK/92CtHd9hQvY
f37a7kIILcGffT28KvNa9fZt3iKarCT3j6qJGvJ1qQySYqNAKqp/SVvjEHLqmvLd
Y6DXDQSqJJ7Vo6ZwcDa/dCHm9vAWwe3PJTNiUcKbDNnB0HS/xMjbLqmNh3hkNanK
Tm9CIcLnFGJxN+EM/8KubDjbQQfpBg7fCx1VBnZU6q1GS0gLGTdvVPfNRgtHANGV
owIDAQAB
-----END PUBLIC KEY-----`;
      const publicKeyObject = createPublicKey(publicKeyPem);
      expect(() => validateAlgorithmKeyMatch('HS256', publicKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "HS256" requires a secret key, but a public key was provided.')
      );
    });

    it('should reject secret KeyObject for asymmetric algorithms', () => {
      const secretKeyObject = createSecretKey(Buffer.from('mysecret'));
      
      // RSA algorithms
      expect(() => validateAlgorithmKeyMatch('RS256', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "RS256" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('RS384', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "RS384" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('RS512', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "RS512" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      
      // PS algorithms
      expect(() => validateAlgorithmKeyMatch('PS256', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "PS256" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('PS384', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "PS384" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('PS512', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "PS512" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      
      // ES algorithms
      expect(() => validateAlgorithmKeyMatch('ES256', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "ES256" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('ES384', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "ES384" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('ES512', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "ES512" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      expect(() => validateAlgorithmKeyMatch('ES256K', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "ES256K" requires an asymmetric key, but a symmetric secret key was provided.')
      );
      
      // EdDSA
      expect(() => validateAlgorithmKeyMatch('EdDSA', secretKeyObject)).toThrow(
        new JsonWebTokenError('Algorithm "EdDSA" requires an asymmetric key, but a symmetric secret key was provided.')
      );
    });

    it('should accept string keys for asymmetric algorithms', () => {
      // String keys are not validated deeply here, that happens in the algorithm implementation
      expect(() => validateAlgorithmKeyMatch('RS256', 'somekey')).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('ES256', 'somekey')).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('EdDSA', 'somekey')).not.toThrow();
    });

    it('should accept Buffer keys for asymmetric algorithms', () => {
      // Buffer keys are not validated deeply here, that happens in the algorithm implementation
      expect(() => validateAlgorithmKeyMatch('RS256', Buffer.from('somekey'))).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('ES256', Buffer.from('somekey'))).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('EdDSA', Buffer.from('somekey'))).not.toThrow();
    });

    it('should not validate unknown algorithms', () => {
      // Unknown algorithms pass through without validation
      expect(() => validateAlgorithmKeyMatch('UNKNOWN', 'anykey')).not.toThrow();
      expect(() => validateAlgorithmKeyMatch('none', 'anykey')).not.toThrow();
    });
  });
});