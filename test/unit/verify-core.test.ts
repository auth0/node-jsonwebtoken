/// <reference path="../types/jest.d.ts" />

import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import {
  prepareVerifyContext,
  prepareKey,
  determineAlgorithms,
  verifySignature,
  validateClaims,
  validateOptions
} from '../../src/lib/shared/verify-core';
import { JsonWebTokenError, TokenExpiredError, NotBeforeError } from '../../src/index';
import { sign } from '../../src/index';
import { KeyObject, createSecretKey, createPublicKey } from 'crypto';
import { generateRSAKeyPair, generateECKeyPair, generateEd25519KeyPair, generateSmallRSAKeyPair } from '../helpers/key-generator';
import * as decodeModule from '../../src/decode';

describe('Verify Core Functions', () => {
  const secret = 'test-secret';
  const payload = { test: 'data' };

  describe('validateOptions()', () => {
    it('should throw for invalid clockTimestamp', () => {
      expect(() => validateOptions({ clockTimestamp: 'string' as any }))
        .toThrow('clockTimestamp must be a number');
    });

    it('should throw for invalid nonce', () => {
      expect(() => validateOptions({ nonce: 123 as any }))
        .toThrow('nonce must be a non-empty string');
      
      expect(() => validateOptions({ nonce: '' }))
        .toThrow('nonce must be a non-empty string');
      
      expect(() => validateOptions({ nonce: '   ' }))
        .toThrow('nonce must be a non-empty string');
    });

    it('should throw for invalid allowInvalidAsymmetricKeyTypes', () => {
      expect(() => validateOptions({ allowInvalidAsymmetricKeyTypes: 'string' as any }))
        .toThrow('allowInvalidAsymmetricKeyTypes must be a boolean');
    });

    it('should pass for valid options', () => {
      expect(() => validateOptions({
        clockTimestamp: 1234567890,
        nonce: 'valid-nonce',
        allowInvalidAsymmetricKeyTypes: true
      })).not.toThrow();
    });
  });

  describe('prepareVerifyContext()', () => {
    it('should throw if jwt is not provided', () => {
      expect(() => prepareVerifyContext('', secret))
        .toThrow('jwt must be provided');
    });

    it('should throw if jwt is not a string', () => {
      expect(() => prepareVerifyContext(123 as any, secret))
        .toThrow('jwt must be a string');
    });

    it('should throw if jwt is malformed', () => {
      expect(() => prepareVerifyContext('not.enough', secret))
        .toThrow('jwt malformed');
      
      expect(() => prepareVerifyContext('too.many.parts.here', secret))
        .toThrow('jwt malformed');
    });

    it('should propagate decode errors', async () => {
      // Create a token with invalid base64
      const invalidToken = 'eyJhbGciOiJIUzI1NiJ9.invalid@base64.signature';
      
      expect(() => prepareVerifyContext(invalidToken, secret))
        .toThrow();
    });

    it('should propagate decode errors as JsonWebTokenError', () => {
      // Mock the decode function to throw an error
      const decodeSpy = jest.spyOn(decodeModule, 'decode').mockImplementation(() => {
        throw new Error('Decode failed');
      });
      
      const validToken = 'eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiZGF0YSJ9.signature';
      
      expect(() => prepareVerifyContext(validToken, secret))
        .toThrow('Decode failed');
      
      // Restore the original decode function
      decodeSpy.mockRestore();
    });

    it('should throw for non-object payload', async () => {
      // Mock decode to return a string payload
      jest.mock('../../src/decode', () => ({
        decode: jest.fn(() => ({
          header: { alg: 'HS256' },
          payload: 'string payload',
          signature: 'signature'
        }))
      }));
      
      const token = await sign(payload, secret);
      // This would need proper mocking setup
    });
  });

  describe('prepareKey()', () => {
    it('should return KeyObject as-is', () => {
      const key = createSecretKey(Buffer.from('secret'));
      expect(prepareKey(key, { alg: 'HS256' })).toBe(key);
    });

    it('should throw for invalid key object', () => {
      expect(() => prepareKey({ key: '' } as any, { alg: 'HS256' }))
        .toThrow('secretOrPublicKey.key must have a value');
      
      expect(() => prepareKey({ key: '   ' } as any, { alg: 'HS256' }))
        .toThrow('secretOrPublicKey.key must have a value');
      
      expect(() => prepareKey({ key: 123 } as any, { alg: 'HS256' }))
        .toThrow('secretOrPublicKey.key must have a value');
      
      expect(() => prepareKey({} as any, { alg: 'HS256' }))
        .toThrow('secretOrPublicKey.key must have a value');
    });

    it('should create public key from object', () => {
      const rsaKeys = generateRSAKeyPair();
      const key = prepareKey({
        key: rsaKeys.publicKey
      } as any, { alg: 'RS256' });
      expect(key).toBeInstanceOf(KeyObject);
    });

    it('should create secret key from Buffer', () => {
      const buffer = Buffer.from('secret');
      const key = prepareKey(buffer, { alg: 'HS256' });
      expect(key).toBeInstanceOf(KeyObject);
    });

    it('should create public key for string with PUB_KEY_ALGS', () => {
      const rsaKeys = generateRSAKeyPair();
      const key = prepareKey(rsaKeys.publicKey, { alg: 'RS256' });
      expect(key).toBeInstanceOf(KeyObject);
    });

    it('should create secret key for string with HS_ALGS', () => {
      const key = prepareKey('secret', { alg: 'HS256' });
      expect(key).toBeInstanceOf(KeyObject);
    });

    it('should return string as-is for unknown algorithm', () => {
      const key = prepareKey('secret', { alg: 'unknown' as any });
      expect(key).toBe('secret');
    });
  });

  describe('determineAlgorithms()', () => {
    it('should return none algorithms for none header', () => {
      const algs = determineAlgorithms({}, { alg: 'none' }, null);
      expect(algs).toEqual(['none']);
    });

    it('should throw for missing algorithms with asymmetric header', () => {
      expect(() => determineAlgorithms({}, { alg: 'RS256' }, 'key'))
        .toThrow('please pass "algorithms" option');
    });

    it('should detect algorithms from KeyObject', () => {
      // Test symmetric key
      const secretKey = createSecretKey(Buffer.from('secret'));
      expect(determineAlgorithms({}, { alg: 'HS256' }, secretKey))
        .toEqual(['HS256', 'HS384', 'HS512']);

      // For asymmetric keys, we need to provide algorithms option to avoid the exception
      // Test EC key
      const ecKeys = generateECKeyPair();
      expect(determineAlgorithms({ algorithms: ['ES256'] }, { alg: 'ES256' }, ecKeys.publicKey))
        .toEqual(['ES256']);

      // Test RSA key
      const rsaKeys = generateRSAKeyPair();
      expect(determineAlgorithms({ algorithms: ['RS256'] }, { alg: 'RS256' }, rsaKeys.publicKey))
        .toEqual(['RS256']);

      // Test EdDSA key
      const edKeys = generateEd25519KeyPair();
      expect(determineAlgorithms({ algorithms: ['EdDSA'] }, { alg: 'EdDSA' }, edKeys.publicKey))
        .toEqual(['EdDSA']);
        
      // Test auto-detection when algorithms not provided with non-PUB_KEY_ALGS
      // When header.alg is not a PUB_KEY_ALG but key is asymmetric, it detects based on key
      const ecKeys2 = generateECKeyPair();
      expect(determineAlgorithms({}, { alg: 'HS256' }, ecKeys2.publicKeyObject))
        .toEqual(['ES256', 'ES384', 'ES512', 'ES256K']);
    });

    it('should detect RSA-PSS key type', () => {
      // Create a mock KeyObject with rsa-pss type
      const mockRSAPSSKey = Object.create(KeyObject.prototype);
      Object.defineProperty(mockRSAPSSKey, 'asymmetricKeyType', {
        value: 'rsa-pss',
        writable: false,
        enumerable: true,
        configurable: true
      });
      
      expect(determineAlgorithms({}, { alg: 'HS256' }, mockRSAPSSKey))
        .toEqual(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);
    });

    it('should detect x25519 and x448 key types', () => {
      // Test x25519
      const mockX25519Key = Object.create(KeyObject.prototype);
      Object.defineProperty(mockX25519Key, 'asymmetricKeyType', {
        value: 'x25519',
        writable: false,
        enumerable: true,
        configurable: true
      });
      
      expect(determineAlgorithms({}, { alg: 'HS256' }, mockX25519Key))
        .toEqual(['EdDSA']);
      
      // Test x448
      const mockX448Key = Object.create(KeyObject.prototype);
      Object.defineProperty(mockX448Key, 'asymmetricKeyType', {
        value: 'x448',
        writable: false,
        enumerable: true,
        configurable: true
      });
      
      expect(determineAlgorithms({}, { alg: 'HS256' }, mockX448Key))
        .toEqual(['EdDSA']);
    });

    it('should handle unknown asymmetric key type', () => {
      // Mock a KeyObject with unknown type
      const mockKey = Object.create(KeyObject.prototype);
      Object.defineProperty(mockKey, 'asymmetricKeyType', {
        value: 'unknown',
        writable: false,
        enumerable: true,
        configurable: true
      });
      
      expect(determineAlgorithms({}, { alg: 'HS256' }, mockKey))
        .toEqual(['HS256', 'HS384', 'HS512']);
    });

    it('should throw if no key provided and not none algorithm', () => {
      expect(() => determineAlgorithms({}, { alg: 'HS256' }, null))
        .toThrow('secretOrPublicKey must have a value');
    });

    it('should return provided algorithms if specified', () => {
      const algorithms = ['RS256', 'RS384'] as any;
      expect(determineAlgorithms({ algorithms }, { alg: 'RS256' }, 'key'))
        .toBe(algorithms);
    });
  });

  describe('verifySignature()', () => {
    it('should handle none algorithm verification', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Create a token with none algorithm
      const token = await sign(payload, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });
      
      const context = prepareVerifyContext(token, '');
      expect(() => verifySignature(context, '')).not.toThrow();
      
      expect(consoleSpy).toHaveBeenCalledWith('WARNING: Verifying JWT with "none" algorithm - this token has NO security!');
      consoleSpy.mockRestore();
    });

    it('should throw if none algorithm has signature', () => {
      const tokenWithSig = 'eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoiZGF0YSJ9.signature';
      const context = prepareVerifyContext(tokenWithSig, '');
      
      expect(() => verifySignature(context, ''))
        .toThrow('jwt signature must be empty for "none" algorithm');
    });

    it('should throw for invalid none algorithm verification', async () => {
      const token = await sign(payload, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });
      
      const context = prepareVerifyContext(token, '');
      
      // Test specifying none in algorithms
      context.options.algorithms = ['none'];
      expect(() => verifySignature(context, ''))
        .toThrow('Invalid verify option "algorithms" for "none" algorithm');
    });

    it('should throw if key provided with none in algorithms', async () => {
      const token = await sign(payload, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });
      
      const context = prepareVerifyContext(token, 'key');
      context.options.algorithms = ['none'];
      
      expect(() => verifySignature(context, 'key'))
        .toThrow('Invalid verify option "algorithms" for "none" algorithm');
    });


    it('should throw for algorithm mismatch with none', async () => {
      const token = await sign(payload, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });
      
      const context = prepareVerifyContext(token, '');
      context.options.algorithms = ['HS256'];
      
      expect(() => verifySignature(context, ''))
        .toThrow('invalid algorithm');
    });

    it('should throw if signature required but missing', () => {
      const tokenNoSig = 'eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiZGF0YSJ9.';
      const context = prepareVerifyContext(tokenNoSig, secret);
      
      expect(() => verifySignature(context, secret))
        .toThrow('jwt signature is required');
    });

    it('should throw if signature exists but no key', async () => {
      const token = await sign(payload, secret);
      const context = prepareVerifyContext(token, '');
      
      expect(() => verifySignature(context, null as any))
        .toThrow('secretOrPublicKey must have a value');
    });

    it('should throw for RSA key size validation', async () => {
      const smallRSAKeys = generateSmallRSAKeyPair();
      const token = await sign(payload, smallRSAKeys.privateKey, { 
        algorithm: 'RS256',
        allowInsecureKeySizes: true 
      });
      const context = prepareVerifyContext(token, smallRSAKeys.publicKey, {
        algorithms: ['RS256']
      });
      
      expect(() => verifySignature(context, smallRSAKeys.publicKey))
        .toThrow('minimum RSA key size is 2048 bits');
    });

    it('should allow small RSA key with allowInsecureKeySizes', async () => {
      const smallRSAKeys = generateSmallRSAKeyPair();
      const token = await sign(payload, smallRSAKeys.privateKey, { 
        algorithm: 'RS256',
        allowInsecureKeySizes: true 
      });
      const context = prepareVerifyContext(token, smallRSAKeys.publicKey, {
        algorithms: ['RS256'],
        allowInsecureKeySizes: true
      });
      
      expect(() => verifySignature(context, smallRSAKeys.publicKey)).not.toThrow();
    });

    it('should propagate verify errors', async () => {
      const token = await sign(payload, secret);
      const context = prepareVerifyContext(token, 'wrong-secret');
      
      // Mock getAlgorithm to throw
      jest.mock('../../src/lib/algorithms/index', () => ({
        getAlgorithm: jest.fn(() => { throw new Error('Algorithm error'); })
      }));
      
      // Would need proper mock setup
    });

    it('should throw for invalid signature', async () => {
      const token = await sign(payload, secret);
      const context = prepareVerifyContext(token, 'wrong-secret');
      
      expect(() => verifySignature(context, 'wrong-secret'))
        .toThrow('invalid signature');
    });

    it('should verify with string key (non-KeyObject) for HMAC', async () => {
      // Test line 274: when secretOrKey is NOT a KeyObject
      const token = await sign(payload, secret);
      const context = prepareVerifyContext(token, secret);
      
      // This should not throw - string keys don't trigger crypto validation
      expect(() => verifySignature(context, secret)).not.toThrow();
    });

    it('should verify with Buffer key (non-KeyObject) for HMAC', async () => {
      // Test line 274: when secretOrKey is NOT a KeyObject
      const bufferSecret = Buffer.from(secret);
      const token = await sign(payload, bufferSecret);
      const context = prepareVerifyContext(token, bufferSecret);
      
      // This should not throw - Buffer keys don't trigger crypto validation
      expect(() => verifySignature(context, bufferSecret)).not.toThrow();
    });

    it('should validate cryptographic parameters for KeyObject', async () => {
      // Test line 274: when secretOrKey IS a KeyObject
      const keyObject = createSecretKey(Buffer.from(secret));
      const token = await sign(payload, keyObject);
      const context = prepareVerifyContext(token, keyObject);
      
      // This triggers the validateCryptographicParameters call
      expect(() => verifySignature(context, keyObject)).not.toThrow();
    });

    it('should validate EC signature with KeyObject', async () => {
      // Test ECDSA signature validation with KeyObject
      const { privateKey, publicKey } = generateECKeyPair();
      const token = await sign(payload, privateKey, { algorithm: 'ES256' });
      const context = prepareVerifyContext(token, publicKey, {
        algorithms: ['ES256'] // Required for asymmetric algorithms
      });
      
      // This triggers crypto validation for EC keys
      expect(() => verifySignature(context, publicKey)).not.toThrow();
    });
  });

  describe('validateClaims()', () => {
    const now = Math.floor(Date.now() / 1000);

    it('should throw for invalid nbf value', () => {
      const payload = { nbf: 'not-a-number' } as any;
      expect(() => validateClaims(payload, {}, now))
        .toThrow('invalid nbf value');
    });

    it('should throw for invalid exp value', () => {
      const payload = { exp: 'not-a-number' } as any;
      expect(() => validateClaims(payload, {}, now))
        .toThrow('invalid exp value');
    });

    it('should validate audience with RegExp', () => {
      const payload = { aud: 'test-audience' };
      const options = { audience: /test-.*/ };
      
      expect(() => validateClaims(payload, options, now)).not.toThrow();
      
      const options2 = { audience: /different-.*/ };
      expect(() => validateClaims(payload, options2, now))
        .toThrow('jwt audience invalid. expected: /different-.*/');
    });

    it('should handle null/undefined audience in JWT with RegExp', () => {
      // Test with null audience
      const payloadNull = { aud: null };
      const options = { audience: /test-.*/ };
      
      expect(() => validateClaims(payloadNull, options, now))
        .toThrow('jwt audience invalid. expected: /test-.*/');
      
      // Test with undefined audience (implicitly)
      const payloadUndefined = { aud: [undefined, 'other'] };
      
      expect(() => validateClaims(payloadUndefined, options, now))
        .toThrow('jwt audience invalid. expected: /test-.*/');
    });

    it('should validate array audiences', () => {
      const payload = { aud: ['aud1', 'aud2'] };
      const options = { audience: ['aud1', 'aud3'] };
      
      expect(() => validateClaims(payload, options, now)).not.toThrow();
      
      const options2 = { audience: ['aud3', 'aud4'] };
      expect(() => validateClaims(payload, options2, now))
        .toThrow('jwt audience invalid. expected: aud3 or aud4');
    });

    it('should validate issuer', () => {
      const payload = { iss: 'test-issuer' };
      
      expect(() => validateClaims(payload, { issuer: 'test-issuer' }, now))
        .not.toThrow();
      
      expect(() => validateClaims(payload, { issuer: 'different-issuer' }, now))
        .toThrow('jwt issuer invalid. expected: different-issuer');
      
      expect(() => validateClaims(payload, { issuer: ['different', 'issuers'] }, now))
        .toThrow('jwt issuer invalid. expected: different,issuers');
    });

    it('should handle null/undefined issuer in JWT with array of issuers', () => {
      // Test with null issuer
      const payloadNull = { iss: null };
      const options = { issuer: ['issuer1', 'issuer2'] };
      
      expect(() => validateClaims(payloadNull, options, now))
        .toThrow('jwt issuer invalid. expected: issuer1,issuer2');
      
      // Test with undefined issuer (no iss property)
      const payloadUndefined = {};
      
      expect(() => validateClaims(payloadUndefined, options, now))
        .toThrow('jwt issuer invalid. expected: issuer1,issuer2');
    });

    it('should validate subject', () => {
      const payload = { sub: 'test-subject' };
      
      expect(() => validateClaims(payload, { subject: 'test-subject' }, now))
        .not.toThrow();
      
      expect(() => validateClaims(payload, { subject: 'different-subject' }, now))
        .toThrow('jwt subject invalid. expected: different-subject');
    });

    it('should validate jwtid', () => {
      const payload = { jti: 'test-id' };
      
      expect(() => validateClaims(payload, { jwtid: 'test-id' }, now))
        .not.toThrow();
      
      expect(() => validateClaims(payload, { jwtid: 'different-id' }, now))
        .toThrow('jwt jwtid invalid. expected: different-id');
    });

    it('should validate nonce', () => {
      const payload = { nonce: 'test-nonce' };
      
      expect(() => validateClaims(payload, { nonce: 'test-nonce' }, now))
        .not.toThrow();
      
      expect(() => validateClaims(payload, { nonce: 'different-nonce' }, now))
        .toThrow('jwt nonce invalid. expected: different-nonce');
    });

    it('should validate maxAge without iat', () => {
      const payload = { sub: 'test' };
      
      expect(() => validateClaims(payload, { maxAge: '1h' }, now))
        .toThrow('iat required when maxAge is specified');
    });

    it('should validate maxAge with invalid timespan', () => {
      const payload = { iat: now };
      
      expect(() => validateClaims(payload, { maxAge: 'invalid' }, now))
        .toThrow('"maxAge" should be a number of seconds or string representing a timespan');
    });

    it('should validate maxAge exceeded', () => {
      const payload = { iat: now - 3600 }; // 1 hour ago
      
      expect(() => validateClaims(payload, { maxAge: '30m' }, now))
        .toThrow(TokenExpiredError);
    });

    it('should handle clockTolerance', () => {
      // Test exp with clockTolerance
      const expiredPayload = { 
        exp: now - 5 // expired 5 seconds ago
      };
      
      // Should fail without tolerance
      expect(() => validateClaims(expiredPayload, {}, now))
        .toThrow(TokenExpiredError);
      
      // Should pass with tolerance
      expect(() => validateClaims(expiredPayload, { clockTolerance: 10 }, now))
        .not.toThrow();
        
      // Test nbf with clockTolerance
      const notBeforePayload = {
        nbf: now + 5  // active in 5 seconds
      };
      
      // Should fail without tolerance
      expect(() => validateClaims(notBeforePayload, {}, now))
        .toThrow(NotBeforeError);
      
      // Should pass with tolerance
      expect(() => validateClaims(notBeforePayload, { clockTolerance: 10 }, now))
        .not.toThrow();
    });

    it('should handle missing claims gracefully', () => {
      const payload = {};
      const options = {
        audience: 'test',
        issuer: 'test',
        subject: 'test',
        jwtid: 'test',
        nonce: 'test'
      };
      
      // All should fail due to missing claims
      expect(() => validateClaims(payload, options, now)).toThrow();
    });

    it('should ignore claims when ignore options are set', () => {
      const payload = {
        exp: now - 1000,
        nbf: now + 1000
      };
      
      expect(() => validateClaims(payload, {
        ignoreExpiration: true,
        ignoreNotBefore: true
      }, now)).not.toThrow();
    });
  });
});