/// <reference path="../types/jest.d.ts" />

import { describe, it, expect, jest } from '@jest/globals';
import {
  prepareSignContext,
  prepareSecret,
  validateKey,
  createSignature,
  validateOptions,
  validatePayload,
  validate,
  sign_options_schema,
  registered_claims_schema
} from '../../src/lib/shared/sign-core';
import { KeyObject, createPrivateKey, createSecretKey } from 'crypto';
import { generateRSAKeyPair, generateECKeyPair, generateEd25519KeyPair, generateSmallRSAKeyPair } from '../helpers/key-generator';

describe('Sign Core Functions', () => {
  describe('validate()', () => {
    it('should throw if object is not a plain object', () => {
      expect(() => validate(sign_options_schema, false, null, 'options'))
        .toThrow('Expected "options" to be a plain object.');
      
      expect(() => validate(sign_options_schema, false, 'string', 'options'))
        .toThrow('Expected "options" to be a plain object.');
      
      expect(() => validate(sign_options_schema, false, [], 'options'))
        .toThrow('Expected "options" to be a plain object.');
    });

    it('should throw for unknown properties when allowUnknown is false', () => {
      expect(() => validate(sign_options_schema, false, { unknownProp: 'value' }, 'options'))
        .toThrow('"unknownProp" is not allowed in "options"');
    });

    it('should allow unknown properties when allowUnknown is true', () => {
      expect(() => validate(sign_options_schema, true, { unknownProp: 'value' }, 'options'))
        .not.toThrow();
    });

    it('should validate all sign options schema properties', () => {
      // Test invalid values for each option
      expect(() => validateOptions({ expiresIn: null }))
        .toThrow('"expiresIn" should be a number of seconds or string representing a timespan');
      
      expect(() => validateOptions({ notBefore: null }))
        .toThrow('"notBefore" should be a number of seconds or string representing a timespan');
      
      expect(() => validateOptions({ audience: 123 }))
        .toThrow('"audience" must be a string or array');
      
      expect(() => validateOptions({ algorithm: 'INVALID' as any }))
        .toThrow('"algorithm" must be a valid string enum value');
      
      expect(() => validateOptions({ header: 'string' as any }))
        .toThrow('"header" must be an object');
      
      expect(() => validateOptions({ encoding: 123 as any }))
        .toThrow('"encoding" must be a string');
      
      expect(() => validateOptions({ issuer: 123 as any }))
        .toThrow('"issuer" must be a string');
      
      expect(() => validateOptions({ subject: 123 as any }))
        .toThrow('"subject" must be a string');
      
      expect(() => validateOptions({ jwtid: 123 as any }))
        .toThrow('"jwtid" must be a string');
      
      expect(() => validateOptions({ noTimestamp: 'string' as any }))
        .toThrow('"noTimestamp" must be a boolean');
      
      expect(() => validateOptions({ keyid: 123 as any }))
        .toThrow('"keyid" must be a string');
      
      expect(() => validateOptions({ mutatePayload: 'string' as any }))
        .toThrow('"mutatePayload" must be a boolean');
      
      expect(() => validateOptions({ allowInsecureKeySizes: 'string' as any }))
        .toThrow('"allowInsecureKeySizes" must be a boolean');
      
      expect(() => validateOptions({ allowInvalidAsymmetricKeyTypes: 'string' as any }))
        .toThrow('"allowInvalidAsymmetricKeyTypes" must be a boolean');
      
      expect(() => validateOptions({ allowInsecureNoneAlgorithm: 'string' as any }))
        .toThrow('"allowInsecureNoneAlgorithm" must be a boolean');
    });
  });

  describe('prepareSignContext()', () => {
    it('should throw if payload is undefined', () => {
      expect(() => prepareSignContext(undefined as any, 'secret'))
        .toThrow('payload is required');
    });

    it('should throw if payload is not a plain object, string, or Buffer', () => {
      expect(() => prepareSignContext(123 as any, 'secret'))
        .toThrow('Expected "payload" to be a plain object.');
        
      expect(() => prepareSignContext(null as any, 'secret'))
        .toThrow('Expected "payload" to be a plain object.');
        
      expect(() => prepareSignContext([] as any, 'secret'))
        .toThrow('Expected "payload" to be a plain object.');
    });

    it('should throw if object payload has exp and expiresIn option', () => {
      expect(() => prepareSignContext({ exp: 1234567890 }, 'secret', { expiresIn: '1h' }))
        .toThrow('Bad "options.expiresIn" option the payload already has an "exp" property.');
    });

    it('should throw if object payload has nbf and notBefore option', () => {
      expect(() => prepareSignContext({ nbf: 1234567890 }, 'secret', { notBefore: '1h' }))
        .toThrow('Bad "options.notBefore" option the payload already has an "nbf" property.');
    });

    it('should throw if string/Buffer payload has object-only options', () => {
      expect(() => prepareSignContext('string payload', 'secret', { audience: 'test' }))
        .toThrow('invalid audience option for string payload');
      
      expect(() => prepareSignContext(Buffer.from('buffer'), 'secret', { expiresIn: '1h' }))
        .toThrow('invalid expiresIn option for object payload');
    });

    it('should use mutatePayload option correctly', () => {
      const originalPayload = { test: 'data' };
      const context1 = prepareSignContext(originalPayload, 'secret', { mutatePayload: true });
      expect(context1.payload).toBe(originalPayload);
      
      const context2 = prepareSignContext(originalPayload, 'secret', { mutatePayload: false });
      expect(context2.payload).not.toBe(originalPayload);
      expect(context2.payload).toEqual(originalPayload);
    });

    it('should throw for none algorithm without allowInsecureNoneAlgorithm', () => {
      expect(() => prepareSignContext({ test: 'data' }, '', { algorithm: 'none' }))
        .toThrow('The "none" algorithm is insecure and disabled by default');
    });

    it('should warn for none algorithm with allowInsecureNoneAlgorithm', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      prepareSignContext({ test: 'data' }, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true 
      });
      
      expect(consoleSpy).toHaveBeenCalledWith('WARNING: JWT signed with "none" algorithm - this token has NO security!');
      consoleSpy.mockRestore();
    });

    it('should throw if secret missing for non-none algorithm', () => {
      expect(() => prepareSignContext({ test: 'data' }, ''))
        .toThrow('secretOrPrivateKey must have a value');
    });

    it('should add custom header fields', () => {
      const context = prepareSignContext({ test: 'data' }, 'secret', {
        header: { custom: 'value' }
      });
      expect(context.header.custom).toBe('value');
    });
  });

  describe('prepareSecret()', () => {
    it('should throw if secret is empty string', () => {
      expect(() => prepareSecret(''))
        .toThrow('secretOrPrivateKey must have a value');
      
      expect(() => prepareSecret('   '))
        .toThrow('secretOrPrivateKey must have a value');
    });

    it('should throw if secret is falsy', () => {
      expect(() => prepareSecret(null as any))
        .toThrow('secretOrPrivateKey must have a value');
        
      expect(() => prepareSecret(undefined as any))
        .toThrow('secretOrPrivateKey must have a value');
    });

    it('should handle key objects with invalid key property', () => {
      expect(() => prepareSecret({ key: '' } as any))
        .toThrow('secretOrPrivateKey.key must have a value');
      
      expect(() => prepareSecret({ key: '   ' } as any))
        .toThrow('secretOrPrivateKey.key must have a value');
      
      expect(() => prepareSecret({ key: 123 } as any))
        .toThrow('secretOrPrivateKey.key must have a value');
      
      expect(() => prepareSecret({} as any))
        .toThrow('secretOrPrivateKey.key must have a value');
    });

    it('should create private key from object', () => {
      const rsaKeys = generateRSAKeyPair();
      const key = prepareSecret({ 
        key: rsaKeys.privateKey
      } as any);
      expect(key).toBeInstanceOf(KeyObject);
    });

    it('should handle Buffer for EdDSA algorithm', () => {
      const edKeys = generateEd25519KeyPair();
      const privateKeyBuffer = Buffer.from(edKeys.privateKey);
      const key = prepareSecret(privateKeyBuffer, 'EdDSA');
      expect(key).toBeInstanceOf(KeyObject);
    });

    it('should handle Buffer for ES algorithms', () => {
      const ecKeys = generateECKeyPair();
      const privateKeyBuffer = Buffer.from(ecKeys.privateKey);
      const key = prepareSecret(privateKeyBuffer, 'ES256');
      expect(key).toBeInstanceOf(KeyObject);
    });

    it('should create secret key from Buffer for other algorithms', () => {
      const buffer = Buffer.from('secret');
      const key = prepareSecret(buffer, 'HS256');
      expect(key).toBeInstanceOf(KeyObject);
    });
  });

  describe('validateKey()', () => {
    it('should throw for ES algorithms with non-EC key', () => {
      const rsaKeys = generateRSAKeyPair();
      expect(() => validateKey('ES256', rsaKeys.privateKeyObject, {}))
        .toThrow('Invalid key for ECDSA algorithms');
    });

    it('should accept valid EC key for ES algorithms', () => {
      const ecKeys = generateECKeyPair();
      expect(() => validateKey('ES256', ecKeys.privateKeyObject, {}))
        .not.toThrow();
    });

    it('should throw for EdDSA with invalid key type', () => {
      const rsaKeys = generateRSAKeyPair();
      expect(() => validateKey('EdDSA', rsaKeys.privateKeyObject, {}))
        .toThrow('Invalid key for EdDSA algorithm');
    });

    it('should accept valid EdDSA key types', () => {
      const edKeys = generateEd25519KeyPair();
      expect(() => validateKey('EdDSA', edKeys.privateKeyObject, {}))
        .not.toThrow();
    });

    it('should validate asymmetric key when allowInvalidAsymmetricKeyTypes is false', () => {
      const rsaKeys = generateRSAKeyPair();
      // This should call validateAsymmetricKey internally
      expect(() => validateKey('RS256', rsaKeys.privateKeyObject, { allowInvalidAsymmetricKeyTypes: false }))
        .not.toThrow();
    });

    it('should propagate validateAsymmetricKey errors for small RSA keys', () => {
      const smallRSAKeys = generateSmallRSAKeyPair();
      expect(() => validateKey('RS256', smallRSAKeys.privateKey, {}))
        .toThrow('minimum RSA key size is 2048 bits');
    });

  });

  describe('createSignature()', () => {
    it('should throw for invalid expiresIn timespan', () => {
      const context = prepareSignContext({ test: 'data' }, 'secret', { expiresIn: 'invalid' });
      expect(() => createSignature(context, Date.now() / 1000))
        .toThrow('"expiresIn" should be a number of seconds or string representing a timespan');
    });

    it('should throw for invalid notBefore timespan', () => {
      const context = prepareSignContext({ test: 'data' }, 'secret', { notBefore: 'invalid' });
      expect(() => createSignature(context, Date.now() / 1000))
        .toThrow('"notBefore" should be a number of seconds or string representing a timespan');
    });


    it('should add standard claims from options', () => {
      const context = prepareSignContext({ test: 'data' }, 'secret', {
        audience: 'test-audience',
        issuer: 'test-issuer',
        subject: 'test-subject',
        jwtid: 'test-id'
      });
      
      const token = createSignature(context, Math.floor(Date.now() / 1000));
      const parts = token.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      
      expect(payload.aud).toBe('test-audience');
      expect(payload.iss).toBe('test-issuer');
      expect(payload.sub).toBe('test-subject');
      expect(payload.jti).toBe('test-id');
    });

    it('should reject non-UTF8 encoding option', () => {
      const context = prepareSignContext({ test: 'data' }, 'secret', {
        encoding: 'latin1' as any
      });
      
      // Should throw due to encoding validation
      expect(() => createSignature(context, Date.now() / 1000)).toThrow(/Only UTF-8 encoding is supported/);
    });
    
    it('should accept UTF-8 encoding option', () => {
      const context = prepareSignContext({ test: 'data' }, 'secret', {
        encoding: 'utf8'
      });
      
      // Should not throw
      expect(() => createSignature(context, Date.now() / 1000)).not.toThrow();
    });

    it('should properly set exp and nbf values when valid', () => {
      const now = Math.floor(Date.now() / 1000);
      const context = prepareSignContext({ test: 'data' }, 'secret', {
        expiresIn: 3600, // 1 hour
        notBefore: 60    // 1 minute
      });
      
      const token = createSignature(context, now);
      const parts = token.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      
      expect(payload.exp).toBe(now + 3600);
      expect(payload.nbf).toBe(now + 60);
      expect(payload.iat).toBe(now);
    });
  });

  describe('validatePayload()', () => {
    it('should validate registered claims', () => {
      expect(() => validatePayload({ iat: 'string' }))
        .toThrow('"iat" should be a number of seconds');
      
      expect(() => validatePayload({ exp: 'string' }))
        .toThrow('"exp" should be a number of seconds');
      
      expect(() => validatePayload({ nbf: 'string' }))
        .toThrow('"nbf" should be a number of seconds');
    });

    it('should allow custom claims', () => {
      expect(() => validatePayload({ customClaim: 'value' }))
        .not.toThrow();
    });
  });
});