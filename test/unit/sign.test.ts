/// <reference path="../types/jest.d.ts" />

import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { sign, signSync } from '../../src/index';
import type { Algorithm } from '../../src/types';
import { 
  generateHMACSecret, 
  generateRSAKeyPair, 
  generateECKeyPair,
  generateEd25519KeyPair,
  generateKeysForAlgorithm 
} from '../helpers/key-generator';
import { 
  defaultPayload, 
  createPayload, 
  expectValidJWT,
  decodeJWTParts,
  promisify,
  expectError,
  ALGORITHMS
} from '../helpers/test-utils';

describe('JWT Sign Functions', () => {
  // Test data
  const hmacSecret = generateHMACSecret();
  const rsaKeys = generateRSAKeyPair();
  const ecKeys = generateECKeyPair();
  const edKeys = generateEd25519KeyPair();

  describe('sign() - Async/Promise API', () => {
    it('should sign a token with default algorithm (HS256)', async () => {
      const token = await sign(defaultPayload, hmacSecret);
      expect(token).toBeValidJWT();
      expect(token).toHaveJWTStructure();
      
      const { header } = decodeJWTParts(token);
      expect(header.alg).toBe('HS256');
      expect(header.typ).toBe('JWT');
    });

    it('should sign a token with RS256', async () => {
      const token = await sign(defaultPayload, rsaKeys.privateKey, { 
        algorithm: 'RS256' 
      });
      expect(token).toBeValidJWT();
      
      const { header } = decodeJWTParts(token);
      expect(header.alg).toBe('RS256');
    });

    it('should sign a token with ES256', async () => {
      const token = await sign(defaultPayload, ecKeys.privateKey, { 
        algorithm: 'ES256' 
      });
      expect(token).toBeValidJWT();
      
      const { header } = decodeJWTParts(token);
      expect(header.alg).toBe('ES256');
    });

    it('should sign a token with EdDSA', async () => {
      const token = await sign(defaultPayload, edKeys.privateKey, { 
        algorithm: 'EdDSA' 
      });
      expect(token).toBeValidJWT();
      
      const { header } = decodeJWTParts(token);
      expect(header.alg).toBe('EdDSA');
    });

    it('should add iat claim automatically', async () => {
      const payload = { sub: '1234567890', name: 'Test User' };
      const before = Math.floor(Date.now() / 1000);
      
      const token = await sign(payload, hmacSecret);
      
      const { payload: decoded } = decodeJWTParts(token);
      expect(decoded.iat).toBeDefined();
      expect(decoded.iat).toBeGreaterThanOrEqual(before);
      expect(decoded.iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
    });

    it('should handle expiresIn option', async () => {
      const token = await sign(defaultPayload, hmacSecret, { 
        expiresIn: '1h' 
      });
      
      const { payload: decoded } = decodeJWTParts(token);
      expect(decoded.exp).toBeDefined();
      expect(decoded.exp).toBeGreaterThan(decoded.iat);
      expect(decoded.exp - decoded.iat).toBe(3600); // 1 hour = 3600 seconds
    });

    it('should handle audience option', async () => {
      const audience = 'test-audience';
      const token = await sign(defaultPayload, hmacSecret, { audience });
      
      const { payload: decoded } = decodeJWTParts(token);
      expect(decoded.aud).toBe(audience);
    });

    it('should handle multiple audiences', async () => {
      const audiences = ['audience1', 'audience2'];
      const token = await sign(defaultPayload, hmacSecret, { 
        audience: audiences 
      });
      
      const { payload: decoded } = decodeJWTParts(token);
      expect(decoded.aud).toEqual(audiences);
    });

    it('should throw error for invalid payload', async () => {
      await expectError(
        () => sign(null as any, hmacSecret),
        'Expected "payload" to be a plain object.'
      );
    });

    it('should throw error for missing secret', async () => {
      await expectError(
        () => sign(defaultPayload, ''),
        'secretOrPrivateKey must have a value'
      );
    });

    it('should handle custom headers', async () => {
      const customHeader = { kid: 'test-key-id', custom: 'value' };
      const token = await sign(defaultPayload, hmacSecret, { 
        header: customHeader 
      });
      
      const { header } = decodeJWTParts(token);
      expect(header.kid).toBe('test-key-id');
      expect(header.custom).toBe('value');
    });

    it('should sign string payload', async () => {
      const stringPayload = 'This is a plain text payload';
      // Explicitly test the promise path without callback to ensure coverage
      const promise = sign(stringPayload, hmacSecret);
      expect(promise).toBeInstanceOf(Promise);
      const token = await promise;
      
      const { header, payload } = decodeJWTParts(token);
      // String payloads should not have typ: 'JWT' in header
      expect(header.typ).toBeUndefined();
      expect(payload).toBe(stringPayload);
    });

    it('should sign Buffer payload', async () => {
      const bufferPayload = Buffer.from('This is a buffer payload');
      const token = await sign(bufferPayload, hmacSecret);
      
      const { header } = decodeJWTParts(token);
      // Buffer payloads should not have typ: 'JWT' in header
      expect(header.typ).toBeUndefined();
    });
  });

  describe('sign() - Callback API', () => {
    it('should sign a token with callback', (done) => {
      sign(defaultPayload, hmacSecret, (err, token) => {
        expect(err).toBeNull();
        expect(token).toBeValidJWT();
        done();
      });
    });

    it('should sign with algorithm option and callback', (done) => {
      sign(defaultPayload, rsaKeys.privateKey, { algorithm: 'RS256' }, (err, token) => {
        expect(err).toBeNull();
        expect(token).toBeValidJWT();
        
        const { header } = decodeJWTParts(token!);
        expect(header.alg).toBe('RS256');
        done();
      });
    });

    it('should handle errors in callback', (done) => {
      sign(null as any, hmacSecret, (err, token) => {
        expect(err).toBeDefined();
        expect(err!.message).toBe('Expected "payload" to be a plain object.');
        expect(token).toBeUndefined();
        done();
      });
    });

    it('should work with promisify helper', async () => {
      const token = await promisify<string>(sign, defaultPayload, hmacSecret);
      expect(token).toBeValidJWT();
    });

    it('should sign string payload with callback', (done) => {
      const stringPayload = 'This is a plain text payload';
      sign(stringPayload, hmacSecret, (err, token) => {
        expect(err).toBeNull();
        expect(token).toBeDefined();
        
        const { header, payload } = decodeJWTParts(token!);
        // String payloads should not have typ: 'JWT' in header
        expect(header.typ).toBeUndefined();
        expect(payload).toBe(stringPayload);
        done();
      });
    });

    it('should sign Buffer payload with callback', (done) => {
      const bufferPayload = Buffer.from('This is a buffer payload');
      sign(bufferPayload, hmacSecret, (err, token) => {
        expect(err).toBeNull();
        expect(token).toBeDefined();
        
        const { header } = decodeJWTParts(token!);
        // Buffer payloads should not have typ: 'JWT' in header
        expect(header.typ).toBeUndefined();
        done();
      });
    });
  });

  describe('signSync() - Synchronous API', () => {
    it('should sign a token synchronously', () => {
      const token = signSync(defaultPayload, hmacSecret);
      expect(token).toBeValidJWT();
      expect(token).toHaveJWTStructure();
      
      const { header } = decodeJWTParts(token);
      expect(header.alg).toBe('HS256');
    });

    it('should work with all HMAC algorithms', () => {
      ALGORITHMS.HMAC.forEach(alg => {
        const token = signSync(defaultPayload, hmacSecret, { 
          algorithm: alg as Algorithm 
        });
        expect(token).toBeValidJWT();
        
        const { header } = decodeJWTParts(token);
        expect(header.alg).toBe(alg);
      });
    });

    it('should work with RSA algorithms', () => {
      ALGORITHMS.RSA.forEach(alg => {
        const token = signSync(defaultPayload, rsaKeys.privateKey, { 
          algorithm: alg as Algorithm 
        });
        expect(token).toBeValidJWT();
        
        const { header } = decodeJWTParts(token);
        expect(header.alg).toBe(alg);
      });
    });

    it('should handle options same as async version', () => {
      const options = {
        expiresIn: '2h',
        audience: 'test-aud',
        issuer: 'test-issuer',
        subject: 'test-subject',
        jwtid: 'test-id'
      };
      
      const token = signSync(defaultPayload, hmacSecret, options);
      const { payload } = decodeJWTParts(token);
      
      expect(payload.aud).toBe(options.audience);
      expect(payload.iss).toBe(options.issuer);
      expect(payload.sub).toBe(options.subject);
      expect(payload.jti).toBe(options.jwtid);
      expect(payload.exp - payload.iat).toBe(7200); // 2 hours
    });

    it('should throw errors synchronously', () => {
      expect(() => signSync(null as any, hmacSecret))
        .toThrow('Expected "payload" to be a plain object.');
      
      expect(() => signSync(defaultPayload, ''))
        .toThrow('secretOrPrivateKey must have a value');
    });

    it('should sign string payload synchronously', () => {
      const stringPayload = 'This is a plain text payload';
      const token = signSync(stringPayload, hmacSecret);
      
      const { header, payload } = decodeJWTParts(token);
      // String payloads should not have typ: 'JWT' in header
      expect(header.typ).toBeUndefined();
      expect(payload).toBe(stringPayload);
    });

    it('should sign Buffer payload synchronously', () => {
      const bufferPayload = Buffer.from('This is a buffer payload');
      const token = signSync(bufferPayload, hmacSecret);
      
      const { header } = decodeJWTParts(token);
      // Buffer payloads should not have typ: 'JWT' in header
      expect(header.typ).toBeUndefined();
    });
  });

  describe('Algorithm Support', () => {
    it('should support all documented algorithms', async () => {
      const algorithmsToTest = [
        ...ALGORITHMS.HMAC,
        ...ALGORITHMS.RSA,
        ...ALGORITHMS.PSS,
        ...ALGORITHMS.ECDSA,
        ...ALGORITHMS.EDDSA
      ];

      for (const alg of algorithmsToTest) {
        const keys = generateKeysForAlgorithm(alg);
        
        // Test async
        const asyncToken = await sign(defaultPayload, keys.privateKey, { 
          algorithm: alg as Algorithm 
        });
        expect(asyncToken).toBeValidJWT();
        
        // Test sync
        const syncToken = signSync(defaultPayload, keys.privateKey, { 
          algorithm: alg as Algorithm 
        });
        expect(syncToken).toBeValidJWT();
        
        // Verify algorithm in header
        const { header } = decodeJWTParts(asyncToken);
        expect(header.alg).toBe(alg);
      }
    });

    it('should handle "none" algorithm with security flag', async () => {
      // Should throw without allowInsecureNoneAlgorithm
      await expectError(
        () => sign(defaultPayload, '', { algorithm: 'none' }),
        /The "none" algorithm is insecure and disabled by default/
      );

      // Should work with security flag
      const token = await sign(defaultPayload, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });
      
      const parts = token.split('.');
      expect(parts[2]).toBe(''); // No signature
      
      const { header } = decodeJWTParts(token);
      expect(header.alg).toBe('none');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle Buffer payload', async () => {
      const bufferPayload = Buffer.from('test data');
      const token = await sign(bufferPayload, hmacSecret);
      expect(token).toBeValidJWT();
      
      const { header } = decodeJWTParts(token);
      expect(header.typ).toBeUndefined(); // No typ for non-object payloads
    });

    it('should handle string payload', async () => {
      const stringPayload = 'test string data';
      const token = await sign(stringPayload, hmacSecret);
      expect(token).toBeValidJWT();
    });

    it('should reject invalid options for non-object payloads', async () => {
      await expectError(
        () => sign('string payload', hmacSecret, { audience: 'test' }),
        /invalid audience option for string payload/
      );
    });

    it('should handle noTimestamp option', async () => {
      const token = await sign(defaultPayload, hmacSecret, { 
        noTimestamp: true 
      });
      
      const { payload } = decodeJWTParts(token);
      expect(payload.iat).toBeUndefined();
    });

    it('should reject when exp already exists with expiresIn', async () => {
      const payloadWithExp = { ...defaultPayload, exp: 123456 };
      
      await expectError(
        () => sign(payloadWithExp, hmacSecret, { expiresIn: '1h' }),
        'Bad "options.expiresIn" option the payload already has an "exp" property.'
      );
    });

    it('should handle KeyObject inputs', async () => {
      const token = await sign(defaultPayload, rsaKeys.privateKeyObject, { 
        algorithm: 'RS256' 
      });
      expect(token).toBeValidJWT();
    });
  });
});