/// <reference path="../types/jest.d.ts" />

import { describe, it, expect } from '@jest/globals';
import { decode } from '../../src/index';
import { sign } from '../../src/index';
import { 
  generateHMACSecret, 
  generateRSAKeyPair,
  generateKeysForAlgorithm 
} from '../helpers/key-generator';
import { 
  defaultPayload,
  createMalformedTokens,
  ALGORITHMS
} from '../helpers/test-utils';

describe('JWT Decode Function', () => {
  const secret = generateHMACSecret();
  const rsaKeys = generateRSAKeyPair();

  describe('Basic Decoding', () => {
    it('should decode a valid JWT token', async () => {
      const token = await sign(defaultPayload, secret);
      const decoded = decode(token);
      
      expect(decoded).toBeDefined();
      expect(decoded).toMatchObject(defaultPayload);
      expect(decoded!.iat).toBeDefined();
    });

    it('should decode tokens from all algorithms', async () => {
      const algorithmsToTest = [
        ...ALGORITHMS.HMAC,
        ...ALGORITHMS.RSA,
        ...ALGORITHMS.PSS,
        ...ALGORITHMS.ECDSA,
        ...ALGORITHMS.EDDSA
      ];

      for (const alg of algorithmsToTest) {
        const keys = generateKeysForAlgorithm(alg);
        const token = await sign(defaultPayload, keys.privateKey, { algorithm: alg as any });
        const decoded = decode(token);
        
        expect(decoded).toBeDefined();
        expect(decoded).toMatchObject(defaultPayload);
      }
    });

    it('should decode without verifying signature', async () => {
      const token = await sign(defaultPayload, secret);
      // Corrupt the signature
      const parts = token.split('.');
      const corruptedToken = parts[0] + '.' + parts[1] + '.invalidsignature';
      
      const decoded = decode(corruptedToken);
      expect(decoded).toBeDefined();
      expect(decoded).toMatchObject(defaultPayload);
    });
  });

  describe('Complete Option', () => {
    it('should return header, payload, and signature with complete option', async () => {
      const token = await sign(defaultPayload, secret, { algorithm: 'HS256' });
      const decoded = decode(token, { complete: true });
      
      expect(decoded).toBeDefined();
      expect(decoded!.header).toBeDefined();
      expect(decoded!.header.alg).toBe('HS256');
      expect(decoded!.header.typ).toBe('JWT');
      expect(decoded!.payload).toMatchObject(defaultPayload);
      expect(decoded!.signature).toBeDefined();
      expect(decoded!.signature).toBeTruthy();
    });

    it('should include custom header fields', async () => {
      const customHeader = { kid: 'test-key-id', custom: 'value' };
      const token = await sign(defaultPayload, secret, { header: customHeader });
      const decoded = decode(token, { complete: true });
      
      expect(decoded!.header.kid).toBe('test-key-id');
      expect(decoded!.header.custom).toBe('value');
    });

    it('should work with different algorithms in complete mode', async () => {
      const algorithms = ['RS256', 'ES256', 'PS256'];
      
      for (const alg of algorithms) {
        const keys = generateKeysForAlgorithm(alg);
        const token = await sign(defaultPayload, keys.privateKey, { algorithm: alg as any });
        const decoded = decode(token, { complete: true });
        
        expect(decoded!.header.alg).toBe(alg);
        expect(decoded!.payload).toMatchObject(defaultPayload);
      }
    });
  });

  describe('Non-JSON Payloads', () => {
    it('should decode string payload', async () => {
      const stringPayload = 'This is a string payload';
      const token = await sign(stringPayload, secret);
      const decoded = decode(token);
      
      expect(decoded).toBe(stringPayload);
    });

    it('should decode Buffer payload', async () => {
      const bufferPayload = Buffer.from('Buffer payload data');
      const token = await sign(bufferPayload, secret);
      const decoded = decode(token);
      
      // When signing a Buffer, it gets JSON stringified
      expect(decoded).toEqual({
        type: 'Buffer',
        data: Array.from(bufferPayload)
      });
    });

    it('should respect json option', async () => {
      const token = await sign(defaultPayload, secret);
      
      // With json: true (default for JWT typ)
      const decodedJson = decode(token, { json: true });
      expect(typeof decodedJson).toBe('object');
      
      // Note: json: false would return the raw base64url string
      // This is rarely used but supported
    });
  });

  describe('Error Handling', () => {
    it('should return null for undefined input', () => {
      const decoded = decode(undefined as any);
      expect(decoded).toBeNull();
    });

    it('should return null for null input', () => {
      const decoded = decode(null as any);
      expect(decoded).toBeNull();
    });

    it('should return null for empty string', () => {
      const decoded = decode('');
      expect(decoded).toBeNull();
    });

    it('should return null for non-string input', () => {
      const decoded = decode(123 as any);
      expect(decoded).toBeNull();
      
      const decoded2 = decode({} as any);
      expect(decoded2).toBeNull();
      
      const decoded3 = decode([] as any);
      expect(decoded3).toBeNull();
    });

    it('should return null for malformed tokens', () => {
      const malformed = createMalformedTokens();
      
      expect(decode(malformed.notEnoughSegments)).toBeNull();
      expect(decode(malformed.tooManySegments)).toBeNull();
      expect(decode(malformed.emptySegments)).toBeNull();
    });

    it('should return null for invalid base64url encoding', () => {
      const invalidBase64 = 'not-base64.also-not-base64.definitely-not-base64';
      const decoded = decode(invalidBase64);
      expect(decoded).toBeNull();
    });

    it('should return null when payload decoding throws an error', () => {
      // Mock the decodePayload to throw an error
      const { decode } = require('../../src/decode');
      const jwtCore = require('../../src/lib/jwt-core');
      
      // Create a valid token structure
      const validHeader = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');
      const validPayload = Buffer.from('{"test":"data"}').toString('base64url');
      const signature = 'signature';
      const token = `${validHeader}.${validPayload}.${signature}`;
      
      // Mock decodePayload to return null
      const originalDecodePayload = jwtCore.decodePayload;
      jwtCore.decodePayload = jest.fn().mockReturnValueOnce(null);
      
      const decoded = decode(token);
      expect(decoded).toBeNull();
      
      // Restore original function
      jwtCore.decodePayload = originalDecodePayload;
    });

    it('should handle tokens with invalid JSON in payload', () => {
      const malformed = createMalformedTokens();
      const decoded = decode(malformed.invalidJSON);
      expect(decoded).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should decode token without typ header', async () => {
      // Create a minimal JWT manually
      const header = { alg: 'HS256' };
      const payload = { data: 'test' };
      
      const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
      const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const token = `${encodedHeader}.${encodedPayload}.signature`;
      
      const decoded = decode(token);
      expect(decoded).toEqual(payload);
    });

    it('should decode token with minimal header', async () => {
      const header = { alg: 'none' };
      const payload = { minimal: true };
      
      const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
      const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const token = `${encodedHeader}.${encodedPayload}.`;
      
      const decoded = decode(token, { complete: true });
      expect(decoded!.header).toEqual(header);
      expect(decoded!.payload).toEqual(payload);
    });

    it('should preserve all custom claims', async () => {
      const customPayload = {
        ...defaultPayload,
        customString: 'value',
        customNumber: 123,
        customBoolean: true,
        customArray: [1, 2, 3],
        customObject: { nested: 'value' },
        customNull: null
      };
      
      const token = await sign(customPayload, secret);
      const decoded = decode(token);
      
      expect(decoded).toMatchObject(customPayload);
    });

    it('should handle very large payloads', async () => {
      const largePayload = {
        data: 'x'.repeat(10000),
        array: new Array(100).fill('item')
      };
      
      const token = await sign(largePayload, secret);
      const decoded = decode(token);
      
      expect(decoded).toMatchObject(largePayload);
    });

    it('should handle unicode in payload', async () => {
      const unicodePayload = {
        emoji: '🎉🎊🎈',
        chinese: '你好世界',
        arabic: 'مرحبا بالعالم',
        special: '¡™£¢∞§¶•ªº–≠'
      };
      
      const token = await sign(unicodePayload, secret);
      const decoded = decode(token);
      
      expect(decoded).toMatchObject(unicodePayload);
    });
  });

  describe('Compatibility', () => {
    it('should decode tokens with "none" algorithm', async () => {
      const token = await sign(defaultPayload, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });
      
      const decoded = decode(token);
      expect(decoded).toMatchObject(defaultPayload);
      
      const complete = decode(token, { complete: true });
      expect(complete!.header.alg).toBe('none');
      expect(complete!.signature).toBe('');
    });

    it('should handle tokens with all standard claims', async () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: 'test-issuer',
        sub: 'test-subject',
        aud: ['aud1', 'aud2'],
        exp: now + 3600,
        nbf: now,
        iat: now,
        jti: 'unique-id'
      };
      
      const token = await sign(claims, secret);
      const decoded = decode(token);
      
      expect(decoded).toMatchObject(claims);
    });
  });
});