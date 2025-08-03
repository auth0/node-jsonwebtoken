/// <reference path="../types/jest.d.ts" />

import { describe, it, expect } from '@jest/globals';
import { verifySync, sign, JsonWebTokenError, TokenExpiredError, NotBeforeError } from '../../src/index';
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
  createExpiredToken,
  createNotBeforeToken,
  createTokenWithAudience,
  createTokenWithClaims,
  createTokenWithInvalidClaim,
  createMalformedTokens,
  ALGORITHMS
} from '../helpers/test-utils';

describe('JWT VerifySync Function', () => {
  const secret = generateHMACSecret();
  const rsaKeys = generateRSAKeyPair();
  const ecKeys = generateECKeyPair();
  const edKeys = generateEd25519KeyPair();

  describe('verifySync() - Synchronous API', () => {
    describe('Basic Verification', () => {
      it('should verify a valid token synchronously', async () => {
        const token = await sign(defaultPayload, secret);
        const decoded = verifySync(token, secret);
        
        expect(decoded).toMatchObject(defaultPayload);
        expect(decoded.iat).toBeDefined();
      });

      it('should verify tokens with all HMAC algorithms', async () => {
        for (const alg of ALGORITHMS.HMAC) {
          const token = await sign(defaultPayload, secret, { algorithm: alg as Algorithm });
          const decoded = verifySync(token, secret, { algorithms: [alg as Algorithm] });
          
          expect(decoded).toMatchObject(defaultPayload);
        }
      });

      it('should verify RSA signed tokens', async () => {
        for (const alg of ALGORITHMS.RSA) {
          const token = await sign(defaultPayload, rsaKeys.privateKey, { algorithm: alg as Algorithm });
          const decoded = verifySync(token, rsaKeys.publicKey, { algorithms: [alg as Algorithm] });
          
          expect(decoded).toMatchObject(defaultPayload);
        }
      });

      it('should verify ECDSA signed tokens', async () => {
        const token = await sign(defaultPayload, ecKeys.privateKey, { algorithm: 'ES256' });
        const decoded = verifySync(token, ecKeys.publicKey, { algorithms: ['ES256'] });
        
        expect(decoded).toMatchObject(defaultPayload);
      });

      it('should verify EdDSA signed tokens', async () => {
        const token = await sign(defaultPayload, edKeys.privateKey, { algorithm: 'EdDSA' });
        const decoded = verifySync(token, edKeys.publicKey, { algorithms: ['EdDSA'] });
        
        expect(decoded).toMatchObject(defaultPayload);
      });

      it('should verify with complete option', async () => {
        const token = await sign(defaultPayload, secret);
        const decoded = verifySync(token, secret, { complete: true });
        
        expect(decoded.header).toBeDefined();
        expect(decoded.header.alg).toBe('HS256');
        expect(decoded.payload).toMatchObject(defaultPayload);
        expect(decoded.signature).toBeDefined();
      });
    });

    describe('Sync-specific Behavior', () => {
      it('should throw error when trying to use function as key', async () => {
        const token = await sign(defaultPayload, secret);
        const getKey = async () => secret;
        
        expect(() => verifySync(token, getKey as any))
          .toThrow(JsonWebTokenError);
        expect(() => verifySync(token, getKey as any))
          .toThrow('Synchronous verify cannot use async key resolution. Use verify() instead.');
      });

      it('should work synchronously without promises', () => {
        // This test verifies that verifySync truly works synchronously
        let token: string = '';
        let error: Error | null = null;
        
        // Create token synchronously (using sync sign in a previous step)
        try {
          // We need to create a token first - using async for setup
          const payload = { sync: true, data: 'test' };
          token = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url') + '.' +
                 Buffer.from(JSON.stringify(payload)).toString('base64url') + '.fakesignature';
        } catch (e) {
          error = e as Error;
        }
        
        expect(error).toBeNull();
        
        // Note: This would fail signature verification, but demonstrates sync operation
        expect(() => verifySync(token, secret)).toThrow();
      });
    });

    describe('Signature Verification', () => {
      it('should reject tokens with invalid signature', async () => {
        const token = await sign(defaultPayload, secret);
        const tamperedToken = token.slice(0, -4) + 'xxxx';
        
        expect(() => verifySync(tamperedToken, secret))
          .toThrow(JsonWebTokenError);
        expect(() => verifySync(tamperedToken, secret))
          .toThrow('invalid signature');
      });

      it('should reject tokens signed with different secret', async () => {
        const token = await sign(defaultPayload, secret);
        const wrongSecret = generateHMACSecret();
        
        expect(() => verifySync(token, wrongSecret))
          .toThrow('invalid signature');
      });

      it('should reject when algorithm mismatch', async () => {
        const token = await sign(defaultPayload, secret, { algorithm: 'HS256' });
        
        expect(() => verifySync(token, secret, { algorithms: ['HS384'] }))
          .toThrow('invalid algorithm');
      });
    });

    describe('Claims Validation', () => {
      describe('Expiration (exp)', () => {
        it('should reject expired tokens', async () => {
          const expiredToken = await createExpiredToken(secret);
          
          expect(() => verifySync(expiredToken, secret))
            .toThrow(TokenExpiredError);
        });

        it('should accept expired tokens with ignoreExpiration', async () => {
          const expiredToken = await createExpiredToken(secret);
          const decoded = verifySync(expiredToken, secret, { ignoreExpiration: true });
          
          expect(decoded).toBeDefined();
          expect(decoded.exp).toBeLessThan(Math.floor(Date.now() / 1000));
        });

        it('should handle clockTolerance for expiration', async () => {
          const token = await sign({
            ...defaultPayload,
            exp: Math.floor(Date.now() / 1000) - 5 // Expired 5 seconds ago
          }, secret);

          // Should fail without tolerance
          expect(() => verifySync(token, secret))
            .toThrow(TokenExpiredError);

          // Should pass with 10 second tolerance
          const decoded = verifySync(token, secret, { clockTolerance: 10 });
          expect(decoded).toBeDefined();
        });
      });

      describe('Not Before (nbf)', () => {
        it('should reject tokens not yet valid', async () => {
          const notBeforeToken = await createNotBeforeToken(secret);
          
          expect(() => verifySync(notBeforeToken, secret))
            .toThrow(NotBeforeError);
        });

        it('should accept future tokens with ignoreNotBefore', async () => {
          const notBeforeToken = await createNotBeforeToken(secret);
          const decoded = verifySync(notBeforeToken, secret, { ignoreNotBefore: true });
          
          expect(decoded).toBeDefined();
          expect(decoded.nbf).toBeGreaterThan(Math.floor(Date.now() / 1000));
        });
      });

      describe('Audience (aud)', () => {
        it('should verify single audience string', async () => {
          const token = await createTokenWithAudience(secret, 'test-audience');
          const decoded = verifySync(token, secret, { audience: 'test-audience' });
          
          expect(decoded.aud).toBe('test-audience');
        });

        it('should verify audience array', async () => {
          const token = await createTokenWithAudience(secret, ['aud1', 'aud2']);
          const decoded = verifySync(token, secret, { audience: 'aud1' });
          
          expect(decoded.aud).toEqual(['aud1', 'aud2']);
        });

        it('should verify with RegExp audience', async () => {
          const token = await createTokenWithAudience(secret, 'test-audience-123');
          const decoded = verifySync(token, secret, { audience: /^test-audience-\d+$/ });
          
          expect(decoded.aud).toBe('test-audience-123');
        });

        it('should reject invalid audience', async () => {
          const token = await createTokenWithAudience(secret, 'wrong-audience');
          
          expect(() => verifySync(token, secret, { audience: 'expected-audience' }))
            .toThrow('jwt audience invalid. expected: expected-audience');
        });
      });

      describe('Other Claims', () => {
        it('should verify issuer', async () => {
          const token = await sign({ ...defaultPayload, iss: 'test-issuer' }, secret);
          
          const decoded = verifySync(token, secret, { issuer: 'test-issuer' });
          expect(decoded.iss).toBe('test-issuer');
          
          expect(() => verifySync(token, secret, { issuer: 'wrong-issuer' }))
            .toThrow('jwt issuer invalid. expected: wrong-issuer');
        });

        it('should verify subject', async () => {
          const token = await sign({ ...defaultPayload, sub: 'test-subject' }, secret);
          
          const decoded = verifySync(token, secret, { subject: 'test-subject' });
          expect(decoded.sub).toBe('test-subject');
          
          expect(() => verifySync(token, secret, { subject: 'wrong-subject' }))
            .toThrow('jwt subject invalid. expected: wrong-subject');
        });

        it('should verify jwtid', async () => {
          const token = await sign({ ...defaultPayload, jti: 'unique-id' }, secret);
          
          const decoded = verifySync(token, secret, { jwtid: 'unique-id' });
          expect(decoded.jti).toBe('unique-id');
          
          expect(() => verifySync(token, secret, { jwtid: 'wrong-id' }))
            .toThrow('jwt jwtid invalid. expected: wrong-id');
        });

        it('should verify nonce', async () => {
          const token = await sign({ ...defaultPayload, nonce: 'test-nonce' }, secret);
          
          const decoded = verifySync(token, secret, { nonce: 'test-nonce' });
          expect(decoded.nonce).toBe('test-nonce');
          
          expect(() => verifySync(token, secret, { nonce: 'wrong-nonce' }))
            .toThrow('jwt nonce invalid. expected: wrong-nonce');
        });

        it('should verify maxAge', async () => {
          const token = await sign(defaultPayload, secret);
          
          // Should pass - token just created
          verifySync(token, secret, { maxAge: '1h' });
          
          // Create old token
          const oldToken = await sign({
            ...defaultPayload,
            iat: Math.floor(Date.now() / 1000) - 7200 // 2 hours ago
          }, secret);
          
          expect(() => verifySync(oldToken, secret, { maxAge: '1h' }))
            .toThrow(TokenExpiredError);
        });
      });
    });

    describe('Error Handling', () => {
      it('should reject malformed tokens', () => {
        const malformed = createMalformedTokens();
        
        expect(() => verifySync(malformed.notEnoughSegments, secret))
          .toThrow('jwt malformed');
        
        expect(() => verifySync(malformed.invalidBase64, secret))
          .toThrow(JsonWebTokenError);
      });

      it('should reject empty token', () => {
        expect(() => verifySync('', secret))
          .toThrow('jwt must be provided');
      });

      it('should reject non-string token', () => {
        expect(() => verifySync(123 as any, secret))
          .toThrow('jwt must be a string');
      });

      it('should reject when secret is missing', async () => {
        const token = await sign(defaultPayload, secret);
        
        expect(() => verifySync(token, ''))
          .toThrow('secretOrPublicKey must have a value');
      });

      it('should handle invalid exp value', () => {
        const secret = 'test-secret';
        const token = createTokenWithInvalidClaim(secret, 'exp', 'not-a-number');
        
        expect(() => verifySync(token, secret)).toThrow('invalid exp value');
      });

      it('should handle invalid nbf value', () => {
        const secret = 'test-secret';
        const token = createTokenWithInvalidClaim(secret, 'nbf', 'not-a-number');
        
        expect(() => verifySync(token, secret)).toThrow('invalid nbf value');
      });
    });

    describe('Options', () => {
      it('should use custom clockTimestamp', async () => {
        const futureTimestamp = Math.floor(Date.now() / 1000) + 3600;
        const token = await sign({
          ...defaultPayload,
          nbf: futureTimestamp - 10 // Valid 10 seconds before custom timestamp
        }, secret);

        // Should fail with current time
        expect(() => verifySync(token, secret))
          .toThrow(NotBeforeError);

        // Should pass with future timestamp
        const decoded = verifySync(token, secret, { clockTimestamp: futureTimestamp });
        expect(decoded).toBeDefined();
      });

      it('should validate with multiple allowed algorithms', async () => {
        const token = await sign(defaultPayload, secret, { algorithm: 'HS384' });
        
        const decoded = verifySync(token, secret, { 
          algorithms: ['HS256', 'HS384', 'HS512'] 
        });
        
        expect(decoded).toMatchObject(defaultPayload);
      });
    });

    describe('Edge Cases', () => {
      it('should handle "none" algorithm tokens', async () => {
        const token = await sign(defaultPayload, '', { 
          algorithm: 'none',
          allowInsecureNoneAlgorithm: true
        });

        // The library now prevents 'none' in algorithms for security
        expect(() => verifySync(token, '', { algorithms: ['none'] }))
          .toThrow('Invalid verify option "algorithms" for "none" algorithm');
        
        // Without specifying algorithms, it should work
        const decoded = verifySync(token, '');
        expect(decoded).toMatchObject(defaultPayload);
      });

      it('should handle Buffer secrets', async () => {
        const bufferSecret = Buffer.from('my-secret-key');
        const token = await sign(defaultPayload, bufferSecret);
        const decoded = verifySync(token, bufferSecret);
        
        expect(decoded).toMatchObject(defaultPayload);
      });

      it('should handle KeyObject inputs', async () => {
        const token = await sign(defaultPayload, rsaKeys.privateKeyObject, { algorithm: 'RS256' });
        const decoded = verifySync(token, rsaKeys.publicKeyObject, { algorithms: ['RS256'] });
        
        expect(decoded).toMatchObject(defaultPayload);
      });
    });

    describe('Performance Comparison', () => {
      it('should perform multiple verifications synchronously', async () => {
        const tokens = await Promise.all(
          Array(10).fill(0).map(() => sign(defaultPayload, secret))
        );

        const startTime = Date.now();
        
        // Verify all tokens synchronously
        const results = tokens.map(token => verifySync(token, secret));
        
        const syncTime = Date.now() - startTime;
        
        expect(results).toHaveLength(10);
        results.forEach(result => {
          expect(result).toMatchObject(defaultPayload);
        });
        
        // Sync should complete quickly for simple operations
        expect(syncTime).toBeLessThan(100); // Should be fast
      });
    });
  });
});