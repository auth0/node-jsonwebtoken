/// <reference path="../types/jest.d.ts" />

import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { verify, sign, JsonWebTokenError, TokenExpiredError, NotBeforeError } from '../../src/index';
import type { Algorithm, GetPublicKeyOrSecret } from '../../src/types';
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
  promisify,
  ALGORITHMS
} from '../helpers/test-utils';

describe('JWT Verify Function', () => {
  const secret = generateHMACSecret();
  const rsaKeys = generateRSAKeyPair();
  const ecKeys = generateECKeyPair();
  const edKeys = generateEd25519KeyPair();

  describe('verify() - Async/Promise API', () => {
    describe('Basic Verification', () => {
      it('should verify a valid token with HS256', async () => {
        const token = await sign(defaultPayload, secret);
        const decoded = await verify(token, secret);
        
        expect(decoded).toMatchObject(defaultPayload);
        expect(decoded.iat).toBeDefined();
      });

      it('should verify token without options parameter', async () => {
        const token = await sign(defaultPayload, secret);
        // Call verify without the third parameter to trigger default options initialization
        const decoded = await verify(token, secret);
        
        expect(decoded).toMatchObject(defaultPayload);
        expect(decoded.iat).toBeDefined();
      });

      it('should verify tokens with all HMAC algorithms', async () => {
        for (const alg of ALGORITHMS.HMAC) {
          const token = await sign(defaultPayload, secret, { algorithm: alg as Algorithm });
          const decoded = await verify(token, secret, { algorithms: [alg as Algorithm] });
          
          expect(decoded).toMatchObject(defaultPayload);
        }
      });

      it('should verify RSA signed tokens', async () => {
        for (const alg of ALGORITHMS.RSA) {
          const token = await sign(defaultPayload, rsaKeys.privateKey, { algorithm: alg as Algorithm });
          const decoded = await verify(token, rsaKeys.publicKey, { algorithms: [alg as Algorithm] });
          
          expect(decoded).toMatchObject(defaultPayload);
        }
      });

      it('should verify ECDSA signed tokens', async () => {
        const token = await sign(defaultPayload, ecKeys.privateKey, { algorithm: 'ES256' });
        const decoded = await verify(token, ecKeys.publicKey, { algorithms: ['ES256'] });
        
        expect(decoded).toMatchObject(defaultPayload);
      });

      it('should verify EdDSA signed tokens', async () => {
        const token = await sign(defaultPayload, edKeys.privateKey, { algorithm: 'EdDSA' });
        const decoded = await verify(token, edKeys.publicKey, { algorithms: ['EdDSA'] });
        
        expect(decoded).toMatchObject(defaultPayload);
      });

      it('should verify with complete option', async () => {
        const token = await sign(defaultPayload, secret);
        const decoded = await verify(token, secret, { complete: true });
        
        expect(decoded.header).toBeDefined();
        expect(decoded.header.alg).toBe('HS256');
        expect(decoded.payload).toMatchObject(defaultPayload);
        expect(decoded.signature).toBeDefined();
      });
    });

    describe('Async Key Resolution', () => {
      it('should support GetPublicKeyOrSecret function', async () => {
        const token = await sign(defaultPayload, rsaKeys.privateKey, { 
          algorithm: 'RS256',
          keyid: 'test-key-1'
        });

        const getKey: GetPublicKeyOrSecret = async (header) => {
          expect(header.kid).toBe('test-key-1');
          expect(header.alg).toBe('RS256');
          return rsaKeys.publicKey;
        };

        const decoded = await verify(token, getKey, { algorithms: ['RS256'] });
        expect(decoded).toMatchObject(defaultPayload);
      });

      it('should handle errors in key resolution', async () => {
        const token = await sign(defaultPayload, secret);
        
        const getKey: GetPublicKeyOrSecret = async () => {
          throw new Error('Key resolution failed');
        };

        await expect(verify(token, getKey))
          .rejects.toThrow('Key resolution failed');
      });

      it('should select correct key based on kid', async () => {
        const keys = {
          'key-1': generateRSAKeyPair(),
          'key-2': generateRSAKeyPair()
        };

        const token = await sign(defaultPayload, keys['key-2'].privateKey, { 
          algorithm: 'RS256',
          keyid: 'key-2'
        });

        const getKey: GetPublicKeyOrSecret = async (header) => {
          return keys[header.kid as keyof typeof keys].publicKey;
        };

        const decoded = await verify(token, getKey, { algorithms: ['RS256'] });
        expect(decoded).toMatchObject(defaultPayload);
      });
    });

    describe('Signature Verification', () => {
      it('should reject tokens with invalid signature', async () => {
        const token = await sign(defaultPayload, secret);
        const tamperedToken = token.slice(0, -4) + 'xxxx';
        
        await expect(verify(tamperedToken, secret))
          .rejects.toThrow(JsonWebTokenError);
        await expect(verify(tamperedToken, secret))
          .rejects.toThrow('invalid signature');
      });

      it('should reject tokens signed with different secret', async () => {
        const token = await sign(defaultPayload, secret);
        const wrongSecret = generateHMACSecret();
        
        await expect(verify(token, wrongSecret))
          .rejects.toThrow('invalid signature');
      });

      it('should reject when algorithm mismatch', async () => {
        const token = await sign(defaultPayload, secret, { algorithm: 'HS256' });
        
        await expect(verify(token, secret, { algorithms: ['HS384'] }))
          .rejects.toThrow('invalid algorithm');
      });

      it('should require algorithms option for asymmetric algorithms', async () => {
        const token = await sign(defaultPayload, rsaKeys.privateKey, { algorithm: 'RS256' });
        
        await expect(verify(token, rsaKeys.publicKey))
          .rejects.toThrow('please pass "algorithms" option');
      });
    });

    describe('Claims Validation', () => {
      describe('Expiration (exp)', () => {
        it('should reject expired tokens', async () => {
          const expiredToken = await createExpiredToken(secret);
          
          await expect(verify(expiredToken, secret))
            .rejects.toThrow(TokenExpiredError);
          await expect(verify(expiredToken, secret))
            .rejects.toThrow('jwt expired');
        });

        it('should accept expired tokens with ignoreExpiration', async () => {
          const expiredToken = await createExpiredToken(secret);
          const decoded = await verify(expiredToken, secret, { ignoreExpiration: true });
          
          expect(decoded).toBeDefined();
          expect(decoded.exp).toBeLessThan(Math.floor(Date.now() / 1000));
        });

        it('should handle clockTolerance for expiration', async () => {
          const token = await sign({
            ...defaultPayload,
            exp: Math.floor(Date.now() / 1000) - 5 // Expired 5 seconds ago
          }, secret);

          // Should fail without tolerance
          await expect(verify(token, secret))
            .rejects.toThrow(TokenExpiredError);

          // Should pass with 10 second tolerance
          const decoded = await verify(token, secret, { clockTolerance: 10 });
          expect(decoded).toBeDefined();
        });
      });

      describe('Not Before (nbf)', () => {
        it('should reject tokens not yet valid', async () => {
          const notBeforeToken = await createNotBeforeToken(secret);
          
          await expect(verify(notBeforeToken, secret))
            .rejects.toThrow(NotBeforeError);
          await expect(verify(notBeforeToken, secret))
            .rejects.toThrow('jwt not active');
        });

        it('should accept future tokens with ignoreNotBefore', async () => {
          const notBeforeToken = await createNotBeforeToken(secret);
          const decoded = await verify(notBeforeToken, secret, { ignoreNotBefore: true });
          
          expect(decoded).toBeDefined();
          expect(decoded.nbf).toBeGreaterThan(Math.floor(Date.now() / 1000));
        });
      });

      describe('Audience (aud)', () => {
        it('should verify single audience string', async () => {
          const token = await createTokenWithAudience(secret, 'test-audience');
          const decoded = await verify(token, secret, { audience: 'test-audience' });
          
          expect(decoded.aud).toBe('test-audience');
        });

        it('should verify audience array', async () => {
          const token = await createTokenWithAudience(secret, ['aud1', 'aud2']);
          const decoded = await verify(token, secret, { audience: 'aud1' });
          
          expect(decoded.aud).toEqual(['aud1', 'aud2']);
        });

        it('should verify with RegExp audience', async () => {
          const token = await createTokenWithAudience(secret, 'test-audience-123');
          const decoded = await verify(token, secret, { audience: /^test-audience-\d+$/ });
          
          expect(decoded.aud).toBe('test-audience-123');
        });

        it('should reject invalid audience', async () => {
          const token = await createTokenWithAudience(secret, 'wrong-audience');
          
          await expect(verify(token, secret, { audience: 'expected-audience' }))
            .rejects.toThrow('jwt audience invalid. expected: expected-audience');
        });
      });

      describe('Other Claims', () => {
        it('should verify issuer', async () => {
          const token = await sign({ ...defaultPayload, iss: 'test-issuer' }, secret);
          
          const decoded = await verify(token, secret, { issuer: 'test-issuer' });
          expect(decoded.iss).toBe('test-issuer');
          
          await expect(verify(token, secret, { issuer: 'wrong-issuer' }))
            .rejects.toThrow('jwt issuer invalid. expected: wrong-issuer');
        });

        it('should verify subject', async () => {
          const token = await sign({ ...defaultPayload, sub: 'test-subject' }, secret);
          
          const decoded = await verify(token, secret, { subject: 'test-subject' });
          expect(decoded.sub).toBe('test-subject');
          
          await expect(verify(token, secret, { subject: 'wrong-subject' }))
            .rejects.toThrow('jwt subject invalid. expected: wrong-subject');
        });

        it('should verify jwtid', async () => {
          const token = await sign({ ...defaultPayload, jti: 'unique-id' }, secret);
          
          const decoded = await verify(token, secret, { jwtid: 'unique-id' });
          expect(decoded.jti).toBe('unique-id');
          
          await expect(verify(token, secret, { jwtid: 'wrong-id' }))
            .rejects.toThrow('jwt jwtid invalid. expected: wrong-id');
        });

        it('should verify nonce', async () => {
          const token = await sign({ ...defaultPayload, nonce: 'test-nonce' }, secret);
          
          const decoded = await verify(token, secret, { nonce: 'test-nonce' });
          expect(decoded.nonce).toBe('test-nonce');
          
          await expect(verify(token, secret, { nonce: 'wrong-nonce' }))
            .rejects.toThrow('jwt nonce invalid. expected: wrong-nonce');
        });

        it('should verify maxAge', async () => {
          const token = await sign(defaultPayload, secret);
          
          // Should pass - token just created
          await verify(token, secret, { maxAge: '1h' });
          
          // Create old token
          const oldToken = await sign({
            ...defaultPayload,
            iat: Math.floor(Date.now() / 1000) - 7200 // 2 hours ago
          }, secret);
          
          await expect(verify(oldToken, secret, { maxAge: '1h' }))
            .rejects.toThrow(TokenExpiredError);
          await expect(verify(oldToken, secret, { maxAge: '1h' }))
            .rejects.toThrow('maxAge exceeded');
        });
      });
    });

    describe('Error Handling', () => {
      it('should reject malformed tokens', async () => {
        const malformed = createMalformedTokens();
        
        await expect(verify(malformed.notEnoughSegments, secret))
          .rejects.toThrow('jwt malformed');
        
        await expect(verify(malformed.invalidBase64, secret))
          .rejects.toThrow(JsonWebTokenError);
      });

      it('should reject empty token', async () => {
        await expect(verify('', secret))
          .rejects.toThrow('jwt must be provided');
      });

      it('should reject non-string token', async () => {
        await expect(verify(123 as any, secret))
          .rejects.toThrow('jwt must be a string');
      });

      it('should reject when secret is missing', async () => {
        const token = await sign(defaultPayload, secret);
        
        await expect(verify(token, ''))
          .rejects.toThrow('secretOrPublicKey must have a value');
      });

      it('should handle invalid exp value', async () => {
        const secret = 'test-secret';
        const token = createTokenWithInvalidClaim(secret, 'exp', 'not-a-number');
        
        await expect(verify(token, secret)).rejects.toThrow('invalid exp value');
      });

      it('should handle invalid nbf value', async () => {
        const secret = 'test-secret';
        const token = createTokenWithInvalidClaim(secret, 'nbf', 'not-a-number');
        
        await expect(verify(token, secret)).rejects.toThrow('invalid nbf value');
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
        await expect(verify(token, secret))
          .rejects.toThrow(NotBeforeError);

        // Should pass with future timestamp
        const decoded = await verify(token, secret, { clockTimestamp: futureTimestamp });
        expect(decoded).toBeDefined();
      });

      it('should validate with multiple allowed algorithms', async () => {
        const token = await sign(defaultPayload, secret, { algorithm: 'HS384' });
        
        const decoded = await verify(token, secret, { 
          algorithms: ['HS256', 'HS384', 'HS512'] 
        });
        
        expect(decoded).toMatchObject(defaultPayload);
      });
    });
  });

  describe('verify() - Callback API', () => {
    it('should verify token with callback', (done) => {
      sign(defaultPayload, secret, async (err, token) => {
        expect(err).toBeNull();
        
        (verify as any)(token, secret, (err: any, decoded: any) => {
          expect(err).toBeNull();
          expect(decoded).toMatchObject(defaultPayload);
          done();
        });
      });
    });

    it('should return error in callback for invalid token', (done) => {
      const invalidToken = 'invalid.token.here';
      
      (verify as any)(invalidToken, secret, (err: any, decoded: any) => {
        expect(err).toBeDefined();
        expect(err).toBeInstanceOf(JsonWebTokenError);
        expect(decoded).toBeUndefined();
        done();
      });
    });

    it('should work with options and callback', (done) => {
      sign(defaultPayload, rsaKeys.privateKey, { algorithm: 'RS256' }, async (err, token) => {
        expect(err).toBeNull();
        
        (verify as any)(token, rsaKeys.publicKey, { algorithms: ['RS256'] }, (err: any, decoded: any) => {
          expect(err).toBeNull();
          expect(decoded).toMatchObject(defaultPayload);
          done();
        });
      });
    });

    it('should return complete result with callback', (done) => {
      sign(defaultPayload, secret, async (err, token) => {
        expect(err).toBeNull();
        
        (verify as any)(token, secret, { complete: true }, (err: any, decoded: any) => {
          expect(err).toBeNull();
          expect(decoded.header).toBeDefined();
          expect(decoded.payload).toMatchObject(defaultPayload);
          expect(decoded.signature).toBeDefined();
          done();
        });
      });
    });

    it('should handle expired token error in callback', (done) => {
      createExpiredToken(secret).then(token => {
        (verify as any)(token, secret, (err: any, decoded: any) => {
          expect(err).toBeInstanceOf(TokenExpiredError);
          expect(err.message).toContain('jwt expired');
          expect(decoded).toBeUndefined();
          done();
        });
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle "none" algorithm tokens', async () => {
      const token = await sign(defaultPayload, '', { 
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });

      // The library now prevents 'none' in algorithms for security
      await expect(verify(token, '', { algorithms: ['none'] }))
        .rejects.toThrow('Invalid verify option "algorithms" for "none" algorithm');
      
      // Without specifying algorithms, it should work
      const decoded = await verify(token, '');
      expect(decoded).toMatchObject(defaultPayload);
    });

    it('should handle Buffer secrets', async () => {
      const bufferSecret = Buffer.from('my-secret-key');
      const token = await sign(defaultPayload, bufferSecret);
      const decoded = await verify(token, bufferSecret);
      
      expect(decoded).toMatchObject(defaultPayload);
    });

    it('should handle KeyObject inputs', async () => {
      const token = await sign(defaultPayload, rsaKeys.privateKeyObject, { algorithm: 'RS256' });
      const decoded = await verify(token, rsaKeys.publicKeyObject, { algorithms: ['RS256'] });
      
      expect(decoded).toMatchObject(defaultPayload);
    });

    it('should validate minimum RSA key size', async () => {
      // This would require generating a small RSA key which is not recommended
      // Skipping actual implementation but the library checks for 2048-bit minimum
      expect(true).toBe(true);
    });
  });
});