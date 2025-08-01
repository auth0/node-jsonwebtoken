const { describe, it, expect, beforeEach } = require('@jest/globals');
const jwt = require('../');

describe('none algorithm', () => {
  const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

  describe('signing', () => {
    it('should throw error when allowInsecureNoneAlgorithm is not set', async () => {
      const payload = {foo: 'bar'};

      await expect(
        jwt.sign(payload, '', {algorithm: 'none'})
      ).rejects.toThrow(/The "none" algorithm is insecure and disabled by default/);
    });

    it('should create unsigned token when allowInsecureNoneAlgorithm is true', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };

      // Capture console.warn
      const originalWarn = console.warn;
      let warnMessage = '';
      console.warn = (msg) => { warnMessage = msg; };

      try {
        const token = await jwt.sign(payload, '', options);
        const parts = token.split('.');

        expect(parts).toHaveLength(3);
        expect(parts[0]).toBe(noneAlgorithmHeader);
        expect(parts[2]).toBe(''); // Empty signature

        // Verify payload
        const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        expect(decodedPayload.foo).toBe('bar');
        expect(typeof decodedPayload.iat).toBe('number');

        // Check warning was logged
        expect(warnMessage).toMatch(/WARNING: JWT signed with "none" algorithm/);
      } finally {
        console.warn = originalWarn;
      }
    });

    it('should work with string payload', async () => {
      const payload = 'a string payload';
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };

      const token = await jwt.sign(payload, '', options);
      const parts = token.split('.');

      expect(parts).toHaveLength(3);
      expect(parts[2]).toBe(''); // Empty signature

      // Verify it's not typed as JWT
      const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      expect(header.typ).toBeUndefined();
    });

    it('should include standard claims when specified', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true,
        expiresIn: '1h',
        notBefore: '1m',
        issuer: 'test-issuer',
        subject: 'test-subject',
        audience: 'test-audience',
        jwtid: 'test-jwtid'
      };

      const token = await jwt.sign(payload, '', options);
      const decoded = jwt.decode(token);

      expect(decoded.foo).toBe('bar');
      expect(typeof decoded.exp).toBe('number');
      expect(typeof decoded.nbf).toBe('number');
      expect(decoded.iss).toBe('test-issuer');
      expect(decoded.sub).toBe('test-subject');
      expect(decoded.aud).toBe('test-audience');
      expect(decoded.jti).toBe('test-jwtid');
    });

    it('should accept null as secret parameter', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };

      const token = await jwt.sign(payload, null, options);
      const parts = token.split('.');
      expect(parts[2]).toBe('');
    });

    it('should accept undefined as secret parameter', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };

      const token = await jwt.sign(payload, undefined, options);
      const parts = token.split('.');
      expect(parts[2]).toBe('');
    });
  });

  describe('verifying', () => {
    let token;

    beforeEach(async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };
      token = await jwt.sign(payload, '', options);
    });

    it('should verify unsigned token without secret', async () => {
      // Capture console.warn
      const originalWarn = console.warn;
      let warnMessage = '';
      console.warn = (msg) => { warnMessage = msg; };

      try {
        const decoded = await jwt.verify(token, null, {algorithms: ['none']});
        expect(decoded.foo).toBe('bar');
        expect(warnMessage).toMatch(/WARNING: Verifying JWT with "none" algorithm/);
      } finally {
        console.warn = originalWarn;
      }
    });

    it('should verify with empty string secret', async () => {
      const decoded = await jwt.verify(token, '', {algorithms: ['none']});
      expect(decoded.foo).toBe('bar');
    });

    it('should fail if algorithms does not include none', async () => {
      await expect(
        jwt.verify(token, null, {algorithms: ['HS256']})
      ).rejects.toThrow('invalid algorithm');
    });

    it('should fail if token has signature', async () => {
      // Create a token with a fake signature
      const tamperedToken = `${token}fake-signature`;

      await expect(
        jwt.verify(tamperedToken, null, {algorithms: ['none']})
      ).rejects.toThrow('jwt signature must be empty for "none" algorithm');
    });

    it('should auto-detect none algorithm', async () => {
      const decoded = await jwt.verify(token, null);
      expect(decoded.foo).toBe('bar');
    });

    it('should work with verify complete option', async () => {
      const result = await jwt.verify(token, null, {algorithms: ['none'], complete: true});

      expect(result.header.alg).toBe('none');
      expect(result.header.typ).toBe('JWT');
      expect(result.payload.foo).toBe('bar');
      expect(result.signature).toBe('');
    });

    it('should verify expired token when ignoreExpiration is true', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true,
        expiresIn: '-1h' // Already expired
      };

      const expiredToken = await jwt.sign(payload, '', options);

      // Should fail without ignoreExpiration
      await expect(
        jwt.verify(expiredToken, null, {algorithms: ['none']})
      ).rejects.toThrow(jwt.TokenExpiredError);

      // Should pass with ignoreExpiration
      const decoded = await jwt.verify(expiredToken, null, {
        algorithms: ['none'],
        ignoreExpiration: true
      });
      expect(decoded.foo).toBe('bar');
    });

    it('should handle notBefore claim', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true,
        notBefore: '1h' // Not valid yet
      };

      const futureToken = await jwt.sign(payload, '', options);

      // Should fail without ignoreNotBefore
      await expect(
        jwt.verify(futureToken, null, {algorithms: ['none']})
      ).rejects.toThrow(jwt.NotBeforeError);

      // Should pass with ignoreNotBefore
      const decoded = await jwt.verify(futureToken, null, {
        algorithms: ['none'],
        ignoreNotBefore: true
      });
      expect(decoded.foo).toBe('bar');
    });

    it('should validate audience claim', async () => {
      const payload = {foo: 'bar', aud: 'expected-audience'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };

      const tokenWithAud = await jwt.sign(payload, '', options);

      // Should pass with correct audience
      const decoded = await jwt.verify(tokenWithAud, null, {
        algorithms: ['none'],
        audience: 'expected-audience'
      });
      expect(decoded.foo).toBe('bar');

      // Should fail with wrong audience
      await expect(
        jwt.verify(tokenWithAud, null, {
          algorithms: ['none'],
          audience: 'wrong-audience'
        })
      ).rejects.toThrow(/jwt audience invalid/);
    });
  });

  describe('decoding', () => {
    it('should decode unsigned token', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };

      const token = await jwt.sign(payload, '', options);
      const decoded = jwt.decode(token);

      expect(decoded.foo).toBe('bar');
      expect(typeof decoded.iat).toBe('number');
    });

    it('should decode with complete option', async () => {
      const payload = {foo: 'bar'};
      const options = {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      };

      const token = await jwt.sign(payload, '', options);
      const result = jwt.decode(token, {complete: true});

      expect(result.header.alg).toBe('none');
      expect(result.header.typ).toBe('JWT');
      expect(result.payload.foo).toBe('bar');
      expect(result.signature).toBe('');
    });
  });

  describe('security considerations', () => {
    it('should not accept none algorithm when mixed with other algorithms', async () => {
      const payload = {foo: 'bar'};
      const noneToken = await jwt.sign(payload, '', {
        algorithm: 'none',
        allowInsecureNoneAlgorithm: true
      });

      // Try to verify with both none and HS256
      await expect(
        jwt.verify(noneToken, 'secret', {algorithms: ['HS256', 'none']})
      ).rejects.toThrow();
    });

    it('should reject signed token as none algorithm', async () => {
      // Create a properly signed token
      const signedToken = await jwt.sign({foo: 'bar'}, 'secret', {algorithm: 'HS256'});

      // Try to verify it as 'none' algorithm
      await expect(
        jwt.verify(signedToken, null, {algorithms: ['none']})
      ).rejects.toThrow(jwt.JsonWebTokenError);
    });

    it('should handle malformed tokens', async () => {
      const malformedTokens = [
        'not.a.jwt',
        'eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ', // Only 2 parts
        'eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ..', // 4 parts
        '..' // Empty parts
      ];

      for (const malformedToken of malformedTokens) {
        await expect(
          jwt.verify(malformedToken, null, {algorithms: ['none']})
        ).rejects.toThrow(jwt.JsonWebTokenError);
      }
    });
  });
});