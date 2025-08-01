const { describe, it } = require('@jest/globals');
const jwt = require('../dist/index');
const fs = require('fs');
const path = require('path');

describe('Algorithm Integration Tests', () => {
  const payload = {
    sub: '1234567890',
    name: 'John Doe',
    admin: true,
    iat: Math.floor(Date.now() / 1000)
  };

  // Load test keys
  const hmacSecret = 'your-256-bit-secret';
  const rsaPrivateKey = fs.readFileSync(path.join(__dirname, 'priv.pem'));
  const rsaPublicKey = fs.readFileSync(path.join(__dirname, 'pub.pem'));
  const ecPrivateKey = fs.readFileSync(path.join(__dirname, 'ecdsa-private.pem'));
  const ecPublicKey = fs.readFileSync(path.join(__dirname, 'ecdsa-public.pem'));
  const ed25519PrivateKey = fs.readFileSync(path.join(__dirname, 'ed25519-private.pem'));
  const ed25519PublicKey = fs.readFileSync(path.join(__dirname, 'ed25519-public.pem'));

  describe('HMAC Algorithms', () => {
    ['HS256', 'HS384', 'HS512'].forEach(algorithm => {
      it(`should sign and verify JWT with ${algorithm}`, async () => {
        const token = await jwt.sign(payload, hmacSecret, { algorithm });
        expect(typeof token).toBe('string');
        expect(token.split('.')).toHaveLength(3);

        const decoded = await jwt.verify(token, hmacSecret, { algorithms: [algorithm] });
        expect(decoded.sub).toBe(payload.sub);
        expect(decoded.name).toBe(payload.name);
        expect(decoded.admin).toBe(payload.admin);
      });

      it(`should reject ${algorithm} token with wrong secret`, async () => {
        const token = await jwt.sign(payload, hmacSecret, { algorithm });

        await expect(jwt.verify(token, 'wrong-secret', { algorithms: [algorithm] }))
          .rejects.toThrow('invalid signature');
      });
    });
  });

  describe('RSA Algorithms', () => {
    ['RS256', 'RS384', 'RS512'].forEach(algorithm => {
      it(`should sign and verify JWT with ${algorithm}`, async () => {
        const token = await jwt.sign(payload, rsaPrivateKey, { algorithm });
        expect(typeof token).toBe('string');
        expect(token.split('.')).toHaveLength(3);

        const decoded = await jwt.verify(token, rsaPublicKey, { algorithms: [algorithm] });
        expect(decoded.sub).toBe(payload.sub);
        expect(decoded.name).toBe(payload.name);
        expect(decoded.admin).toBe(payload.admin);
      });

      it(`should reject ${algorithm} token with wrong public key`, async () => {
        const token = await jwt.sign(payload, rsaPrivateKey, { algorithm });
        const wrongKey = fs.readFileSync(path.join(__dirname, 'invalid_pub.pem'));

        await expect(jwt.verify(token, wrongKey, { algorithms: [algorithm] }))
          .rejects.toThrow('invalid signature');
      });
    });
  });

  describe('RSA-PSS Algorithms', () => {
    ['PS256', 'PS384', 'PS512'].forEach(algorithm => {
      it(`should sign and verify JWT with ${algorithm}`, async () => {
        const token = await jwt.sign(payload, rsaPrivateKey, { algorithm });
        expect(typeof token).toBe('string');
        expect(token.split('.')).toHaveLength(3);

        const decoded = await jwt.verify(token, rsaPublicKey, { algorithms: [algorithm] });
        expect(decoded.sub).toBe(payload.sub);
        expect(decoded.name).toBe(payload.name);
        expect(decoded.admin).toBe(payload.admin);
      });

      it(`should produce different signatures each time with ${algorithm}`, async () => {
        const token1 = await jwt.sign(payload, rsaPrivateKey, { algorithm });
        const token2 = await jwt.sign(payload, rsaPrivateKey, { algorithm });

        // Headers and payloads should be the same
        const parts1 = token1.split('.');
        const parts2 = token2.split('.');
        expect(parts1[0]).toBe(parts2[0]); // header
        expect(parts1[1]).toBe(parts2[1]); // payload

        // But signatures should be different (probabilistic)
        expect(parts1[2]).not.toBe(parts2[2]);

        // Both should verify correctly
        const decoded1 = await jwt.verify(token1, rsaPublicKey, { algorithms: [algorithm] });
        const decoded2 = await jwt.verify(token2, rsaPublicKey, { algorithms: [algorithm] });
        expect(decoded1).toEqual(decoded2);
      });
    });
  });

  describe('ECDSA Algorithms', () => {
    ['ES256'].forEach(algorithm => {
      it(`should sign and verify JWT with ${algorithm}`, async () => {
        const token = await jwt.sign(payload, ecPrivateKey, { algorithm });
        expect(typeof token).toBe('string');
        expect(token.split('.')).toHaveLength(3);

        const decoded = await jwt.verify(token, ecPublicKey, { algorithms: [algorithm] });
        expect(decoded.sub).toBe(payload.sub);
        expect(decoded.name).toBe(payload.name);
        expect(decoded.admin).toBe(payload.admin);
      });

      it(`should produce different signatures each time with ${algorithm}`, async () => {
        const token1 = await jwt.sign(payload, ecPrivateKey, { algorithm });
        const token2 = await jwt.sign(payload, ecPrivateKey, { algorithm });

        // Headers and payloads should be the same
        const parts1 = token1.split('.');
        const parts2 = token2.split('.');
        expect(parts1[0]).toBe(parts2[0]); // header
        expect(parts1[1]).toBe(parts2[1]); // payload

        // But signatures should be different (probabilistic)
        expect(parts1[2]).not.toBe(parts2[2]);
      });
    });
  });

  describe('EdDSA Algorithm', () => {
    it('should sign and verify JWT with EdDSA', async () => {
      const token = await jwt.sign(payload, ed25519PrivateKey, { algorithm: 'EdDSA' });
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);

      const decoded = await jwt.verify(token, ed25519PublicKey, { algorithms: ['EdDSA'] });
      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.name).toBe(payload.name);
      expect(decoded.admin).toBe(payload.admin);
    });

    it('should produce same signature each time with EdDSA (deterministic)', async () => {
      const token1 = await jwt.sign(payload, ed25519PrivateKey, { algorithm: 'EdDSA' });
      const token2 = await jwt.sign(payload, ed25519PrivateKey, { algorithm: 'EdDSA' });

      // EdDSA is deterministic, so tokens should be identical
      expect(token1).toBe(token2);
    });
  });

  describe('Cross-algorithm security', () => {
    it('should not verify HS256 token as RS256', async () => {
      const token = await jwt.sign(payload, hmacSecret, { algorithm: 'HS256' });

      await expect(jwt.verify(token, rsaPublicKey, { algorithms: ['RS256'] }))
        .rejects.toThrow('invalid algorithm');
    });

    it('should not verify RS256 token as HS256', async () => {
      const token = await jwt.sign(payload, rsaPrivateKey, { algorithm: 'RS256' });

      await expect(jwt.verify(token, hmacSecret, { algorithms: ['HS256'] }))
        .rejects.toThrow('invalid algorithm');
    });

    it('should enforce algorithm whitelist', async () => {
      const token = await jwt.sign(payload, hmacSecret, { algorithm: 'HS256' });

      // Try to verify with different algorithm in whitelist
      await expect(jwt.verify(token, hmacSecret, { algorithms: ['HS384', 'HS512'] }))
        .rejects.toThrow('invalid algorithm');
    });
  });

  describe('Decode functionality', () => {
    it('should decode without verification', () => {
      const token = jwt.sign(payload, hmacSecret, { algorithm: 'HS256' });

      const decoded = jwt.decode(token);
      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.name).toBe(payload.name);
      expect(decoded.admin).toBe(payload.admin);
    });

    it('should decode with complete option', () => {
      const token = jwt.sign(payload, hmacSecret, { algorithm: 'HS256' });

      const decoded = jwt.decode(token, { complete: true });
      expect(decoded.header.alg).toBe('HS256');
      expect(decoded.header.typ).toBe('JWT');
      expect(decoded.payload.sub).toBe(payload.sub);
      expect(decoded.signature).toBeTruthy();
    });
  });

  describe('Options and claims', () => {
    it('should handle expiresIn option', async () => {
      const token = await jwt.sign(payload, hmacSecret, {
        algorithm: 'HS256',
        expiresIn: '1h'
      });

      const decoded = await jwt.verify(token, hmacSecret);
      expect(decoded.exp).toBeDefined();
      expect(decoded.exp).toBeGreaterThan(decoded.iat);
    });

    it('should handle notBefore option', async () => {
      const token = await jwt.sign(payload, hmacSecret, {
        algorithm: 'HS256',
        notBefore: '1s'
      });

      const decoded = await jwt.verify(token, hmacSecret);
      expect(decoded.nbf).toBeDefined();
    });

    it('should handle audience option', async () => {
      const token = await jwt.sign(payload, hmacSecret, {
        algorithm: 'HS256',
        audience: 'myapp'
      });

      const decoded = await jwt.verify(token, hmacSecret, { audience: 'myapp' });
      expect(decoded.aud).toBe('myapp');
    });

    it('should handle issuer option', async () => {
      const token = await jwt.sign(payload, hmacSecret, {
        algorithm: 'HS256',
        issuer: 'myissuer'
      });

      const decoded = await jwt.verify(token, hmacSecret, { issuer: 'myissuer' });
      expect(decoded.iss).toBe('myissuer');
    });
  });

  describe('Error handling', () => {
    it('should throw on expired token', async () => {
      const token = await jwt.sign(payload, hmacSecret, {
        algorithm: 'HS256',
        expiresIn: '-1s' // Already expired
      });

      await expect(jwt.verify(token, hmacSecret))
        .rejects.toThrow('jwt expired');
    });

    it('should throw on token not active yet', async () => {
      const token = await jwt.sign(payload, hmacSecret, {
        algorithm: 'HS256',
        notBefore: '1h' // Not active for another hour
      });

      await expect(jwt.verify(token, hmacSecret))
        .rejects.toThrow('jwt not active');
    });

    it('should throw on malformed token', async () => {
      await expect(jwt.verify('not.a.token', hmacSecret))
        .rejects.toThrow('jwt malformed');
    });

    it('should throw on invalid token', async () => {
      await expect(jwt.verify('invalid.token.here', hmacSecret))
        .rejects.toThrow();
    });
  });
});