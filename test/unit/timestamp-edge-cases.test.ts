import { describe, it, expect } from '@jest/globals';
import jwt from '../../src/index.js';
import { JsonWebTokenError } from '../../src/lib/JsonWebTokenError.js';

describe('Timestamp Edge Cases', () => {
  const secret = 'test-secret';
  
  describe('MAX_SAFE_INTEGER timestamp attacks', () => {
    it('should reject iat at MAX_SAFE_INTEGER + 1', async () => {
      const payload = {
        iat: Number.MAX_SAFE_INTEGER + 1,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/iat.*should be a number of seconds between 0 and/);
    });

    it('should reject exp at MAX_SAFE_INTEGER + 1', async () => {
      const payload = {
        exp: Number.MAX_SAFE_INTEGER + 1,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/exp.*should be a number of seconds between 0 and/);
    });

    it('should reject nbf at MAX_SAFE_INTEGER + 1', async () => {
      const payload = {
        nbf: Number.MAX_SAFE_INTEGER + 1,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/nbf.*should be a number of seconds between 0 and/);
    });

    it('should accept timestamps at exactly MAX_SAFE_INTEGER', async () => {
      const payload = {
        iat: Number.MAX_SAFE_INTEGER,
        exp: Number.MAX_SAFE_INTEGER,
        nbf: Number.MAX_SAFE_INTEGER - 1000,
        data: 'test'
      };
      
      const token = await jwt.sign(payload, secret, { noTimestamp: true });
      expect(token).toBeTruthy();
      
      // Decode to verify values
      const decoded = jwt.decode(token) as any;
      expect(decoded.iat).toBe(Number.MAX_SAFE_INTEGER);
      expect(decoded.exp).toBe(Number.MAX_SAFE_INTEGER);
      expect(decoded.nbf).toBe(Number.MAX_SAFE_INTEGER - 1000);
    });

    it('should reject clockTimestamp at MAX_SAFE_INTEGER + 1', async () => {
      const token = await jwt.sign({ data: 'test' }, secret);
      
      await expect(jwt.verify(token, secret, {
        clockTimestamp: Number.MAX_SAFE_INTEGER + 1
      })).rejects.toThrow(/clockTimestamp.*must be between 0 and/);
    });
  });

  describe('Negative timestamp attacks', () => {
    it('should reject negative iat', async () => {
      const payload = {
        iat: -1,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/iat.*should be a number of seconds between 0 and/);
    });

    it('should reject negative exp', async () => {
      const payload = {
        exp: -1000,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/exp.*should be a number of seconds between 0 and/);
    });

    it('should reject negative nbf', async () => {
      const payload = {
        nbf: -999999,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/nbf.*should be a number of seconds between 0 and/);
    });

    it('should reject negative clockTimestamp', async () => {
      const token = await jwt.sign({ data: 'test' }, secret);
      
      await expect(jwt.verify(token, secret, {
        clockTimestamp: -1000
      })).rejects.toThrow(/clockTimestamp.*must be between 0 and/);
    });

    it('should handle tokens with negative timestamps during verify', async () => {
      // Manually create a token with negative timestamps
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ 
        iat: -1000,
        exp: -500,
        nbf: -2000,
        data: 'test' 
      })).toString('base64url');
      
      // Create a fake signature
      const fakeToken = `${header}.${payload}.fake-signature`;
      
      // Verify should fail - could be either invalid signature or timestamp validation
      await expect(jwt.verify(fakeToken, secret))
        .rejects.toThrow();
    });
  });

  describe('Clock tolerance edge cases', () => {
    it('should reject negative clockTolerance', async () => {
      const token = await jwt.sign({ exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
      
      await expect(jwt.verify(token, secret, {
        clockTolerance: -1
      })).rejects.toThrow(/clockTolerance must not be negative/);
    });

    it('should reject clockTolerance exceeding 5 years', async () => {
      const token = await jwt.sign({ exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
      
      await expect(jwt.verify(token, secret, {
        clockTolerance: 157680001 // 5 years + 1 second
      })).rejects.toThrow(/clockTolerance must not exceed.*5 years/);
    });

    it('should accept clockTolerance at exactly 5 years', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await jwt.sign({ 
        exp: now - 100, // Expired 100 seconds ago
        data: 'test' 
      }, secret);
      
      // Should normally be expired
      await expect(jwt.verify(token, secret))
        .rejects.toThrow(/jwt expired/);
      
      // But with 5 year tolerance, should be valid
      const decoded = await jwt.verify(token, secret, {
        clockTolerance: 157680000 // Exactly 5 years
      });
      expect(decoded).toBeTruthy();
    });

    it('should reject non-numeric clockTolerance', async () => {
      const token = await jwt.sign({ data: 'test' }, secret);
      
      await expect(jwt.verify(token, secret, {
        clockTolerance: 'invalid' as any
      })).rejects.toThrow(/clockTolerance must be a number/);
    });

    it('should reject NaN clockTolerance', async () => {
      const token = await jwt.sign({ data: 'test' }, secret);
      
      await expect(jwt.verify(token, secret, {
        clockTolerance: NaN
      })).rejects.toThrow(/clockTolerance must be a number/);
    });
  });

  describe('Timestamp calculation edge cases', () => {
    it('should handle timestamp calculations approaching MAX_SAFE_INTEGER', async () => {
      const almostMax = Number.MAX_SAFE_INTEGER - 10000;
      
      // This should fail because adding expiresIn would exceed MAX_SAFE_INTEGER
      await expect(jwt.sign({ data: 'test' }, secret, {
        noTimestamp: false,
        iat: almostMax,
        expiresIn: 20000 // Would exceed MAX_SAFE_INTEGER
      })).rejects.toThrow();
    });

    it('should validate generated exp timestamp', async () => {
      // Create a token with current time close to MAX_SAFE_INTEGER
      const mockNow = Number.MAX_SAFE_INTEGER - 1000;
      
      // Mock Date.now() would be complex, so we'll test by providing iat
      const payload = {
        iat: mockNow,
        data: 'test'
      };
      
      // This should fail because exp would exceed MAX_SAFE_INTEGER
      await expect(jwt.sign(payload, secret, {
        expiresIn: 2000 // Would make exp > MAX_SAFE_INTEGER
      })).rejects.toThrow(/exp.*must be between 0 and/);
    });

    it('should validate generated nbf timestamp', async () => {
      const mockNow = Number.MAX_SAFE_INTEGER - 1000;
      
      const payload = {
        iat: mockNow,
        data: 'test'
      };
      
      // This should fail because nbf would exceed MAX_SAFE_INTEGER
      await expect(jwt.sign(payload, secret, {
        notBefore: 2000 // Would make nbf > MAX_SAFE_INTEGER
      })).rejects.toThrow(/nbf.*must be between 0 and/);
    });
  });

  describe('Combined timestamp attacks', () => {
    it('should handle multiple invalid timestamps', async () => {
      const payload = {
        iat: -1000,
        exp: Number.MAX_SAFE_INTEGER + 1,
        nbf: -5000,
        data: 'test'
      };
      
      // Should fail on the first invalid timestamp found
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/should be a number of seconds between 0 and/);
    });

    it('should validate all timestamps during verify', async () => {
      // Create a valid token first
      const token = await jwt.sign({ data: 'test' }, secret);
      
      // Try to verify with invalid options
      await expect(jwt.verify(token, secret, {
        clockTimestamp: -1000,
        clockTolerance: -100
      })).rejects.toThrow(); // Should fail on validation
    });
  });

  describe('Infinity and special values', () => {
    it('should reject Infinity timestamps', async () => {
      const payload = {
        iat: Infinity,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/iat.*should be a number of seconds/);
    });

    it('should reject -Infinity timestamps', async () => {
      const payload = {
        exp: -Infinity,
        data: 'test'
      };
      
      await expect(jwt.sign(payload, secret))
        .rejects.toThrow(/exp.*should be a number of seconds/);
    });

    it('should handle undefined timestamps properly', async () => {
      const payload = {
        data: 'test'
      };
      
      // undefined timestamps should be ignored
      const token = await jwt.sign(payload, secret);
      const decoded = jwt.decode(token) as any;
      expect(decoded.nbf).toBeUndefined();
      expect(decoded.exp).toBeUndefined();
      // iat will be added automatically unless noTimestamp is true
      expect(decoded.iat).toBeDefined();
    });
  });
});