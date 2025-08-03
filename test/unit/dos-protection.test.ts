import { describe, it, expect } from '@jest/globals';
import jwt from '../../src/index.js';
import { JsonWebTokenError } from '../../src/lib/JsonWebTokenError.js';
import { generateRSAKeyPair } from '../helpers/key-generator.js';

// Generate test keys
const { privateKey, publicKey } = generateRSAKeyPair();

describe('DoS Protection', () => {
  describe('Token Size Limits', () => {
    it('should reject tokens exceeding default size limit', async () => {
      // Create a large payload that will exceed 250KB when encoded
      const largePayload = {
        data: 'A'.repeat(300 * 1024) // 300KB of data
      };
      
      await expect(jwt.sign(largePayload, 'secret'))
        .rejects.toThrow(/JWT exceeds maximum allowed size/);
    });

    it('should throw with correct error message for token size limit', async () => {
      // Create a payload that will result in specific token size
      const largePayload = {
        data: 'A'.repeat(300 * 1024) // 300KB of data
      };
      
      try {
        await jwt.sign(largePayload, 'secret');
        // Should not reach here
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.message).toMatch(/JWT exceeds maximum allowed size of \d+ bytes \(actual: \d+ bytes\)/);
      }
    });

    it('should accept tokens within size limit', async () => {
      const normalPayload = {
        sub: '1234567890',
        name: 'John Doe',
        data: 'A'.repeat(1024) // 1KB of data
      };
      
      const token = await jwt.sign(normalPayload, 'secret');
      const decoded = await jwt.verify(token, 'secret');
      expect(decoded).toMatchObject(normalPayload);
    });

    it('should respect custom token size limit', async () => {
      const payload = {
        data: 'A'.repeat(10 * 1024) // 10KB of data
      };
      
      // Set a 5KB limit
      await expect(jwt.sign(payload, 'secret', { maxTokenSize: 5 * 1024 }))
        .rejects.toThrow(/JWT exceeds maximum allowed size of 5120 bytes/);
    });

    it('should validate token size during decode', () => {
      // Create a fake large token
      const largeToken = 'header.' + 'A'.repeat(300 * 1024) + '.signature';
      
      const decoded = jwt.decode(largeToken);
      expect(decoded).toBeNull(); // Decode returns null on size violation
    });

    it('should validate token size during verify', async () => {
      // Create a fake large token
      const largeToken = 'header.' + 'A'.repeat(300 * 1024) + '.signature';
      
      await expect(jwt.verify(largeToken, 'secret'))
        .rejects.toThrow(/JWT exceeds maximum allowed size/);
    });

    it('should allow disabling token size protection', async () => {
      const largePayload = {
        data: 'A'.repeat(300 * 1024) // 300KB
      };
      
      // This should work with protection disabled
      const token = await jwt.sign(largePayload, 'secret', { 
        disableDoSProtection: true 
      });
      
      const decoded = await jwt.verify(token, 'secret', {
        disableDoSProtection: true
      });
      
      expect(decoded.data).toBe(largePayload.data);
    });
  });

  describe('Payload Depth Limits', () => {
    it('should reject deeply nested payloads', async () => {
      // Create a deeply nested object
      let payload: any = { value: 'bottom' };
      for (let i = 0; i < 60; i++) {
        payload = { nested: payload };
      }
      
      await expect(jwt.sign(payload, 'secret'))
        .rejects.toThrow(/JWT payload exceeds maximum allowed depth/);
    });

    it('should throw with correct error message for depth limit', async () => {
      // Create object with depth 51
      let payload: any = { value: 'bottom' };
      for (let i = 0; i < 51; i++) {
        payload = { nested: payload };
      }
      
      try {
        await jwt.sign(payload, 'secret');
        // Should not reach here
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.message).toBe('JWT payload exceeds maximum allowed depth of 50 (actual: 52)');
      }
    });

    it('should accept payloads within depth limit', async () => {
      // Create a moderately nested object (depth 10)
      let payload: any = { value: 'bottom' };
      for (let i = 0; i < 10; i++) {
        payload = { nested: payload };
      }
      
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret') as any;
      // Remove iat for comparison
      delete decoded.iat;
      expect(decoded).toEqual(payload);
    });

    it('should respect custom depth limit', async () => {
      // Create object with depth 6
      let payload: any = { value: 'bottom' };
      for (let i = 0; i < 6; i++) {
        payload = { nested: payload };
      }
      
      // Set depth limit to 5
      await expect(jwt.sign(payload, 'secret', { maxPayloadDepth: 5 }))
        .rejects.toThrow(/JWT payload exceeds maximum allowed depth of 5/);
    });

    it('should handle arrays in depth calculation', async () => {
      const payload = {
        level1: [
          {
            level2: [
              {
                level3: {
                  level4: 'deep'
                }
              }
            ]
          }
        ]
      };
      
      // This has depth of 5, should work with default limit
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret') as any;
      // Remove iat for comparison
      delete decoded.iat;
      expect(decoded).toEqual(payload);
    });

    it('should not apply depth limit to string payloads', async () => {
      const stringPayload = 'This is a simple string payload';
      
      // String payloads are not supported in the current implementation
      // They get wrapped in an object during sign
      const token = await jwt.sign({ data: stringPayload }, 'secret');
      const decoded = await jwt.verify(token, 'secret') as any;
      expect(decoded.data).toBe(stringPayload);
    });
  });

  describe('Claim Count Limits', () => {
    it('should reject payloads with too many claims', async () => {
      // Create payload with 1500 claims
      const payload: any = {};
      for (let i = 0; i < 1500; i++) {
        payload[`claim${i}`] = `value${i}`;
      }
      
      await expect(jwt.sign(payload, 'secret'))
        .rejects.toThrow(/JWT payload exceeds maximum allowed claim count/);
    });

    it('should throw with correct error message for claim count limit', async () => {
      // Create payload with 1001 claims
      const payload: any = {};
      for (let i = 0; i < 1001; i++) {
        payload[`claim${i}`] = `value${i}`;
      }
      
      try {
        await jwt.sign(payload, 'secret');
        // Should not reach here
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.message).toBe('JWT payload exceeds maximum allowed claim count of 1000 (actual: 1001)');
      }
    });

    it('should accept payloads within claim limit', async () => {
      // Create payload with 100 claims
      const payload: any = {};
      for (let i = 0; i < 100; i++) {
        payload[`claim${i}`] = `value${i}`;
      }
      
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret');
      expect(Object.keys(decoded).length).toBeGreaterThanOrEqual(100);
    });

    it('should respect custom claim count limit', async () => {
      // Create payload with 15 claims
      const payload: any = {};
      for (let i = 0; i < 15; i++) {
        payload[`claim${i}`] = `value${i}`;
      }
      
      // Set limit to 10
      await expect(jwt.sign(payload, 'secret', { maxClaimCount: 10 }))
        .rejects.toThrow(/JWT payload exceeds maximum allowed claim count of 10/);
    });

    it('should count nested claims correctly', async () => {
      const payload = {
        user: {
          id: '123',
          profile: {
            name: 'John',
            email: 'john@example.com'
          }
        },
        permissions: ['read', 'write'],
        metadata: {
          created: '2024-01-01',
          updated: '2024-01-02'
        }
      };
      
      // This has 9 total claims (including nested), should work
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret') as any;
      // Remove iat for comparison
      delete decoded.iat;
      expect(decoded).toEqual(payload);
    });

    it('should handle circular references safely', async () => {
      const payload: any = { id: '123' };
      payload.circular = payload; // Create circular reference
      
      // Should handle circular reference without infinite loop
      await expect(jwt.sign(payload, 'secret'))
        .rejects.toThrow(); // Will throw due to JSON.stringify circular reference
    });
  });

  describe('Payload Size Limits', () => {
    it('should reject payloads exceeding size limit', async () => {
      const largePayload = {
        data: 'B'.repeat(150 * 1024) // 150KB payload
      };
      
      await expect(jwt.sign(largePayload, 'secret'))
        .rejects.toThrow(/JWT payload exceeds maximum allowed size/);
    });

    it('should throw with correct error message for payload size limit', async () => {
      const largePayload = {
        data: 'B'.repeat(150 * 1024) // 150KB payload
      };
      
      try {
        await jwt.sign(largePayload, 'secret');
        fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).toMatch(/JWT payload exceeds maximum allowed size of \d+ bytes \(actual: \d+ bytes\)/);
      }
    });

    it('should accept payloads within size limit', async () => {
      const normalPayload = {
        data: 'B'.repeat(50 * 1024) // 50KB payload
      };
      
      const token = await jwt.sign(normalPayload, 'secret');
      const decoded = await jwt.verify(token, 'secret');
      expect(decoded.data).toBe(normalPayload.data);
    });

    it('should respect custom payload size limit', async () => {
      const payload = {
        data: 'B'.repeat(2 * 1024) // 2KB
      };
      
      // Set limit to 1KB
      await expect(jwt.sign(payload, 'secret', { maxPayloadSize: 1024 }))
        .rejects.toThrow(/JWT payload exceeds maximum allowed size of 1024 bytes/);
    });
  });

  describe('Combined Attack Scenarios', () => {
    it('should handle combined large and deep payload', async () => {
      // Create a moderately deep object with large data
      let payload: any = { 
        data: 'X'.repeat(50 * 1024), // 50KB at bottom
        metadata: { count: 1000 }
      };
      
      for (let i = 0; i < 55; i++) {
        payload = { level: i, nested: payload };
      }
      
      // Should fail on depth (exceeds default of 50)
      await expect(jwt.sign(payload, 'secret'))
        .rejects.toThrow(/JWT payload exceeds maximum allowed depth/);
    });

    it('should validate all limits during decode', () => {
      // Create a complex payload manually
      const complexPayload: any = {};
      for (let i = 0; i < 100; i++) {
        complexPayload[`key${i}`] = { nested: { value: 'data'.repeat(100) } };
      }
      
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify(complexPayload)).toString('base64url');
      const fakeToken = `${header}.${payload}.signature`;
      
      // Decode with strict limits
      const decoded = jwt.decode(fakeToken, {
        maxPayloadSize: 1024,
        maxClaimCount: 50
      });
      
      expect(decoded).toBeNull(); // Should fail validation
    });

    it('should validate all limits during verify', async () => {
      // First create a valid but large token with DoS protection disabled
      const payload: any = {};
      for (let i = 0; i < 100; i++) {
        payload[`claim${i}`] = `value${i}`;
      }
      
      const token = await jwt.sign(payload, 'secret', {
        disableDoSProtection: true
      });
      
      // Now verify with strict limits - the decode inside verify will catch it
      await expect(jwt.verify(token, 'secret', {
        maxClaimCount: 50
      })).rejects.toThrow(/invalid token/);
    });
  });

  describe('Configuration Validation', () => {
    it('should reject negative size limits', async () => {
      await expect(jwt.sign({ foo: 'bar' }, 'secret', {
        maxTokenSize: -1
      })).rejects.toThrow('"maxTokenSize" must be a positive number');
    });

    it('should reject zero size limits', async () => {
      await expect(jwt.sign({ foo: 'bar' }, 'secret', {
        maxPayloadSize: 0
      })).rejects.toThrow('"maxPayloadSize" must be a positive number');
    });

    it('should reject non-number limits', async () => {
      await expect(jwt.sign({ foo: 'bar' }, 'secret', {
        maxPayloadDepth: '50' as any
      })).rejects.toThrow('"maxPayloadDepth" must be a positive number');
    });

    it('should allow all operations with protection disabled', async () => {
      // Create a worst-case payload
      let deepPayload: any = { data: 'X'.repeat(100 * 1024) };
      for (let i = 0; i < 80; i++) {
        deepPayload = { [`level${i}`]: deepPayload };
      }
      
      const options = { disableDoSProtection: true };
      
      // Sign should work
      const token = await jwt.sign(deepPayload, 'secret', options);
      
      // Decode should work
      const decoded = jwt.decode(token, options);
      expect(decoded).toBeTruthy();
      
      // Verify should work
      const verified = await jwt.verify(token, 'secret', options);
      expect(verified).toBeTruthy();
    });
  });

  describe('Edge Cases', () => {
    it('should handle objects at exactly 50 depth', async () => {
      // Test object exactly at the default limit
      let deepObj: any = { value: 'bottom' };
      for (let i = 0; i < 49; i++) {
        deepObj = { nested: deepObj };
      }
      
      // Should work at exactly depth 50
      const token = await jwt.sign(deepObj, 'secret');
      expect(token).toBeTruthy();
    });

    it('should reject objects exceeding depth limit', async () => {
      // Test object that exceeds the default limit
      let deepObj: any = { value: 'bottom' };
      for (let i = 0; i < 51; i++) {
        deepObj = { nested: deepObj };
      }
      
      // Should throw because depth is 52, exceeds default limit of 50
      await expect(jwt.sign(deepObj, 'secret'))
        .rejects.toThrow(/JWT payload exceeds maximum allowed depth/);
    });

    it('should handle null values in claim count', async () => {
      const payload = {
        user: null,
        data: {
          items: [null, { id: 1 }, null],
          metadata: null
        }
      };
      
      // Should count only the actual keys, not null values
      const token = await jwt.sign(payload, 'secret');
      expect(token).toBeTruthy();
    });

    it('should handle circular references in claim count', async () => {
      const obj1: any = { id: 1 };
      const obj2: any = { id: 2, ref: obj1 };
      obj1.ref = obj2; // Create circular reference
      
      const payload = {
        circular: obj1,
        normal: { data: 'test' }
      };
      
      // Should handle circular references without infinite loop
      await expect(jwt.sign(payload, 'secret'))
        .rejects.toThrow(); // Will throw due to JSON.stringify, not our validation
    });

    it('should handle objects with inherited properties in depth calculation', async () => {
      // Create object with inherited properties
      const proto = { inherited: 'value' };
      const obj = Object.create(proto);
      obj.own = { nested: { level: 3 } };
      
      const payload = {
        data: obj,
        regular: { test: true }
      };
      
      // Should only count own properties in depth calculation
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret');
      expect(decoded).toBeTruthy();
    });

    it('should handle objects with inherited properties in claim count', async () => {
      // Create object with many inherited properties
      const proto = {};
      for (let i = 0; i < 100; i++) {
        proto[`inherited${i}`] = `value${i}`;
      }
      
      const obj = Object.create(proto);
      // Add only a few own properties
      for (let i = 0; i < 10; i++) {
        obj[`own${i}`] = `value${i}`;
      }
      
      const payload = {
        data: obj,
        meta: { count: 10 }
      };
      
      // Should only count own properties, not inherited ones
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret');
      expect(decoded).toBeTruthy();
    });

    it('should handle extremely deep objects gracefully', async () => {
      // Create an extremely deep object that would exceed internal recursion limit
      let veryDeep: any = { value: 'bottom' };
      for (let i = 0; i < 105; i++) {
        veryDeep = { nested: veryDeep };
      }
      
      // With DoS protection disabled, the depth check still has an internal limit of 100
      // to prevent stack overflow, so this should succeed but return currentDepth when > 100
      const token = await jwt.sign(veryDeep, 'secret', { disableDoSProtection: true });
      expect(token).toBeTruthy();
    });

    it('should handle undefined and non-object values in depth calculation', async () => {
      const payload = {
        undefined: undefined,
        null: null,
        string: 'test',
        number: 123,
        boolean: true,
        nested: {
          array: [undefined, null, 'test', { deep: true }]
        }
      };
      
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret');
      expect(decoded).toBeTruthy();
    });

    it('should handle payloads at exactly the default limits', async () => {
      // Test with exactly 1000 claims (the default limit)
      const exactLimitPayload: any = {};
      for (let i = 0; i < 999; i++) {
        exactLimitPayload[`claim${i}`] = `value${i}`;
      }
      
      const token = await jwt.sign(exactLimitPayload, 'secret');
      const decoded = await jwt.verify(token, 'secret') as any;
      // Remove iat which is added automatically
      delete decoded.iat;
      expect(Object.keys(decoded).length).toBe(999);
    });

    it('should handle empty objects and arrays', async () => {
      const payload = {
        emptyObj: {},
        emptyArray: [],
        nested: {
          deep: {
            empty: {}
          }
        }
      };
      
      const token = await jwt.sign(payload, 'secret');
      const decoded = await jwt.verify(token, 'secret');
      expect(decoded).toBeTruthy();
    });
  });

  describe('Performance Impact', () => {
    it('should not significantly impact performance for normal tokens', async () => {
      const payload = {
        sub: '1234567890',
        name: 'John Doe',
        iat: Math.floor(Date.now() / 1000)
      };
      
      const iterations = 100;
      const start = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const token = await jwt.sign(payload, 'secret');
        await jwt.verify(token, 'secret');
      }
      
      const duration = Date.now() - start;
      const avgTime = duration / iterations;
      
      // Average time per operation should be reasonable (< 10ms)
      expect(avgTime).toBeLessThan(10);
    });
  });
});