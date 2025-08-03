import { describe, it, expect } from '@jest/globals';
import { sign, signSync } from '../../src/index';
import { generateHMACSecret } from '../helpers/key-generator';

describe('Basic JWT Tests', () => {
  const secret = generateHMACSecret();
  const payload = { sub: '1234567890', name: 'Test User' };

  describe('sign() - Basic', () => {
    it('should sign a token', async () => {
      const token = await sign(payload, secret);
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });
  });

  describe('signSync() - Basic', () => {
    it('should sign a token synchronously', () => {
      const token = signSync(payload, secret);
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });
  });

  describe('Callback API', () => {
    it('should work with callbacks', (done) => {
      (sign as any)(payload, secret, (err: any, token: string) => {
        expect(err).toBeNull();
        expect(typeof token).toBe('string');
        done();
      });
    });
  });
});