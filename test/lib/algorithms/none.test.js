const { describe, it, expect } = require('@jest/globals');
const { none } = require('../../../dist/lib/algorithms/none');

describe('none Algorithm', () => {
  describe('sign', () => {
    it('should return empty string for any input', () => {
      const message = 'test message';
      const signature = none.sign(message, '');
      expect(signature).toBe('');
    });

    it('should return empty string regardless of key', () => {
      const message = 'test message';
      const signature = none.sign(message, 'any-key');
      expect(signature).toBe('');
    });

    it('should handle buffer input', () => {
      const message = Buffer.from('test message');
      const signature = none.sign(message, '');
      expect(signature).toBe('');
    });
  });

  describe('verify', () => {
    it('should return true for empty signature', () => {
      const message = 'test message';
      const signature = '';
      const result = none.verify(message, signature, '');
      expect(result).toBe(true);
    });

    it('should return false for non-empty signature', () => {
      const message = 'test message';
      const signature = 'any-signature';
      const result = none.verify(message, signature, '');
      expect(result).toBe(false);
    });

    it('should handle buffer input', () => {
      const message = Buffer.from('test message');
      const signature = '';
      const result = none.verify(message, signature, '');
      expect(result).toBe(true);
    });

    it('should be case sensitive for signature', () => {
      const message = 'test message';
      const result1 = none.verify(message, ' ', ''); // Space
      const result2 = none.verify(message, '\n', ''); // Newline
      const result3 = none.verify(message, '\t', ''); // Tab

      expect(result1).toBe(false);
      expect(result2).toBe(false);
      expect(result3).toBe(false);
    });
  });
});