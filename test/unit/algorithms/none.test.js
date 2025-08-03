const { describe, it, expect } = require('@jest/globals');
const { none } = require('../../../src/lib/algorithms/none');

describe('None Algorithm', () => {
  describe('sign operation', () => {
    it('should always return empty string', () => {
      // 'none' algorithm always returns empty signature
      expect(none.sign('message', null)).toBe('');
      expect(none.sign('message', 'key')).toBe('');
      expect(none.sign('message', Buffer.from('key'))).toBe('');
      expect(none.sign('message', { key: 'value' })).toBe('');
      expect(none.sign('message', 123)).toBe('');
      expect(none.sign('message', true)).toBe('');
      expect(none.sign('message', undefined)).toBe('');
    });

    it('should return empty string for any message type', () => {
      expect(none.sign('string message', null)).toBe('');
      expect(none.sign(Buffer.from('buffer message'), null)).toBe('');
      expect(none.sign('', null)).toBe('');
      expect(none.sign(Buffer.alloc(0), null)).toBe('');
      expect(none.sign('🔐 Unicode message', null)).toBe('');
    });

    it('should ignore key parameter completely', () => {
      const message = 'test message';

      // All these should produce the same empty signature
      const sig1 = none.sign(message, 'key1');
      const sig2 = none.sign(message, 'key2');
      const sig3 = none.sign(message, null);
      const sig4 = none.sign(message, undefined);

      expect(sig1).toBe('');
      expect(sig2).toBe('');
      expect(sig3).toBe('');
      expect(sig4).toBe('');
      expect(sig1).toEqual(sig2);
      expect(sig2).toEqual(sig3);
      expect(sig3).toEqual(sig4);
    });
  });

  describe('verify operation', () => {
    it('should return true only for empty signature', () => {
      const message = 'test message';

      // Empty signature should verify
      expect(none.verify(message, '', null)).toBe(true);
      expect(none.verify(message, '', 'key')).toBe(true);
      expect(none.verify(message, '', Buffer.from('key'))).toBe(true);
      expect(none.verify(message, '', undefined)).toBe(true);
    });

    it('should return false for non-empty signatures', () => {
      const message = 'test message';

      // Any non-empty signature should fail
      expect(none.verify(message, 'signature', null)).toBe(false);
      expect(none.verify(message, 'a', null)).toBe(false);
      expect(none.verify(message, ' ', null)).toBe(false);
      expect(none.verify(message, '0', null)).toBe(false);
      expect(none.verify(message, 'null', null)).toBe(false);
      expect(none.verify(message, 'undefined', null)).toBe(false);
      expect(none.verify(message, 'false', null)).toBe(false);
    });

    it('should verify regardless of message content', () => {
      // Empty signature should verify for any message
      expect(none.verify('message1', '', null)).toBe(true);
      expect(none.verify('message2', '', null)).toBe(true);
      expect(none.verify(Buffer.from('buffer'), '', null)).toBe(true);
      expect(none.verify('', '', null)).toBe(true);
      expect(none.verify('🔐 Unicode', '', null)).toBe(true);
    });

    it('should ignore key parameter for verification', () => {
      const message = 'test message';
      const emptySignature = '';
      const nonEmptySignature = 'sig';

      // Key should be ignored - only signature matters
      expect(none.verify(message, emptySignature, 'key1')).toBe(true);
      expect(none.verify(message, emptySignature, 'key2')).toBe(true);
      expect(none.verify(message, emptySignature, null)).toBe(true);

      expect(none.verify(message, nonEmptySignature, 'key1')).toBe(false);
      expect(none.verify(message, nonEmptySignature, 'key2')).toBe(false);
      expect(none.verify(message, nonEmptySignature, null)).toBe(false);
    });

    it('should handle edge cases', () => {
      // Verify behavior with various edge cases
      expect(none.verify(null, '', null)).toBe(true);
      expect(none.verify(undefined, '', null)).toBe(true);
      expect(none.verify(0, '', null)).toBe(true);
      expect(none.verify(false, '', null)).toBe(true);

      // Non-empty signatures should still fail
      expect(none.verify(null, 'sig', null)).toBe(false);
      expect(none.verify(undefined, 'sig', null)).toBe(false);
    });
  });

  describe('security considerations', () => {
    it('should demonstrate that none algorithm provides no security', () => {
      const message1 = 'original message';
      const message2 = 'forged message';

      // Sign with 'none'
      const signature = none.sign(message1, 'secret');

      // Signature is empty
      expect(signature).toBe('');

      // Anyone can "verify" any message with the empty signature
      expect(none.verify(message1, signature, 'secret')).toBe(true);
      expect(none.verify(message2, signature, 'secret')).toBe(true);
      expect(none.verify(message1, signature, 'wrong-secret')).toBe(true);
      expect(none.verify(message2, signature, null)).toBe(true);

      // This demonstrates why 'none' algorithm is insecure
    });
  });
});