const { describe, it, beforeEach } = require('@jest/globals');
const {
  base64urlEscape,
  base64urlUnescape,
  base64urlEncode,
  base64urlDecode,
  createSecuredInput,
  parseJwt,
  decodeHeader,
  decodePayload
} = require('../../dist/lib/jwt-core');

describe('JWT Core Utilities', () => {
  describe('base64urlEscape', () => {
    it('should remove padding characters', () => {
      expect(base64urlEscape('abc=')).toBe('abc');
      expect(base64urlEscape('abc==')).toBe('abc');
    });

    it('should replace + with -', () => {
      expect(base64urlEscape('ab+cd')).toBe('ab-cd');
    });

    it('should replace / with _', () => {
      expect(base64urlEscape('ab/cd')).toBe('ab_cd');
    });

    it('should handle all transformations together', () => {
      expect(base64urlEscape('ab+/cd==')).toBe('ab-_cd');
    });
  });

  describe('base64urlUnescape', () => {
    it('should add appropriate padding', () => {
      expect(base64urlUnescape('abc')).toBe('abc=');
      expect(base64urlUnescape('ab')).toBe('ab==');
      expect(base64urlUnescape('abcd')).toBe('abcd');
    });

    it('should replace - with +', () => {
      expect(base64urlUnescape('ab-cd')).toBe('ab+cd===');
    });

    it('should replace _ with /', () => {
      expect(base64urlUnescape('ab_cd')).toBe('ab/cd===');
    });

    it('should handle all transformations together', () => {
      expect(base64urlUnescape('ab-_c')).toBe('ab+/c===');
    });
  });

  describe('base64urlEncode', () => {
    it('should encode string to base64url', () => {
      const encoded = base64urlEncode('hello world');
      expect(encoded).toBe('aGVsbG8gd29ybGQ');
    });

    it('should encode buffer to base64url', () => {
      const buffer = Buffer.from('hello world');
      const encoded = base64urlEncode(buffer);
      expect(encoded).toBe('aGVsbG8gd29ybGQ');
    });

    it('should handle different encodings', () => {
      const encoded = base64urlEncode('hello', 'ascii');
      expect(encoded).toBe('aGVsbG8');
    });

    it('should handle special characters', () => {
      const encoded = base64urlEncode('{"test": "value"}');
      expect(encoded).toBe('eyJ0ZXN0IjogInZhbHVlIn0');
    });
  });

  describe('base64urlDecode', () => {
    it('should decode base64url to string', () => {
      const decoded = base64urlDecode('aGVsbG8gd29ybGQ');
      expect(decoded).toBe('hello world');
    });

    it('should handle different encodings', () => {
      const decoded = base64urlDecode('aGVsbG8', 'ascii');
      expect(decoded).toBe('hello');
    });

    it('should decode JSON strings', () => {
      const decoded = base64urlDecode('eyJ0ZXN0IjogInZhbHVlIn0');
      expect(decoded).toBe('{"test": "value"}');
    });
  });

  describe('createSecuredInput', () => {
    it('should create secured input with object payload', () => {
      const header = { alg: 'HS256', typ: 'JWT' };
      const payload = { sub: '1234567890', name: 'John Doe' };
      const securedInput = createSecuredInput(header, payload);

      const parts = securedInput.split('.');
      expect(parts).toHaveLength(2);

      const decodedHeader = JSON.parse(base64urlDecode(parts[0]));
      const decodedPayload = JSON.parse(base64urlDecode(parts[1]));

      expect(decodedHeader).toEqual(header);
      expect(decodedPayload).toEqual(payload);
    });

    it('should create secured input with string payload', () => {
      const header = { alg: 'HS256' };
      const payload = 'just a string';
      const securedInput = createSecuredInput(header, payload);

      const parts = securedInput.split('.');
      expect(parts).toHaveLength(2);

      const decodedPayload = base64urlDecode(parts[1]);
      expect(decodedPayload).toBe(payload);
    });

    it('should handle different encodings', () => {
      const header = { alg: 'HS256' };
      const payload = 'test';
      const securedInput = createSecuredInput(header, payload, 'ascii');

      expect(securedInput).toContain('.');
    });
  });

  describe('parseJwt', () => {
    it('should parse valid JWT', () => {
      const token = 'header.payload.signature';
      const parts = parseJwt(token);

      expect(parts).toEqual({
        header: 'header',
        payload: 'payload',
        signature: 'signature'
      });
    });

    it('should return null for invalid JWT', () => {
      expect(parseJwt('invalid')).toBeNull();
      expect(parseJwt('only.two')).toBeNull();
      expect(parseJwt('too.many.parts.here')).toBeNull();
    });

    it('should handle empty parts', () => {
      const token = 'header.payload.';
      const parts = parseJwt(token);

      expect(parts).toEqual({
        header: 'header',
        payload: 'payload',
        signature: ''
      });
    });
  });

  describe('decodeHeader', () => {
    it('should decode JWT header', () => {
      const header = { alg: 'HS256', typ: 'JWT' };
      const encodedHeader = base64urlEncode(JSON.stringify(header));
      const token = `${encodedHeader}.payload.signature`;

      const decoded = decodeHeader(token);
      expect(decoded).toEqual(header);
    });

    it('should return null for invalid token', () => {
      expect(decodeHeader('invalid')).toBeNull();
    });

    it('should return null for invalid JSON in header', () => {
      const invalidHeader = base64urlEncode('not json');
      const token = `${invalidHeader}.payload.signature`;

      expect(decodeHeader(token)).toBeNull();
    });
  });

  describe('decodePayload', () => {
    it('should decode JWT payload as JSON by default', () => {
      const payload = { sub: '1234567890', name: 'John Doe' };
      const encodedPayload = base64urlEncode(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      const decoded = decodePayload(token);
      expect(decoded).toEqual(payload);
    });

    it('should decode JWT payload as string when json is false', () => {
      const payload = 'just a string';
      const encodedPayload = base64urlEncode(payload);
      const token = `header.${encodedPayload}.signature`;

      const decoded = decodePayload(token, false);
      expect(decoded).toBe(payload);
    });

    it('should return string if JSON parse fails', () => {
      const payload = 'not json';
      const encodedPayload = base64urlEncode(payload);
      const token = `header.${encodedPayload}.signature`;

      const decoded = decodePayload(token, true);
      expect(decoded).toBe(payload);
    });

    it('should return null for invalid token', () => {
      expect(decodePayload('invalid')).toBeNull();
    });
  });
});