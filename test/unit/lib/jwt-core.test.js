const { describe, it, expect } = require('@jest/globals');
const {
  base64urlEscape,
  base64urlUnescape,
  base64urlEncode,
  base64urlDecode,
  createSecuredInput,
  parseJwt,
  decodeHeader,
  decodePayload
} = require('../../../src/lib/jwt-core');


describe('jwt-core', () => {
  describe('base64urlEscape', () => {
    it('should escape base64 strings to base64url format', () => {
      expect(base64urlEscape('abc+/123==')).toBe('abc-_123');
      expect(base64urlEscape('no+special/chars')).toBe('no-special_chars');
      expect(base64urlEscape('===multiple=equals===')).toBe('multipleequals');
      expect(base64urlEscape('')).toBe('');
    });

    it('should handle strings without special characters', () => {
      expect(base64urlEscape('abcdef123')).toBe('abcdef123');
      expect(base64urlEscape('ABCDEF')).toBe('ABCDEF');
    });
  });

  describe('base64urlUnescape', () => {
    it('should unescape base64url strings back to base64', () => {
      expect(base64urlUnescape('abc-_123')).toBe('abc+/123');
      expect(base64urlUnescape('no-special_chars')).toBe('no+special/chars');
    });

    it('should add appropriate padding', () => {
      expect(base64urlUnescape('abc')).toBe('abc='); // length 3, needs 1 padding
      expect(base64urlUnescape('ab')).toBe('ab=='); // length 2, needs 2 padding
      expect(base64urlUnescape('abcd')).toBe('abcd'); // length 4, no padding needed
      expect(base64urlUnescape('abcde')).toBe('abcde==='); // length 5, needs 3 padding
    });

    it('should handle empty string', () => {
      expect(base64urlUnescape('')).toBe('');
    });
  });

  describe('base64urlEncode', () => {
    it('should encode strings to base64url', () => {
      expect(base64urlEncode('hello world')).toBe('aGVsbG8gd29ybGQ');
      expect(base64urlEncode('test')).toBe('dGVzdA');
      expect(base64urlEncode('')).toBe('');
    });

    it('should encode with UTF-8 encoding', () => {
      expect(base64urlEncode('hello', 'utf8')).toBe('aGVsbG8');
      expect(base64urlEncode('hello', 'utf-8')).toBe('aGVsbG8');
      expect(base64urlEncode('test')).toBe('dGVzdA'); // default is utf8
    });

    it('should reject non-UTF8 encodings', () => {
      expect(() => base64urlEncode('hello', 'utf16le')).toThrow(/Only UTF-8 encoding is supported/);
      expect(() => base64urlEncode('test', 'ascii')).toThrow(/Only UTF-8 encoding is supported/);
      expect(() => base64urlEncode('test', 'latin1')).toThrow(/Only UTF-8 encoding is supported/);
    });

    it('should encode Buffer objects', () => {
      const buffer = Buffer.from('hello world', 'utf8');
      expect(base64urlEncode(buffer)).toBe('aGVsbG8gd29ybGQ');

      const binaryBuffer = Buffer.from([0x00, 0xff, 0x80, 0x7f]);
      expect(base64urlEncode(binaryBuffer)).toBe('AP-Afw');
    });

    it('should handle special characters', () => {
      expect(base64urlEncode('{"alg":"HS256"}')).toBe('eyJhbGciOiJIUzI1NiJ9');
      expect(base64urlEncode('ñoño')).toBe('w7Fvw7Fv');
      expect(base64urlEncode('🚀')).toBe('8J-agA');
    });
  });

  describe('base64urlDecode', () => {
    it('should decode base64url strings', () => {
      expect(base64urlDecode('aGVsbG8gd29ybGQ')).toBe('hello world');
      expect(base64urlDecode('dGVzdA')).toBe('test');
      expect(base64urlDecode('')).toBe('');
    });

    it('should decode with UTF-8 encoding', () => {
      expect(base64urlDecode('aGVsbG8', 'utf8')).toBe('hello');
      expect(base64urlDecode('aGVsbG8', 'utf-8')).toBe('hello');
      expect(base64urlDecode('dGVzdA')).toBe('test'); // default is utf8
    });

    it('should reject non-UTF8 encodings for decode', () => {
      expect(() => base64urlDecode('aGVsbG8', 'utf16le')).toThrow(/Only UTF-8 encoding is supported/);
      expect(() => base64urlDecode('dGVzdA', 'ascii')).toThrow(/Only UTF-8 encoding is supported/);
      expect(() => base64urlDecode('dGVzdA', 'latin1')).toThrow(/Only UTF-8 encoding is supported/);
    });

    it('should handle special characters', () => {
      expect(base64urlDecode('eyJhbGciOiJIUzI1NiJ9')).toBe('{"alg":"HS256"}');
      expect(base64urlDecode('w7Fvw7Fv')).toBe('ñoño');
      expect(base64urlDecode('8J-agA')).toBe('🚀');
    });

    it('should throw error for invalid encodings', () => {
      // Now these throw encoding validation errors instead of base64 errors
      expect(() => base64urlDecode('VGVzdA', 'invalid-encoding')).toThrow(/Only UTF-8 encoding is supported/);
      expect(() => base64urlDecode('aGVsbG8', 'not-an-encoding')).toThrow(/Only UTF-8 encoding is supported/);
      expect(() => base64urlDecode('YWJj', 'unknown')).toThrow(/Only UTF-8 encoding is supported/);
    });

    it('should handle various base64url strings', () => {
      // Node.js Buffer.from with 'base64' is very permissive and doesn't throw on invalid characters
      // It simply ignores them, so we can't easily test for "Invalid base64url string" errors
      // Instead, let's verify that decoding works correctly for edge cases

      // Empty string should decode to empty
      expect(base64urlDecode('')).toBe('');

      // Single character
      expect(base64urlDecode('YQ')).toBe('a');
      // With padding characters (should be handled by base64urlUnescape)
      expect(base64urlDecode('YWI')).toBe('ab');
    });
  });

  describe('createSecuredInput', () => {
    it('should create secured input from header and payload objects', () => {
      const header = { alg: 'HS256', typ: 'JWT' };
      const payload = { sub: '1234567890', name: 'John Doe' };

      const result = createSecuredInput(header, payload);
      const parts = result.split('.');

      expect(parts).toHaveLength(2);
      expect(base64urlDecode(parts[0])).toBe(JSON.stringify(header));
      expect(base64urlDecode(parts[1])).toBe(JSON.stringify(payload));
    });

    it('should handle string payloads', () => {
      const header = { alg: 'HS256' };
      const payload = 'just a string payload';

      const result = createSecuredInput(header, payload);
      const parts = result.split('.');

      expect(parts).toHaveLength(2);
      expect(base64urlDecode(parts[0])).toBe(JSON.stringify(header));
      expect(base64urlDecode(parts[1])).toBe(payload);
    });

    it('should validate encoding parameter', () => {
      const header = { alg: 'HS256' };
      const payload = 'test';

      // Test that UTF-8 encodings work
      const result1 = createSecuredInput(header, payload, 'utf8');
      const parts1 = result1.split('.');
      expect(parts1).toHaveLength(2);
      expect(base64urlDecode(parts1[0])).toBe(JSON.stringify(header));
      expect(base64urlDecode(parts1[1])).toBe(payload);

      // Test that non-UTF8 encodings are rejected
      expect(() => createSecuredInput(header, payload, 'utf16le')).toThrow(/Only UTF-8 encoding is supported/);
      expect(() => createSecuredInput(header, payload, 'ascii')).toThrow(/Only UTF-8 encoding is supported/);
    });

    it('should handle empty objects and strings', () => {
      expect(createSecuredInput({}, {})).toBe('e30.e30');
      expect(createSecuredInput({}, '')).toBe('e30.');
      expect(createSecuredInput({ alg: 'none' }, '')).toBe('eyJhbGciOiJub25lIn0.');
    });
  });

  describe('parseJwt', () => {
    it('should parse valid JWT strings', () => {
      const token = 'header.payload.signature';
      const result = parseJwt(token);

      expect(result).toEqual({
        header: 'header',
        payload: 'payload',
        signature: 'signature'
      });
    });

    it('should return null for invalid JWT format', () => {
      // Valid JWT has exactly 3 parts
      expect(parseJwt('not.a.jwt')).not.toBe(null); // This has 3 parts, so it's valid
      expect(parseJwt('only.two')).toBe(null);
      expect(parseJwt('one')).toBe(null);
      expect(parseJwt('')).toBe(null);
      expect(parseJwt('too.many.parts.here')).toBe(null);
    });

    it('should handle JWTs with empty parts', () => {
      const result = parseJwt('..signature');
      expect(result).toEqual({
        header: '',
        payload: '',
        signature: 'signature'
      });
    });
  });

  describe('decodeHeader', () => {
    it('should decode JWT headers', () => {
      const header = { alg: 'HS256', typ: 'JWT' };
      const encodedHeader = base64urlEncode(JSON.stringify(header));
      const token = `${encodedHeader}.payload.signature`;

      expect(decodeHeader(token)).toEqual(header);
    });

    it('should return null for invalid token format (line 79)', () => {
      expect(decodeHeader('not.valid')).toBe(null);
      expect(decodeHeader('single')).toBe(null);
      expect(decodeHeader('')).toBe(null);
    });

    it('should return null for invalid header encoding', () => {
      // Invalid base64url in header
      expect(decodeHeader('invalid!@#$.payload.signature')).toBe(null);
      expect(decodeHeader('notjson.payload.signature')).toBe(null);
    });

    it('should handle complex headers', () => {
      const header = {
        alg: 'RS256',
        typ: 'JWT',
        kid: '12345',
        custom: { nested: true }
      };
      const encodedHeader = base64urlEncode(JSON.stringify(header));
      const token = `${encodedHeader}.payload.signature`;

      expect(decodeHeader(token)).toEqual(header);
    });
  });

  describe('decodePayload', () => {
    it('should decode JWT payloads as JSON by default', () => {
      const payload = { sub: '1234567890', name: 'John Doe', admin: true };
      const encodedPayload = base64urlEncode(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      expect(decodePayload(token)).toEqual(payload);
    });

    it('should decode string payloads when not valid JSON', () => {
      const payload = 'just a plain string';
      const encodedPayload = base64urlEncode(payload);
      const token = `header.${encodedPayload}.signature`;

      expect(decodePayload(token)).toBe(payload);
    });

    it('should decode as string when json=false (lines 109-111)', () => {
      const payload = { test: true };
      const encodedPayload = base64urlEncode(JSON.stringify(payload));
      const token = `header.${encodedPayload}.signature`;

      // When json=false, should return the raw string
      expect(decodePayload(token, false)).toBe(JSON.stringify(payload));
    });

    it('should return null for invalid token format (line 95)', () => {
      expect(decodePayload('not.valid')).toBe(null);
      expect(decodePayload('single')).toBe(null);
      expect(decodePayload('')).toBe(null);
    });

    // Line 111 is tested in jwt-core-line111.test.js due to module mocking complexity

    it('should handle various payload types', () => {
      // Number payload (becomes string, then parsed as JSON)
      const numPayload = base64urlEncode('123');
      expect(decodePayload(`h.${numPayload}.s`)).toBe(123);

      // Boolean payload
      const boolPayload = base64urlEncode('true');
      expect(decodePayload(`h.${boolPayload}.s`)).toBe(true);

      // Array payload
      const arrayPayload = base64urlEncode('[1,2,3]');
      expect(decodePayload(`h.${arrayPayload}.s`)).toEqual([1,2,3]);

      // Null payload
      const nullPayload = base64urlEncode('null');
      expect(decodePayload(`h.${nullPayload}.s`)).toBe(null);
    });

    it('should handle empty payload', () => {
      const emptyPayload = base64urlEncode('');
      const token = `header.${emptyPayload}.signature`;

      expect(decodePayload(token)).toBe('');
      expect(decodePayload(token, false)).toBe('');
    });
  });
});