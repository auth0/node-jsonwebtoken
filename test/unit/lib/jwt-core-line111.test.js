const { describe, it, expect } = require('@jest/globals');

describe('jwt-core line 111 coverage', () => {
  it('should return null when base64urlDecode throws (line 111)', () => {
    // This tests the catch block at line 111 by causing base64urlDecode to throw

    // First, let's understand that in the compiled TypeScript module,
    // internal function calls can't be easily mocked. So we need to
    // create a condition where Buffer operations actually fail.

    // We'll use jest manual mocking
    jest.doMock('buffer', () => {
      const actualBuffer = jest.requireActual('buffer');
      return {
        ...actualBuffer,
        Buffer: {
          ...actualBuffer.Buffer,
          from: jest.fn((data, encoding) => {
            // Make Buffer.from throw for a specific base64 pattern
            if (encoding === 'base64' && data === '!!!FORCEERROR!!!') {
              throw new Error('Invalid buffer input');
            }
            return actualBuffer.Buffer.from(data, encoding);
          }),
          isBuffer: actualBuffer.Buffer.isBuffer
        }
      };
    });

    // Clear cache and require module with mocked buffer
    jest.resetModules();
    const { decodePayload } = require('../../../src/lib/jwt-core');

    // We need a payload that when passed through base64urlUnescape
    // will produce the exact string that triggers our Buffer.from error
    // base64urlUnescape adds padding and converts - to + and _ to /

    // Create a payload that will become '!!!FORCEERROR!!!' after base64urlUnescape
    const errorPayload = '!!!FORCEERROR!!!'; // This exact string after unescape

    // Build a token with this payload
    const token = `header.${errorPayload}.signature`;

    // This should trigger the catch block at line 111 and return null
    const result = decodePayload(token);
    expect(result).toBe(null);

    // Clean up
    jest.dontMock('buffer');
    jest.resetModules();
  });
});