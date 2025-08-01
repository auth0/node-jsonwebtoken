const { describe, it } = require('@jest/globals');
const { derToJose, joseToDer } = require('../../../dist/lib/algorithms/ecdsa-sig-formatter');

describe('ECDSA Signature Formatter', () => {
  describe('derToJose', () => {
    it('should convert ES256 DER signature to Jose format', () => {
      // Example ES256 DER signature (r=32 bytes, s=32 bytes)
      const derSignature = Buffer.from(
        '3044' + // SEQUENCE (68 bytes)
        '0220' + // INTEGER (32 bytes)
        '4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41' + // r
        '0220' + // INTEGER (32 bytes)
        '181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09', // s
        'hex'
      );

      const joseSignature = derToJose(derSignature, 'ES256');
      expect(joseSignature).toBe('TkXhaTK4r1FJYaHTOhol_fP091Munic2xhaViKtfuM1BgVIuyOyuB95IYKSs3RKQnYMcxWy7rEYiCCIhqHaNHQk');

      // Jose signature should be 64 bytes base64url encoded
      const decoded = Buffer.from(joseSignature, 'base64');
      expect(decoded.length).toBe(64);
    });

    it('should convert ES384 DER signature to Jose format', () => {
      // ES384 uses 48-byte r and s values
      const derSignature = Buffer.from(
        '3064' + // SEQUENCE
        '0230' + // INTEGER (48 bytes)
        '00b5a77e7e1e3e4b5df490fbc562ee7573e10c97ca7bb8cf973ae670e732705f2b37501c19a5c9cdba5ee6d97d87b08fc7' + // r with padding
        '0230' + // INTEGER (48 bytes)
        '00e4e79e4e1d9c6e8c0819b0d631bfb5dae0c2db0cb5e021fd88fb108fb59e2a2c43dc1a44b61e5bfe088d228b2aac7b4f', // s with padding
        'hex'
      );

      const joseSignature = derToJose(derSignature, 'ES384');
      const decoded = Buffer.from(joseSignature, 'base64');
      expect(decoded.length).toBe(96); // 48 + 48 bytes
    });

    it('should convert ES512 DER signature to Jose format', () => {
      // ES512 uses 66-byte r and s values
      const derSignature = Buffer.from(
        '308184' + // SEQUENCE
        '0240' + // INTEGER
        '4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd414e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41' + // 64 bytes
        '0240' +
        '181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09', // 64 bytes
        'hex'
      );

      const joseSignature = derToJose(derSignature, 'ES512');
      const decoded = Buffer.from(joseSignature, 'base64');
      expect(decoded.length).toBe(132); // 66 + 66 bytes
    });

    it('should handle signatures with leading zeros', () => {
      // DER INTEGER must not have leading zeros unless needed for sign bit
      const derSignature = Buffer.from(
        '3045' + // SEQUENCE
        '0221' + // INTEGER (33 bytes - includes padding)
        '00ff45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41' + // r with leading 00
        '0220' + // INTEGER (32 bytes)
        '181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09', // s
        'hex'
      );

      const joseSignature = derToJose(derSignature, 'ES256');
      const decoded = Buffer.from(joseSignature, 'base64');
      expect(decoded.length).toBe(64);
      // First byte should be 0xff
      expect(decoded[0]).toBe(0xff);
    });

    it('should throw on invalid DER signature', () => {
      const invalidDer = Buffer.from('invalid', 'utf8');
      expect(() => derToJose(invalidDer, 'ES256')).toThrow('Invalid DER signature');
    });

    it('should throw on unknown algorithm', () => {
      const derSignature = Buffer.from('3044022000112233', 'hex');
      expect(() => derToJose(derSignature, 'UNKNOWN')).toThrow('Unknown algorithm');
    });
  });

  describe('joseToDer', () => {
    it('should convert ES256 Jose signature to DER format', () => {
      const joseSignature = 'TkXhaTK4r1FJYaHTOhol_fP091Munic2xhaViKtfuM1BgVIuyOyuB95IYKSs3RKQnYMcxWy7rEYiCCIhqHaNHQk';

      const derSignature = joseToDer(joseSignature, 'ES256');

      // Should be valid DER format
      expect(derSignature[0]).toBe(0x30); // SEQUENCE tag
      expect(derSignature[2]).toBe(0x02); // INTEGER tag for r

      // Extract r and s lengths
      const rLength = derSignature[3];
      const sOffset = 4 + rLength;
      expect(derSignature[sOffset]).toBe(0x02); // INTEGER tag for s
    });

    it('should convert ES384 Jose signature to DER format', () => {
      // Create a 96-byte signature (48 + 48)
      const r = Buffer.alloc(48, 0x11);
      const s = Buffer.alloc(48, 0x22);
      const combined = Buffer.concat([r, s]);
      const joseSignature = combined.toString('base64url');

      const derSignature = joseToDer(joseSignature, 'ES384');

      expect(derSignature[0]).toBe(0x30); // SEQUENCE tag
      expect(derSignature[2]).toBe(0x02); // INTEGER tag
    });

    it('should convert ES512 Jose signature to DER format', () => {
      // Create a 132-byte signature (66 + 66)
      const r = Buffer.alloc(66, 0x33);
      const s = Buffer.alloc(66, 0x44);
      const combined = Buffer.concat([r, s]);
      const joseSignature = combined.toString('base64url');

      const derSignature = joseToDer(joseSignature, 'ES512');

      expect(derSignature[0]).toBe(0x30); // SEQUENCE tag
    });

    it('should add padding for high bit set', () => {
      // Create signature where r and s have high bit set (need padding in DER)
      const r = Buffer.alloc(32, 0xff);
      const s = Buffer.alloc(32, 0x88);
      const combined = Buffer.concat([r, s]);
      const joseSignature = combined.toString('base64url');

      const derSignature = joseToDer(joseSignature, 'ES256');

      // r should have padding
      expect(derSignature[2]).toBe(0x02); // INTEGER tag
      expect(derSignature[3]).toBe(0x21); // length 33 (32 + 1 padding)
      expect(derSignature[4]).toBe(0x00); // padding byte
      expect(derSignature[5]).toBe(0xff); // first byte of r

      // s should have padding too
      const sOffset = 4 + derSignature[3];
      expect(derSignature[sOffset]).toBe(0x02); // INTEGER tag
      expect(derSignature[sOffset + 1]).toBe(0x21); // length 33
      expect(derSignature[sOffset + 2]).toBe(0x00); // padding byte
      expect(derSignature[sOffset + 3]).toBe(0x88); // first byte of s
    });

    it('should throw on invalid signature length', () => {
      const wrongLength = Buffer.alloc(50).toString('base64url');
      expect(() => joseToDer(wrongLength, 'ES256')).toThrow('Invalid signature length');
    });

    it('should throw on unknown algorithm', () => {
      const joseSignature = Buffer.alloc(64).toString('base64url');
      expect(() => joseToDer(joseSignature, 'UNKNOWN')).toThrow('Unknown algorithm');
    });
  });

  describe('Round-trip conversion', () => {
    it('should maintain signature integrity for ES256', () => {
      const original = Buffer.concat([
        Buffer.from('4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41', 'hex'),
        Buffer.from('181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09', 'hex')
      ]);
      const joseSignature = original.toString('base64url');

      const der = joseToDer(joseSignature, 'ES256');
      const backToJose = derToJose(der, 'ES256');

      expect(backToJose).toBe(joseSignature);
    });

    it('should maintain signature integrity with high bit set', () => {
      const original = Buffer.concat([
        Buffer.from('ff45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41', 'hex'),
        Buffer.from('881522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09', 'hex')
      ]);
      const joseSignature = original.toString('base64url');

      const der = joseToDer(joseSignature, 'ES256');
      const backToJose = derToJose(der, 'ES256');

      expect(backToJose).toBe(joseSignature);
    });
  });
});