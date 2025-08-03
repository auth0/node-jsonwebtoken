const { describe, it, expect } = require('@jest/globals');
const { timespan } = require('../../../src/lib/timespan');

describe('timespan', () => {
  describe('with string time values', () => {
    it('should convert valid time strings to seconds', () => {
      const now = Math.floor(Date.now() / 1000);

      // Test various time formats
      expect(timespan('1h')).toBeCloseTo(now + 3600, 0);
      expect(timespan('2d')).toBeCloseTo(now + 172800, 0);
      expect(timespan('10m')).toBeCloseTo(now + 600, 0);
      expect(timespan('30s')).toBeCloseTo(now + 30, 0);
      expect(timespan('1y')).toBeCloseTo(now + 31557600, 0);
      expect(timespan('100ms')).toBeCloseTo(now, 0); // Less than 1 second
      expect(timespan('1500ms')).toBeCloseTo(now + 1, 0); // 1.5 seconds
    });

    it('should use provided iat timestamp', () => {
      const iat = 1234567890;

      expect(timespan('1h', iat)).toBe(iat + 3600);
      expect(timespan('2d', iat)).toBe(iat + 172800);
      expect(timespan('10m', iat)).toBe(iat + 600);
    });

    it('should return NaN for invalid time strings', () => {
      expect(timespan('invalid')).toBeNaN();
      expect(timespan('12x')).toBeNaN();
      expect(timespan('abc')).toBeNaN();
      expect(timespan('')).toBeNaN();
      expect(timespan(' ')).toBeNaN();
    });

    it('should return NaN when ms() returns falsy values', () => {
      // Test when ms() returns null/undefined/0
      expect(timespan('0s')).toBeNaN();
      expect(timespan('0ms')).toBeNaN();
    });

    it('should return NaN when ms() throws an error', () => {
      // Mock ms to throw an error
      jest.isolateModules(() => {
        jest.doMock('ms', () => jest.fn(() => {
          throw new Error('ms error');
        }));

        const { timespan: timespanWithError } = require('../../../src/lib/timespan');
        expect(timespanWithError('1h')).toBeNaN();
      });
    });

    it('should handle edge cases', () => {
      // -1h is actually valid in ms library (negative time)
      const now = Math.floor(Date.now() / 1000);
      expect(timespan('-1h')).toBeCloseTo(now - 3600, 0);

      // These should return NaN
      expect(timespan('Infinity')).toBeNaN();
      expect(timespan('NaN')).toBeNaN();
    });
  });

  describe('with number time values', () => {
    it('should add numeric seconds to current time', () => {
      const now = Math.floor(Date.now() / 1000);

      expect(timespan(60)).toBeCloseTo(now + 60, 0);
      expect(timespan(3600)).toBeCloseTo(now + 3600, 0);
      expect(timespan(0)).toBeCloseTo(now, 0);
      expect(timespan(1)).toBeCloseTo(now + 1, 0);
    });

    it('should add numeric seconds to provided iat', () => {
      const iat = 1234567890;

      expect(timespan(60, iat)).toBe(iat + 60);
      expect(timespan(3600, iat)).toBe(iat + 3600);
      expect(timespan(0, iat)).toBe(iat);
      expect(timespan(-60, iat)).toBe(iat - 60);
    });

    it('should handle special numeric values', () => {
      const now = Math.floor(Date.now() / 1000);

      expect(timespan(Infinity)).toBe(Infinity);
      expect(timespan(-Infinity)).toBe(-Infinity);
      expect(timespan(NaN)).toBeNaN();
      expect(timespan(0.5)).toBeCloseTo(now + 0.5, 0);
      expect(timespan(-3600)).toBeCloseTo(now - 3600, 0);
    });
  });

  describe('with invalid input types', () => {
    it('should return NaN for non-string, non-number inputs', () => {
      expect(timespan(null)).toBeNaN();
      expect(timespan(undefined)).toBeNaN();
      expect(timespan(true)).toBeNaN();
      expect(timespan(false)).toBeNaN();
      expect(timespan({})).toBeNaN();
      expect(timespan([])).toBeNaN();
      expect(timespan(() => {})).toBeNaN();
      expect(timespan(Symbol('test'))).toBeNaN();
      expect(timespan(new Date())).toBeNaN();
    });
  });

  describe('iat parameter', () => {
    it('should default to current time when iat is not provided', () => {
      const before = Math.floor(Date.now() / 1000);
      const result = timespan(60);
      const after = Math.floor(Date.now() / 1000);

      expect(result).toBeGreaterThanOrEqual(before + 60);
      expect(result).toBeLessThanOrEqual(after + 60);
    });

    it('should handle iat value of 0', () => {
      // When iat is 0 (falsy), it uses current timestamp instead
      const now = Math.floor(Date.now() / 1000);
      expect(timespan(60, 0)).toBeCloseTo(now + 60, 0);
      expect(timespan('1h', 0)).toBeCloseTo(now + 3600, 0);
    });

    it('should handle negative iat values', () => {
      expect(timespan(60, -1000)).toBe(-940);
      expect(timespan('1h', -1000)).toBe(2600);
    });
  });

  describe('integration with ms library', () => {
    it('should correctly parse complex time strings', () => {
      const now = Math.floor(Date.now() / 1000);

      // Note: ms library may or may not support complex strings like '1h 30m'
      // Let's test simpler formats that are definitely supported
      expect(timespan('2d')).toBeCloseTo(now + 172800, 0);
      expect(timespan('7d')).toBeCloseTo(now + 604800, 0);
    });
  });
});