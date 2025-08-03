const { describe, it, expect } = require('@jest/globals');
const { algorithms, getAlgorithm } = require('../../../src/lib/algorithms/index');

describe('Algorithm Registry', () => {
  describe('algorithms export', () => {
    it('should export all supported algorithms', () => {
      // Check that all algorithms are exported
      expect(algorithms).toHaveProperty('HS256');
      expect(algorithms).toHaveProperty('HS384');
      expect(algorithms).toHaveProperty('HS512');
      expect(algorithms).toHaveProperty('RS256');
      expect(algorithms).toHaveProperty('RS384');
      expect(algorithms).toHaveProperty('RS512');
      expect(algorithms).toHaveProperty('PS256');
      expect(algorithms).toHaveProperty('PS384');
      expect(algorithms).toHaveProperty('PS512');
      expect(algorithms).toHaveProperty('ES256');
      expect(algorithms).toHaveProperty('ES384');
      expect(algorithms).toHaveProperty('ES512');
      expect(algorithms).toHaveProperty('ES256K');
      expect(algorithms).toHaveProperty('EdDSA');
      expect(algorithms).toHaveProperty('none');
    });

    it('should have sign and verify methods for each algorithm', () => {
      Object.keys(algorithms).forEach(algoName => {
        const algorithm = algorithms[algoName];
        expect(algorithm).toHaveProperty('sign');
        expect(algorithm).toHaveProperty('verify');
        expect(typeof algorithm.sign).toBe('function');
        expect(typeof algorithm.verify).toBe('function');
      });
    });
  });

  describe('getAlgorithm function', () => {
    it('should return algorithm implementation for supported algorithms', () => {
      // Test all supported algorithms
      expect(getAlgorithm('HS256')).toBe(algorithms.HS256);
      expect(getAlgorithm('HS384')).toBe(algorithms.HS384);
      expect(getAlgorithm('HS512')).toBe(algorithms.HS512);
      expect(getAlgorithm('RS256')).toBe(algorithms.RS256);
      expect(getAlgorithm('RS384')).toBe(algorithms.RS384);
      expect(getAlgorithm('RS512')).toBe(algorithms.RS512);
      expect(getAlgorithm('PS256')).toBe(algorithms.PS256);
      expect(getAlgorithm('PS384')).toBe(algorithms.PS384);
      expect(getAlgorithm('PS512')).toBe(algorithms.PS512);
      expect(getAlgorithm('ES256')).toBe(algorithms.ES256);
      expect(getAlgorithm('ES384')).toBe(algorithms.ES384);
      expect(getAlgorithm('ES512')).toBe(algorithms.ES512);
      expect(getAlgorithm('ES256K')).toBe(algorithms.ES256K);
      expect(getAlgorithm('EdDSA')).toBe(algorithms.EdDSA);
      expect(getAlgorithm('none')).toBe(algorithms.none);
    });

    it('should throw error for unknown algorithms', () => {
      expect(() => getAlgorithm('UNKNOWN')).toThrow('Algorithm UNKNOWN is not supported');
      expect(() => getAlgorithm('HS999')).toThrow('Algorithm HS999 is not supported');
      expect(() => getAlgorithm('RS999')).toThrow('Algorithm RS999 is not supported');
      expect(() => getAlgorithm('')).toThrow('Algorithm  is not supported');
      expect(() => getAlgorithm('null')).toThrow('Algorithm null is not supported');
      expect(() => getAlgorithm('undefined')).toThrow('Algorithm undefined is not supported');
    });

    it('should be case sensitive', () => {
      // Algorithm names are case sensitive
      expect(() => getAlgorithm('hs256')).toThrow('Algorithm hs256 is not supported');
      expect(() => getAlgorithm('RS256')).not.toThrow();
      expect(() => getAlgorithm('rs256')).toThrow('Algorithm rs256 is not supported');
      expect(() => getAlgorithm('EDDSA')).toThrow('Algorithm EDDSA is not supported');
      expect(() => getAlgorithm('EdDSA')).not.toThrow();
    });

    it('should handle edge cases', () => {
      // Test with various invalid inputs
      expect(() => getAlgorithm('HS256 ')).toThrow('Algorithm HS256  is not supported');
      expect(() => getAlgorithm(' HS256')).toThrow('Algorithm  HS256 is not supported');
      expect(() => getAlgorithm('HS256\n')).toThrow('Algorithm HS256\n is not supported');
      expect(() => getAlgorithm('HS256\t')).toThrow('Algorithm HS256\t is not supported');
    });
  });

  describe('algorithm count', () => {
    it('should have exactly 15 algorithms', () => {
      const algorithmCount = Object.keys(algorithms).length;
      expect(algorithmCount).toBe(15);
    });

    it('should have correct algorithm categories', () => {
      // HMAC algorithms
      const hmacAlgos = ['HS256', 'HS384', 'HS512'];
      hmacAlgos.forEach(algo => {
        expect(algorithms).toHaveProperty(algo);
      });

      // RSA algorithms
      const rsaAlgos = ['RS256', 'RS384', 'RS512'];
      rsaAlgos.forEach(algo => {
        expect(algorithms).toHaveProperty(algo);
      });

      // RSA-PSS algorithms
      const rsaPssAlgos = ['PS256', 'PS384', 'PS512'];
      rsaPssAlgos.forEach(algo => {
        expect(algorithms).toHaveProperty(algo);
      });

      // ECDSA algorithms
      const ecdsaAlgos = ['ES256', 'ES384', 'ES512', 'ES256K'];
      ecdsaAlgos.forEach(algo => {
        expect(algorithms).toHaveProperty(algo);
      });

      // EdDSA algorithm
      expect(algorithms).toHaveProperty('EdDSA');

      // None algorithm
      expect(algorithms).toHaveProperty('none');
    });
  });
});