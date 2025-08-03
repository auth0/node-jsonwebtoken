/// <reference path="../../types/jest.d.ts" />

import { describe, it, expect } from '@jest/globals';
import { 
  validateHeader, 
  createSanitizedHeader,
  getHeaderValidationOptions 
} from '../../../src/lib/shared/header-validation';
import { JsonWebTokenError } from '../../../src/lib/JsonWebTokenError';
import { JwtHeader, VerifyOptions } from '../../../src/types';

describe('Header Validation', () => {
  describe('validateHeader', () => {
    const validHeader: JwtHeader = {
      alg: 'HS256',
      typ: 'JWT'
    };

    it('should pass validation for a simple header', () => {
      expect(() => validateHeader(validHeader, {})).not.toThrow();
    });

    it('should skip validation when disableHeaderValidation is true', () => {
      const largeHeader: JwtHeader = {
        alg: 'HS256',
        kid: 'A'.repeat(10000)
      };
      
      expect(() => validateHeader(largeHeader, { disableHeaderValidation: true })).not.toThrow();
    });

    describe('Header Size Validation', () => {
      it('should reject headers exceeding default size limit', () => {
        const largeHeader: JwtHeader = {
          alg: 'HS256',
          custom: 'A'.repeat(10000)
        };
        
        expect(() => validateHeader(largeHeader, {}))
          .toThrow('JWT header exceeds maximum allowed size of 8192 bytes');
      });

      it('should respect custom maxHeaderSize', () => {
        const header: JwtHeader = {
          alg: 'HS256',
          custom: 'A'.repeat(100)
        };
        
        // Should fail with small limit
        expect(() => validateHeader(header, { maxHeaderSize: 50 }))
          .toThrow('JWT header exceeds maximum allowed size of 50 bytes');
        
        // Should pass with larger limit
        expect(() => validateHeader(header, { maxHeaderSize: 200 })).not.toThrow();
      });
    });

    describe('Kid Parameter Validation', () => {
      it('should accept valid kid values', () => {
        const validKids = ['key-1', 'key_2', 'key.3', 'key~4', 'KEY-123'];
        
        validKids.forEach(kid => {
          const header: JwtHeader = { alg: 'HS256', kid };
          expect(() => validateHeader(header, {})).not.toThrow();
        });
      });

      it('should reject non-string kid values', () => {
        const header: JwtHeader = {
          alg: 'HS256',
          kid: 123 as any
        };
        
        expect(() => validateHeader(header, {}))
          .toThrow('kid header parameter must be a string');
      });

      it('should reject kid exceeding length limit', () => {
        const header: JwtHeader = {
          alg: 'HS256',
          kid: 'A'.repeat(2000)
        };
        
        expect(() => validateHeader(header, {}))
          .toThrow('kid header parameter exceeds maximum allowed length of 1024 characters');
      });

      it('should respect custom maxKidLength', () => {
        const header: JwtHeader = {
          alg: 'HS256',
          kid: 'A'.repeat(50)
        };
        
        expect(() => validateHeader(header, { maxKidLength: 30 }))
          .toThrow('kid header parameter exceeds maximum allowed length of 30 characters');
        
        expect(() => validateHeader(header, { maxKidLength: 100 })).not.toThrow();
      });

      it('should reject kid with invalid characters', () => {
        const invalidKids = [
          'key with spaces',
          'key!@#$%',
          'key${code}',
          'key<script>'
        ];
        
        invalidKids.forEach(kid => {
          const header: JwtHeader = { alg: 'HS256', kid };
          expect(() => validateHeader(header, {}))
            .toThrow('kid header parameter contains invalid characters');
        });
      });

      it('should reject kid with command injection attempts', () => {
        const commandInjectionKids = [
          'key;rm -rf /',
          'key$(cat /etc/passwd)'
        ];
        
        commandInjectionKids.forEach(kid => {
          const header: JwtHeader = { alg: 'HS256', kid };
          expect(() => validateHeader(header, {}))
            .toThrow('kid header parameter contains potential path traversal characters');
        });
      });

      it('should respect custom kidCharacterWhitelist', () => {
        const header: JwtHeader = {
          alg: 'HS256',
          kid: 'key-with-dashes'
        };
        
        // Custom regex that only allows alphanumeric
        const alphanumericOnly = /^[a-zA-Z0-9]+$/;
        
        expect(() => validateHeader(header, { kidCharacterWhitelist: alphanumericOnly }))
          .toThrow('kid header parameter contains invalid characters');
        
        // Custom regex that allows dashes
        const withDashes = /^[a-zA-Z0-9\-]+$/;
        
        expect(() => validateHeader(header, { kidCharacterWhitelist: withDashes }))
          .not.toThrow();
      });

      it('should reject path traversal attempts', () => {
        const pathTraversalKids = [
          '../../../etc/passwd',
          '..\\..\\windows\\system32',
          'keys/../../../secret',
          'keys/../../',
          'C:/Windows/System32',
          '/etc/passwd'
        ];
        
        pathTraversalKids.forEach(kid => {
          const header: JwtHeader = { alg: 'HS256', kid };
          expect(() => validateHeader(header, {}))
            .toThrow('kid header parameter contains potential path traversal characters');
        });
      });
    });

    describe('Other Header Fields Validation', () => {
      it('should validate jku, x5u, x5t as strings', () => {
        const invalidHeaders = [
          { alg: 'HS256', jku: 123 },
          { alg: 'HS256', x5u: [] },
          { alg: 'HS256', x5t: {} }
        ];
        
        invalidHeaders.forEach((header, index) => {
          const field = Object.keys(header).find(k => k !== 'alg');
          expect(() => validateHeader(header as JwtHeader, {}))
            .toThrow(`${field} header parameter must be a string`);
        });
      });
    });

    describe('Prototype Pollution Protection', () => {
      it('should reject dangerous keys', () => {
        const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
        
        dangerousKeys.forEach(key => {
          const header = {
            alg: 'HS256',
            [key]: 'malicious'
          } as JwtHeader;
          
          expect(() => validateHeader(header, {}))
            .toThrow(`Header contains dangerous key: ${key}`);
        });
      });
    });
  });

  describe('createSanitizedHeader', () => {
    it('should return only safe fields', () => {
      const header: JwtHeader = {
        alg: 'RS256',
        typ: 'JWT',
        kid: 'key-123',
        jku: 'https://example.com/keys',
        x5u: 'https://example.com/cert',
        x5t: 'thumbprint',
        x5c: ['cert1', 'cert2'],
        custom: 'should-be-removed',
        malicious: { nested: 'object' }
      };
      
      const sanitized = createSanitizedHeader(header, {});
      
      expect(sanitized).toEqual({
        alg: 'RS256',
        typ: 'JWT',
        kid: 'key-123',
        jku: 'https://example.com/keys',
        x5u: 'https://example.com/cert',
        x5t: 'thumbprint',
        x5c: ['cert1', 'cert2']
      });
      
      expect(sanitized).not.toHaveProperty('custom');
      expect(sanitized).not.toHaveProperty('malicious');
    });

    it('should truncate kid if too long', () => {
      const header: JwtHeader = {
        alg: 'HS256',
        kid: 'A'.repeat(2000)
      };
      
      const sanitized = createSanitizedHeader(header, { maxKidLength: 50 });
      
      expect(sanitized.kid).toHaveLength(50);
      expect(sanitized.kid).toBe('A'.repeat(50));
    });

    it('should return original header when validation is disabled', () => {
      const header: JwtHeader = {
        alg: 'HS256',
        custom: 'field',
        dangerous: 'value'
      };
      
      const sanitized = createSanitizedHeader(header, { disableHeaderValidation: true });
      
      expect(sanitized).toBe(header); // Same reference
    });

    it('should handle missing optional fields', () => {
      const header: JwtHeader = {
        alg: 'HS256'
      };
      
      const sanitized = createSanitizedHeader(header, {});
      
      expect(sanitized).toEqual({
        alg: 'HS256',
        typ: undefined
      });
    });

    it('should skip non-string kid values', () => {
      const header: JwtHeader = {
        alg: 'HS256',
        kid: 123 as any // Invalid type
      };
      
      const sanitized = createSanitizedHeader(header, {});
      
      expect(sanitized).not.toHaveProperty('kid');
    });
  });

  describe('getHeaderValidationOptions', () => {
    it('should return default options when none provided', () => {
      const options = getHeaderValidationOptions({});
      
      expect(options).toEqual({
        maxHeaderSize: 8192,
        maxKidLength: 1024,
        kidCharacterWhitelist: /^[\w\-._~]+$/,
        disableHeaderValidation: false
      });
    });

    it('should override defaults with provided options', () => {
      const customRegex = /^[a-z]+$/;
      const options = getHeaderValidationOptions({
        maxHeaderSize: 4096,
        maxKidLength: 512,
        kidCharacterWhitelist: customRegex,
        disableHeaderValidation: true
      });
      
      expect(options).toEqual({
        maxHeaderSize: 4096,
        maxKidLength: 512,
        kidCharacterWhitelist: customRegex,
        disableHeaderValidation: true
      });
    });

    it('should handle partial options', () => {
      const options = getHeaderValidationOptions({
        maxHeaderSize: 16384
      });
      
      expect(options.maxHeaderSize).toBe(16384);
      expect(options.maxKidLength).toBe(1024); // default
      expect(options.disableHeaderValidation).toBe(false); // default
    });
  });
});