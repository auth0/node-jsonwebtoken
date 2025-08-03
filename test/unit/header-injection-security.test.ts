/// <reference path="../types/jest.d.ts" />

import { describe, it, expect } from '@jest/globals';
import { sign, verify, JsonWebTokenError } from '../../src/index';
import { generateHMACSecret, generateRSAKeyPair } from '../helpers/key-generator';
import type { GetPublicKeyOrSecret } from '../../src/types';

describe('Header Injection Security Tests', () => {
  const secret = generateHMACSecret();
  const rsaKeys = generateRSAKeyPair();
  const payload = { sub: '1234567890', name: 'John Doe' };

  describe('Path Traversal Protection', () => {
    it('should reject kid with path traversal attempts', async () => {
      const maliciousKids = [
        '../../../etc/passwd',
        '../../secret-keys/master',
        'keys/../../../passwords.txt',
        '/etc/shadow',
        'C:\\Windows\\System32\\config\\SAM'
      ];

      for (const kid of maliciousKids) {
        const token = await sign(payload, rsaKeys.privateKey, {
          algorithm: 'RS256',
          keyid: kid
        });

        await expect(verify(token, rsaKeys.publicKey))
          .rejects.toThrow('kid header parameter contains potential path traversal characters');
      }
    });
  });

  describe('Header Size Limits', () => {
    it('should reject oversized headers', async () => {
      const token = await sign(payload, secret, {
        algorithm: 'HS256',
        header: {
          custom: 'A'.repeat(10000)
        }
      });

      await expect(verify(token, secret))
        .rejects.toThrow('JWT header exceeds maximum allowed size');
    });

    it('should accept headers within custom size limit', async () => {
      const token = await sign(payload, secret, {
        algorithm: 'HS256',
        header: {
          custom: 'A'.repeat(1000)
        }
      });

      // Should pass with increased limit
      const decoded = await verify(token, secret, { 
        maxHeaderSize: 16384 
      });
      expect(decoded.sub).toBe('1234567890');
    });
  });

  describe('GetPublicKeyOrSecret Callback Security', () => {
    it('should receive sanitized header in callback', async () => {
      const token = await sign(payload, rsaKeys.privateKey, {
        algorithm: 'RS256',
        keyid: 'valid-key-id',
        header: {
          custom: 'should-be-removed',
          __proto__: 'dangerous'
        }
      });

      let receivedHeader: any;
      const getKey: GetPublicKeyOrSecret = async (header) => {
        receivedHeader = header;
        return rsaKeys.publicKey;
      };

      await verify(token, getKey, { algorithms: ['RS256'] });

      // Should only have standard fields
      expect(receivedHeader).toHaveProperty('alg', 'RS256');
      expect(receivedHeader).toHaveProperty('kid', 'valid-key-id');
      expect(receivedHeader).not.toHaveProperty('custom');
      // Custom fields should be removed (sanitized header doesn't include them)
    });

    it('should truncate long kid in callback', async () => {
      const longKid = 'A'.repeat(500);
      const token = await sign(payload, rsaKeys.privateKey, {
        algorithm: 'RS256',
        keyid: longKid
      });

      let receivedKid: string | undefined;
      const getKey: GetPublicKeyOrSecret = async (header) => {
        receivedKid = header.kid;
        return rsaKeys.publicKey;
      };

      // With larger kid allowed, it should not throw
      await verify(token, getKey, { algorithms: ['RS256'], maxKidLength: 1024 });

      // The callback receives the full kid (up to maxKidLength)
      expect(receivedKid).toHaveLength(500);
      expect(receivedKid).toBe('A'.repeat(500));
    });

    it('should respect custom kid length in callback', async () => {
      const longKid = 'A'.repeat(200);
      const token = await sign(payload, rsaKeys.privateKey, {
        algorithm: 'RS256',
        keyid: longKid
      });

      let receivedKid: string | undefined;
      const getKey: GetPublicKeyOrSecret = async (header) => {
        receivedKid = header.kid;
        return rsaKeys.publicKey;
      };

      // Should fail with small limit
      await expect(verify(token, getKey, { algorithms: ['RS256'], maxKidLength: 100 }))
        .rejects.toThrow('kid header parameter exceeds maximum allowed length of 100 characters');

      // Should work with larger limit
      await verify(token, getKey, { algorithms: ['RS256'], maxKidLength: 300 });
      
      // The sanitized header truncates to the maxKidLength
      expect(receivedKid).toHaveLength(200);
      expect(receivedKid).toBe('A'.repeat(200));
    });
  });

  describe('SQL/Command Injection Protection', () => {
    it('should reject kid with special characters', async () => {
      const injectionAttempts = [
        { kid: "key'; DROP TABLE users; --", error: 'invalid characters' },
        { kid: 'key" OR "1"="1', error: 'invalid characters' },
        { kid: 'key`; rm -rf /; #', error: 'path traversal' },
        { kid: 'key${process.env.SECRET}', error: 'invalid characters' },
        { kid: 'key$(cat /etc/passwd)', error: 'path traversal' },
        { kid: 'key<script>alert(1)</script>', error: 'path traversal' }
      ];

      for (const { kid, error } of injectionAttempts) {
        const token = await sign(payload, rsaKeys.privateKey, {
          algorithm: 'RS256',
          keyid: kid
        });

        const expectedError = error === 'path traversal' 
          ? 'kid header parameter contains potential path traversal characters'
          : 'kid header parameter contains invalid characters';

        await expect(verify(token, rsaKeys.publicKey))
          .rejects.toThrow(expectedError);
      }
    });

    it('should allow safe kid values', async () => {
      const safeKids = [
        'key-123',
        'KEY_456',
        'key.789',
        'key~abc',
        'org.example.key-2023'
      ];

      for (const kid of safeKids) {
        const token = await sign(payload, rsaKeys.privateKey, {
          algorithm: 'RS256',
          keyid: kid
        });

        const decoded = await verify(token, rsaKeys.publicKey, {
          algorithms: ['RS256']
        });
        expect(decoded.sub).toBe('1234567890');
      }
    });
  });

  describe('Custom Validation Rules', () => {
    it('should apply custom kid whitelist', async () => {
      // Create token with dashes in kid
      const token = await sign(payload, rsaKeys.privateKey, {
        algorithm: 'RS256',
        keyid: 'key-with-dashes'
      });

      // Should fail with alphanumeric-only regex
      await expect(verify(token, rsaKeys.publicKey, {
        kidCharacterWhitelist: /^[a-zA-Z0-9]+$/
      })).rejects.toThrow('kid header parameter contains invalid characters');

      // Should pass with regex allowing dashes
      const decoded = await verify(token, rsaKeys.publicKey, {
        algorithms: ['RS256'],
        kidCharacterWhitelist: /^[a-zA-Z0-9\-]+$/
      });
      expect(decoded.sub).toBe('1234567890');
    });
  });

  describe('Bypass Prevention', () => {
    it('should validate even with valid signature', async () => {
      // Create a valid token with malicious header
      const token = await sign(payload, secret, {
        algorithm: 'HS256',
        keyid: '../../../etc/passwd'
      });

      // Should still reject due to header validation
      await expect(verify(token, secret))
        .rejects.toThrow('kid header parameter contains potential path traversal characters');
    });

    it('should allow disabling validation for backward compatibility', async () => {
      const token = await sign(payload, secret, {
        algorithm: 'HS256',
        keyid: '../../../etc/passwd',
        header: {
          custom: 'A'.repeat(10000)
        }
      });

      // Should pass when validation is disabled
      const decoded = await verify(token, secret, {
        disableHeaderValidation: true
      });
      expect(decoded.sub).toBe('1234567890');
    });
  });
});