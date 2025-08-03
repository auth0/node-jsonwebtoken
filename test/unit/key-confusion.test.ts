import { describe, it, expect, beforeAll } from '@jest/globals';
import jwt from '../../src/index.js';
import { JsonWebTokenError } from '../../src/lib/JsonWebTokenError.js';
import { generateRSAKeyPair, generateECKeyPair } from '../helpers/key-generator.js';
import fs from 'fs';
import path from 'path';

describe('Key Confusion Attacks', () => {
  let rsaPublicKey: string;
  let rsaPrivateKey: string;
  let ecPublicKey: string;
  let ecPrivateKey: string;
  let rsaPublicKeyPem: string;
  let ecPublicKeyPem: string;
  
  beforeAll(() => {
    // Generate test keys
    const rsaKeys = generateRSAKeyPair();
    rsaPublicKey = rsaKeys.publicKey;
    rsaPrivateKey = rsaKeys.privateKey;
    
    const ecKeys = generateECKeyPair();
    ecPublicKey = ecKeys.publicKey;
    ecPrivateKey = ecKeys.privateKey;
    
    // Also try to load some real PEM keys for more realistic tests (optional)
    try {
      rsaPublicKeyPem = fs.readFileSync(path.join(process.cwd(), 'test', 'rsa-public.pem'), 'utf8');
    } catch {
      // Use the generated key if file not found
      rsaPublicKeyPem = rsaPublicKey;
    }
    
    try {
      ecPublicKeyPem = fs.readFileSync(path.join(process.cwd(), 'test', 'ecdsa-public.pem'), 'utf8');
    } catch {
      // Use the generated key if file not found
      ecPublicKeyPem = ecPublicKey;
    }
  });
  
  describe('Public Key as HMAC Secret Attack', () => {
    it('should reject RSA public key when using HS256', async () => {
      const payload = { data: 'test' };
      
      // Try to sign with HS256 using RSA public key
      await expect(jwt.sign(payload, rsaPublicKey, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should reject RSA public key PEM when using HS384', async () => {
      const payload = { data: 'test' };
      
      await expect(jwt.sign(payload, rsaPublicKeyPem, { algorithm: 'HS384' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should reject EC public key when using HS512', async () => {
      const payload = { data: 'test' };
      
      await expect(jwt.sign(payload, ecPublicKey, { algorithm: 'HS512' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should reject EC public key PEM when using HMAC', async () => {
      const payload = { data: 'test' };
      
      await expect(jwt.sign(payload, ecPublicKeyPem, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should reject certificate as HMAC secret', async () => {
      const cert = `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8VSp7XkOjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
-----END CERTIFICATE-----`;
      
      await expect(jwt.sign({ data: 'test' }, cert, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should reject JWK public key format', async () => {
      const jwkPublicKey = JSON.stringify({
        kty: 'RSA',
        n: 'xjlOXLu7fmB9p4M8lhU',
        e: 'AQAB'
      });
      
      await expect(jwt.sign({ data: 'test' }, jwkPublicKey, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should reject OpenSSH public key format', async () => {
      const sshPublicKey = '-----BEGIN OPENSSH PUBLIC KEY-----\nssh-rsa AAAAB3NzaC1yc2EA...\n-----END OPENSSH PUBLIC KEY-----';
      
      await expect(jwt.sign({ data: 'test' }, sshPublicKey, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
  });
  
  describe('Empty/Short Key Attacks', () => {
    it('should reject empty string as HMAC key', async () => {
      await expect(jwt.sign({ data: 'test' }, '', { algorithm: 'HS256' }))
        .rejects.toThrow(/secretOrPrivateKey must have a value/);
    });
    
    it('should reject whitespace-only string as HMAC key', async () => {
      await expect(jwt.sign({ data: 'test' }, '   \t\n   ', { algorithm: 'HS256' }))
        .rejects.toThrow(/secretOrPrivateKey must have a value/);
    });
    
    it('should reject empty Buffer as HMAC key', async () => {
      const emptyBuffer = Buffer.from('');
      
      await expect(jwt.sign({ data: 'test' }, emptyBuffer, { algorithm: 'HS256' }))
        .rejects.toThrow(/secretOrPrivateKey must have a value/);
    });
    
    it('should accept short keys but warn in production', async () => {
      const shortKey = 'short';
      
      // Should work but is not recommended
      const token = await jwt.sign({ data: 'test' }, shortKey, { algorithm: 'HS256' });
      expect(token).toBeTruthy();
    });
    
    it('should accept 31-byte Buffer but warn in production', async () => {
      const shortBuffer = Buffer.alloc(31, 'a');
      
      // Should work but is not recommended
      const token = await jwt.sign({ data: 'test' }, shortBuffer, { algorithm: 'HS256' });
      expect(token).toBeTruthy();
    });
    
    it('should accept exactly 32-byte key', async () => {
      const validKey = 'a'.repeat(32);
      
      const token = await jwt.sign({ data: 'test' }, validKey, { algorithm: 'HS256' });
      expect(token).toBeTruthy();
      
      // Verify it works
      const decoded = await jwt.verify(token, validKey);
      expect(decoded).toMatchObject({ data: 'test' });
    });
  });
  
  describe('Algorithm/Key Type Mismatch', () => {
    it('should reject symmetric key with RS256', async () => {
      const symmetricKey = 'a'.repeat(32);
      
      await expect(jwt.sign({ data: 'test' }, symmetricKey, { algorithm: 'RS256' }))
        .rejects.toThrow(); // Will fail in the RSA algorithm implementation
    });
    
    it('should validate algorithm/key match during verify', async () => {
      // Create a token with RS256
      const token = await jwt.sign({ data: 'test' }, rsaPrivateKey, { algorithm: 'RS256' });
      
      // Try to verify with HMAC using the public key - should fail
      await expect(jwt.verify(token, rsaPublicKey, { algorithms: ['HS256'] }))
        .rejects.toThrow();
    });
    
    it('should reject when trying to use asymmetric key object with HMAC', async () => {
      // This test requires creating a KeyObject
      const { createPublicKey } = await import('crypto');
      const publicKeyObject = createPublicKey(rsaPublicKey);
      
      await expect(jwt.sign({ data: 'test' }, publicKeyObject as any, { algorithm: 'HS256' }))
        .rejects.toThrow(/alg.*parameter.*must be one of/);
    });
  });
  
  describe('Verify Protection', () => {
    it('should reject public key as HMAC secret during verify', async () => {
      // Manually create a token that would be created by an attacker
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ data: 'test', iat: Math.floor(Date.now() / 1000) })).toString('base64url');
      const fakeToken = `${header}.${payload}.fake-signature`;
      
      // Try to verify with public key as HMAC secret
      await expect(jwt.verify(fakeToken, rsaPublicKey))
        .rejects.toThrow();
    });
    
    it('should reject empty key during verify', async () => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoidGVzdCJ9.signature';
      
      await expect(jwt.verify(token, ''))
        .rejects.toThrow();
    });
    
    it('should reject short key during verify', async () => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoidGVzdCJ9.signature';
      
      await expect(jwt.verify(token, 'short'))
        .rejects.toThrow();
    });
  });
  
  describe('Private Key vs Public Key', () => {
    it('should accept private keys for HMAC (they are still secrets)', async () => {
      // Private keys should work as HMAC secrets since they are secret material
      const token = await jwt.sign({ data: 'test' }, rsaPrivateKey, { algorithm: 'HS256' });
      expect(token).toBeTruthy();
      
      // Verify it works
      const decoded = await jwt.verify(token, rsaPrivateKey);
      expect(decoded).toMatchObject({ data: 'test' });
    });
    
    it('should distinguish between private and public keys', async () => {
      // Private key should work
      const token = await jwt.sign({ data: 'test' }, rsaPrivateKey, { algorithm: 'HS256' });
      expect(token).toBeTruthy();
      
      // Public key should fail
      await expect(jwt.sign({ data: 'test' }, rsaPublicKey, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
  });
  
  describe('Edge Cases', () => {
    it('should handle malformed PEM keys gracefully', async () => {
      const malformed = '-----BEGIN PUBLIC KEY-----\ninvalid base64 content!!!\n-----END PUBLIC KEY-----';
      
      await expect(jwt.sign({ data: 'test' }, malformed, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should handle keys with extra whitespace', async () => {
      const keyWithWhitespace = `
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
        -----END PUBLIC KEY-----
      `;
      
      await expect(jwt.sign({ data: 'test' }, keyWithWhitespace, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
    
    it('should reject JWK with public key components', async () => {
      const jwk = JSON.stringify({
        kty: 'EC',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
        crv: 'P-256'
      });
      
      await expect(jwt.sign({ data: 'test' }, jwk, { algorithm: 'HS256' }))
        .rejects.toThrow(/requires a secret key, but a public key was provided/);
    });
  });
});