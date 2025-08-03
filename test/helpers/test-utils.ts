import { expect } from '@jest/globals';
import type { JwtPayload, Secret, SignOptions } from '../../src/types';
import { sign } from '../../src/index';

/**
 * Default test payload
 */
export const defaultPayload: JwtPayload = {
  sub: '1234567890',
  name: 'Test User',
  admin: true
};

/**
 * Create a payload with custom iat
 */
export const createPayload = (overrides?: Partial<JwtPayload>): JwtPayload => {
  return {
    ...defaultPayload,
    iat: Math.floor(Date.now() / 1000),
    ...overrides
  };
};

/**
 * Validate JWT structure
 */
export const expectValidJWT = (token: string): void => {
  const parts = token.split('.');
  expect(parts).toHaveLength(3);
  
  // Validate header
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  expect(header).toHaveProperty('alg');
  expect(header).toHaveProperty('typ');
  
  // Validate payload
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  expect(payload).toBeDefined();
  
  // Signature should exist (even if empty for 'none' algorithm)
  expect(parts[2]).toBeDefined();
};

/**
 * Extract and decode JWT parts
 */
export const decodeJWTParts = (token: string): {
  header: any;
  payload: any;
  signature: string;
} => {
  const parts = token.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payloadString = Buffer.from(parts[1], 'base64url').toString();
  
  let payload;
  try {
    // Try to parse as JSON first
    payload = JSON.parse(payloadString);
  } catch {
    // If not JSON, return the raw string
    payload = payloadString;
  }
  
  return {
    header,
    payload,
    signature: parts[2]
  };
};

/**
 * Wait for a promise with timeout
 */
export const waitForPromise = <T>(
  promise: Promise<T>,
  timeout = 5000
): Promise<T> => {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error('Promise timeout')), timeout)
    )
  ]);
};

/**
 * Test error messages
 */
export const expectError = async (
  fn: () => Promise<any> | any,
  errorMessage: string | RegExp
): Promise<void> => {
  try {
    await fn();
    throw new Error('Expected function to throw');
  } catch (error: any) {
    if (typeof errorMessage === 'string') {
      expect(error.message).toBe(errorMessage);
    } else {
      expect(error.message).toMatch(errorMessage);
    }
  }
};

/**
 * Common test timeout
 */
export const TEST_TIMEOUT = 10000;

/**
 * Algorithm list for testing
 */
export const ALGORITHMS = {
  HMAC: ['HS256', 'HS384', 'HS512'],
  RSA: ['RS256', 'RS384', 'RS512'],
  PSS: ['PS256', 'PS384', 'PS512'],
  ECDSA: ['ES256', 'ES384', 'ES512', 'ES256K'],
  EDDSA: ['EdDSA'],
  NONE: ['none']
} as const;

/**
 * All supported algorithms
 */
export const ALL_ALGORITHMS = [
  ...ALGORITHMS.HMAC,
  ...ALGORITHMS.RSA,
  ...ALGORITHMS.PSS,
  ...ALGORITHMS.ECDSA,
  ...ALGORITHMS.EDDSA,
  ...ALGORITHMS.NONE
];

/**
 * Convert callback to promise
 */
export const promisify = <T>(
  fn: (...args: any[]) => void,
  ...args: any[]
): Promise<T> => {
  return new Promise((resolve, reject) => {
    const callback = (err: Error | null, result?: T) => {
      if (err) {
        reject(err);
      } else {
        resolve(result!);
      }
    };
    fn(...args, callback);
  });
};

/**
 * Create a signed token for testing
 */
export const createSignedToken = async (
  payload: JwtPayload,
  secret: Secret,
  options?: SignOptions
): Promise<string> => {
  return sign(payload, secret, options);
};

/**
 * Create an expired token
 */
export const createExpiredToken = async (
  secret: Secret,
  expiredBy: number = 3600 // Default 1 hour expired
): Promise<string> => {
  const payload = {
    ...defaultPayload,
    iat: Math.floor(Date.now() / 1000) - expiredBy - 60,
    exp: Math.floor(Date.now() / 1000) - expiredBy
  };
  return sign(payload, secret);
};

/**
 * Create a not-before token
 */
export const createNotBeforeToken = async (
  secret: Secret,
  notBeforeIn: number = 3600 // Default 1 hour in future
): Promise<string> => {
  const payload = {
    ...defaultPayload,
    iat: Math.floor(Date.now() / 1000),
    nbf: Math.floor(Date.now() / 1000) + notBeforeIn
  };
  return sign(payload, secret);
};

/**
 * Create a token with specific audience
 */
export const createTokenWithAudience = async (
  secret: Secret,
  audience: string | string[]
): Promise<string> => {
  return sign(defaultPayload, secret, { audience });
};

/**
 * Create a token with all standard claims
 */
export const createTokenWithClaims = async (
  secret: Secret,
  claims: Partial<JwtPayload> = {}
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'test-issuer',
    sub: 'test-subject',
    aud: 'test-audience',
    exp: now + 3600,
    nbf: now,
    iat: now,
    jti: 'test-id',
    ...claims
  };
  return sign(payload, secret);
};

/**
 * Create malformed token for testing
 */
export const createMalformedTokens = () => {
  return {
    notEnoughSegments: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    tooManySegments: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c.extra',
    invalidBase64: 'not.valid.base64',
    emptySegments: '..',
    invalidJSON: Buffer.from('{"alg":"HS256"').toString('base64url') + '.' + Buffer.from('not json').toString('base64url') + '.signature'
  };
};

/**
 * Create token with invalid claim values
 * This manually constructs a JWT to bypass sign() validation
 */
export const createTokenWithInvalidClaim = (
  secret: Secret,
  invalidClaim: 'exp' | 'nbf',
  invalidValue: any
): string => {
  // Create header
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  // Create payload with invalid claim
  const payload: any = {
    ...defaultPayload,
    iat: Math.floor(Date.now() / 1000)
  };
  payload[invalidClaim] = invalidValue;
  
  // Encode header and payload
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  
  // Create signature using crypto
  const crypto = require('crypto');
  const message = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('base64url');
  
  return `${message}.${signature}`;
};