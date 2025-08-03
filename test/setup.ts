/**
 * Jest setup file
 * This file runs before all tests
 */

import { expect, jest } from '@jest/globals';

// Extend Jest matchers
declare module 'expect' {
  interface Matchers<R> {
    toBeValidJWT(): R;
    toHaveJWTStructure(): R;
  }
}

// Custom JWT matcher
expect.extend({
  toBeValidJWT(received: string) {
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    const pass = jwtRegex.test(received);
    
    return {
      pass,
      message: () => pass 
        ? `expected ${received} not to be a valid JWT`
        : `expected ${received} to be a valid JWT format (header.payload.signature)`
    };
  },
  
  toHaveJWTStructure(received: string) {
    try {
      const parts = received.split('.');
      if (parts.length !== 3) {
        return {
          pass: false,
          message: () => `expected JWT to have 3 parts, but got ${parts.length}`
        };
      }
      
      // Try to decode header and payload
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      
      // Check header has required fields
      if (!header.alg) {
        return {
          pass: false,
          message: () => `expected JWT header to have 'alg' field`
        };
      }
      
      return {
        pass: true,
        message: () => `expected ${received} not to have valid JWT structure`
      };
    } catch (error: any) {
      return {
        pass: false,
        message: () => `expected valid JWT structure, but got error: ${error.message}`
      };
    }
  }
});

// Global test configuration
global.console = {
  ...console,
  // Suppress console.warn for 'none' algorithm warnings during tests
  warn: jest.fn()
};

// Increase timeout for cryptographic operations
jest.setTimeout(10000);