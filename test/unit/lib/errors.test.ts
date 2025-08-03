/// <reference path="../../types/jest.d.ts" />

import { describe, it, expect } from '@jest/globals';
import { JsonWebTokenError, TokenExpiredError, NotBeforeError } from '../../../src/index';

describe('Error Classes', () => {
  describe('JsonWebTokenError', () => {
    it('should create error with message only', () => {
      const error = new JsonWebTokenError('test error message');
      
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(JsonWebTokenError);
      expect(error.name).toBe('JsonWebTokenError');
      expect(error.message).toBe('test error message');
      expect(error.cause).toBeUndefined();
    });

    it('should create error with message and cause', () => {
      const cause = new Error('underlying error');
      const error = new JsonWebTokenError('test error message', cause);
      
      expect(error).toBeInstanceOf(JsonWebTokenError);
      expect(error.name).toBe('JsonWebTokenError');
      expect(error.message).toBe('test error message');
      expect(error.cause).toBe(cause);
    });

    it('should have proper stack trace', () => {
      const error = new JsonWebTokenError('test error');
      
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('JsonWebTokenError: test error');
    });
  });

  describe('TokenExpiredError', () => {
    it('should create error with expiredAt date', () => {
      const expiredAt = new Date('2023-01-01');
      const error = new TokenExpiredError('jwt expired', expiredAt);
      
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(JsonWebTokenError);
      expect(error).toBeInstanceOf(TokenExpiredError);
      expect(error.name).toBe('TokenExpiredError');
      expect(error.message).toBe('jwt expired');
      expect(error.expiredAt).toBe(expiredAt);
    });
  });

  describe('NotBeforeError', () => {
    it('should create error with date', () => {
      const date = new Date('2023-01-01');
      const error = new NotBeforeError('jwt not active', date);
      
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(JsonWebTokenError);
      expect(error).toBeInstanceOf(NotBeforeError);
      expect(error.name).toBe('NotBeforeError');
      expect(error.message).toBe('jwt not active');
      expect(error.date).toBe(date);
    });
  });
});