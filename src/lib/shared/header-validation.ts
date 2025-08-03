import { JsonWebTokenError } from '../JsonWebTokenError.js';
import { JwtHeader, VerifyOptions } from '../../types.js';

// Default configuration
const DEFAULT_MAX_HEADER_SIZE = 8192; // 8KB
const DEFAULT_MAX_KID_LENGTH = 1024;
const DEFAULT_KID_CHARACTER_WHITELIST = /^[\w\-._~]+$/;

export interface HeaderValidationOptions {
  maxHeaderSize: number;
  maxKidLength: number;
  kidCharacterWhitelist: RegExp;
  disableHeaderValidation: boolean;
}

/**
 * Get header validation options with defaults
 */
export function getHeaderValidationOptions(options: VerifyOptions): HeaderValidationOptions {
  return {
    maxHeaderSize: options.maxHeaderSize ?? DEFAULT_MAX_HEADER_SIZE,
    maxKidLength: options.maxKidLength ?? DEFAULT_MAX_KID_LENGTH,
    kidCharacterWhitelist: options.kidCharacterWhitelist ?? DEFAULT_KID_CHARACTER_WHITELIST,
    disableHeaderValidation: options.disableHeaderValidation ?? false
  };
}

/**
 * Validate JWT header for security issues
 * @param header The JWT header to validate
 * @param options Verification options with header validation settings
 * @throws {JsonWebTokenError} If header validation fails
 */
export function validateHeader(header: JwtHeader, options: VerifyOptions): void {
  const validationOptions = getHeaderValidationOptions(options);
  
  // Skip validation if disabled
  if (validationOptions.disableHeaderValidation) {
    return;
  }
  
  // Check total header size
  const headerJson = JSON.stringify(header);
  if (headerJson.length > validationOptions.maxHeaderSize) {
    throw new JsonWebTokenError(
      `JWT header exceeds maximum allowed size of ${validationOptions.maxHeaderSize} bytes`
    );
  }
  
  // Validate kid parameter if present
  if (header.kid !== undefined) {
    // Ensure kid is a string
    if (typeof header.kid !== 'string') {
      throw new JsonWebTokenError('kid header parameter must be a string');
    }
    
    // Check kid length
    if (header.kid.length > validationOptions.maxKidLength) {
      throw new JsonWebTokenError(
        `kid header parameter exceeds maximum allowed length of ${validationOptions.maxKidLength} characters`
      );
    }
    
    // Check for path traversal attempts first (more specific error)
    if (header.kid.includes('..') || header.kid.includes('/') || header.kid.includes('\\')) {
      throw new JsonWebTokenError(
        'kid header parameter contains potential path traversal characters'
      );
    }
    
    // Then validate kid characters (more general check)
    if (!validationOptions.kidCharacterWhitelist.test(header.kid)) {
      throw new JsonWebTokenError(
        'kid header parameter contains invalid characters'
      );
    }
  }
  
  // Validate other potentially dangerous header fields
  validateHeaderField('jku', header.jku, 'string');
  validateHeaderField('x5u', header.x5u, 'string');
  validateHeaderField('x5t', header.x5t, 'string');
  
  // Check for prototype pollution attempts in custom fields
  for (const key in header) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new JsonWebTokenError(
        `Header contains dangerous key: ${key}`
      );
    }
  }
}

/**
 * Validate a specific header field
 */
function validateHeaderField(fieldName: string, value: any, expectedType: string): void {
  if (value !== undefined && typeof value !== expectedType) {
    throw new JsonWebTokenError(
      `${fieldName} header parameter must be a ${expectedType}`
    );
  }
}

/**
 * Create a sanitized header for passing to GetPublicKeyOrSecret callbacks
 * @param header The original header
 * @param options Verification options
 * @returns A sanitized copy of the header
 */
export function createSanitizedHeader(header: JwtHeader, options: VerifyOptions): JwtHeader {
  const validationOptions = getHeaderValidationOptions(options);
  
  // If validation is disabled, return the original header
  if (validationOptions.disableHeaderValidation) {
    return header;
  }
  
  // Create a safe copy with only expected fields
  const sanitized: JwtHeader = {
    alg: header.alg,
    typ: header.typ
  };
  
  // Add optional fields if they exist and are valid
  if (header.kid && typeof header.kid === 'string') {
    // Truncate kid if needed
    sanitized.kid = header.kid.substring(0, validationOptions.maxKidLength);
  }
  
  // Add other standard fields
  if (header.jku && typeof header.jku === 'string') {
    sanitized.jku = header.jku;
  }
  
  if (header.x5u && typeof header.x5u === 'string') {
    sanitized.x5u = header.x5u;
  }
  
  if (header.x5t && typeof header.x5t === 'string') {
    sanitized.x5t = header.x5t;
  }
  
  if (header.x5c && Array.isArray(header.x5c)) {
    sanitized.x5c = header.x5c;
  }
  
  return sanitized;
}