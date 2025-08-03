import { Buffer } from 'buffer';
import { safeJsonParse } from './shared/prototype-pollution-protection.js';
import { DoSProtectionOptions, validatePayloadSize, validatePayloadDepth, validateClaimCount, DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_MAX_PAYLOAD_DEPTH, DEFAULT_MAX_CLAIM_COUNT } from './shared/dos-protection.js';
import { validateEncoding, validatePayloadString } from './shared/encoding-validation.js';

/**
 * Convert a string to base64url format
 */
export function base64urlEscape(str: string): string {
  return str.replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Convert base64url string back to base64
 */
export function base64urlUnescape(str: string): string {
  // Add padding if needed
  const padding = (4 - str.length % 4) % 4;
  if (padding) {
    str += '='.repeat(padding);
  }
  return str.replace(/\-/g, '+')
    .replace(/_/g, '/');
}

/**
 * Encode data to base64url format
 */
export function base64urlEncode(data: string | Buffer, encoding: BufferEncoding = 'utf8'): string {
  // Validate encoding to prevent encoding-based attacks
  validateEncoding(encoding);
  
  // Only validate if it's a raw string payload (not for headers or JSON)
  // The validation will be done at a higher level for structured data
  
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding);
  return base64urlEscape(buffer.toString('base64'));
}

/**
 * Decode base64url string
 */
export function base64urlDecode(str: string, encoding: BufferEncoding = 'utf8'): string {
  // Validate encoding to prevent encoding-based attacks
  validateEncoding(encoding);
  
  try {
    return Buffer.from(base64urlUnescape(str), 'base64').toString(encoding);
  } catch {
    throw new Error('Invalid base64url string');
  }
}

/**
 * Create the secured input for JWT (header.payload)
 */
export function createSecuredInput(header: any, payload: any, encoding: BufferEncoding = 'utf8'): string {
  const encodedHeader = base64urlEncode(JSON.stringify(header), 'utf8');
  const encodedPayload = base64urlEncode(
    typeof payload === 'string' ? payload : JSON.stringify(payload),
    encoding
  );
  return `${encodedHeader}.${encodedPayload}`;
}

/**
 * Parse a JWT string into its components
 */
export function parseJwt(token: string): { header: string; payload: string; signature: string } | null {
  const parts = token.split('.');
  
  if (parts.length !== 3) {
    return null;
  }
  
  return {
    header: parts[0],
    payload: parts[1],
    signature: parts[2]
  };
}

/**
 * Decode JWT header from token
 */
export function decodeHeader(token: string): any {
  const parts = parseJwt(token);
  if (!parts) {
    return null;
  }
  
  try {
    return safeJsonParse(base64urlDecode(parts.header));
  } catch {
    return null;
  }
}

/**
 * Decode JWT payload from token
 */
export function decodePayload(token: string, json = true, dosOptions?: DoSProtectionOptions): any {
  const parts = parseJwt(token);
  if (!parts) {
    return null;
  }
  
  try {
    const decoded = base64urlDecode(parts.payload);
    
    // Apply payload size validation if DoS protection is enabled
    if (dosOptions && !dosOptions.disableDoSProtection) {
      const maxPayloadSize = dosOptions.maxPayloadSize ?? DEFAULT_MAX_PAYLOAD_SIZE;
      validatePayloadSize(decoded, maxPayloadSize);
    }
    
    if (json) {
      try {
        const payload = safeJsonParse(decoded);
        
        // Apply depth and claim count validation for object payloads
        if (dosOptions && !dosOptions.disableDoSProtection && payload && typeof payload === 'object') {
          const maxPayloadDepth = dosOptions.maxPayloadDepth ?? DEFAULT_MAX_PAYLOAD_DEPTH;
          const maxClaimCount = dosOptions.maxClaimCount ?? DEFAULT_MAX_CLAIM_COUNT;
          
          validatePayloadDepth(payload, maxPayloadDepth);
          validateClaimCount(payload, maxClaimCount);
        }
        
        return payload;
      } catch {
        return decoded;
      }
    }
    
    return decoded;
  } catch {
    return null;
  }
}