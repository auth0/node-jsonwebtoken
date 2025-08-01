import { Buffer } from 'buffer';

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
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding);
  return base64urlEscape(buffer.toString('base64'));
}

/**
 * Decode base64url string
 */
export function base64urlDecode(str: string, encoding: BufferEncoding = 'utf8'): string {
  return Buffer.from(base64urlUnescape(str), 'base64').toString(encoding);
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
    return JSON.parse(base64urlDecode(parts.header));
  } catch {
    return null;
  }
}

/**
 * Decode JWT payload from token
 */
export function decodePayload(token: string, json = true): any {
  const parts = parseJwt(token);
  if (!parts) {
    return null;
  }
  
  const decoded = base64urlDecode(parts.payload);
  
  if (json) {
    try {
      return JSON.parse(decoded);
    } catch {
      return decoded;
    }
  }
  
  return decoded;
}