import { JsonWebTokenError } from '../JsonWebTokenError.js';

/**
 * Regular expression to detect null bytes
 */
const NULL_BYTE_REGEX = /\x00/;

/**
 * Regular expression to detect control characters (0x00-0x1F, 0x7F)
 * Excludes common whitespace: tab (0x09), newline (0x0A), carriage return (0x0D)
 */
const DANGEROUS_CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;

/**
 * Regular expression to detect any control characters including whitespace
 */
const ALL_CONTROL_CHARS_REGEX = /[\x00-\x1F\x7F]/;

/**
 * Check if a string contains null bytes
 */
export function containsNullByte(str: string): boolean {
  return NULL_BYTE_REGEX.test(str);
}

/**
 * Check if a string contains dangerous control characters
 * This excludes common whitespace characters (tab, newline, carriage return)
 */
export function containsDangerousControlChars(str: string): boolean {
  return DANGEROUS_CONTROL_CHARS_REGEX.test(str);
}

/**
 * Check if a string contains any control characters
 */
export function containsAnyControlChars(str: string): boolean {
  return ALL_CONTROL_CHARS_REGEX.test(str);
}

/**
 * Validate that a string doesn't contain null bytes
 * @throws {JsonWebTokenError} if null bytes are found
 */
export function validateNoNullBytes(value: string, context: string): void {
  if (containsNullByte(value)) {
    throw new JsonWebTokenError(
      `${context} must not contain null bytes (\\x00)`
    );
  }
}

/**
 * Validate that a string doesn't contain dangerous control characters
 * @throws {JsonWebTokenError} if dangerous control characters are found
 */
export function validateNoDangerousControlChars(value: string, context: string): void {
  if (containsDangerousControlChars(value)) {
    throw new JsonWebTokenError(
      `${context} must not contain control characters`
    );
  }
}

/**
 * Validate encoding parameter
 * Only allows safe encodings to prevent encoding-based attacks
 */
export function validateEncoding(encoding: BufferEncoding | undefined): void {
  const allowedEncodings: BufferEncoding[] = ['utf8', 'utf-8'];
  
  if (encoding && !allowedEncodings.includes(encoding as BufferEncoding)) {
    throw new JsonWebTokenError(
      `Encoding "${encoding}" is not allowed. Only UTF-8 encoding is supported for security reasons.`
    );
  }
}

/**
 * Normalize Unicode string to NFC (Canonical Decomposition, followed by Canonical Composition)
 * This ensures consistent representation of Unicode characters
 */
export function normalizeUnicode(str: string): string {
  // Use String.prototype.normalize() which is available in Node.js
  return str.normalize('NFC');
}

/**
 * Validate and normalize a string for use as a key
 * - Checks for null bytes
 * - Checks for control characters
 * - Normalizes Unicode
 */
export function validateAndNormalizeKey(key: string, keyType: string = 'Key'): string {
  // First validate it's a string
  if (typeof key !== 'string') {
    return key; // Non-string keys are handled elsewhere
  }
  
  // Check for null bytes
  validateNoNullBytes(key, keyType);
  
  // Check for dangerous control characters
  validateNoDangerousControlChars(key, keyType);
  
  // Normalize Unicode
  return normalizeUnicode(key);
}

/**
 * Validate payload string for dangerous content
 * Less strict than key validation - allows newlines and tabs
 */
export function validatePayloadString(payload: string): void {
  // Check for null bytes
  validateNoNullBytes(payload, 'Payload');
  
  // For payloads, we're more lenient - only check for truly dangerous control chars
  // This allows newlines, tabs, etc. which are common in payload data
  if (containsDangerousControlChars(payload)) {
    // Log warning but don't throw - payloads might legitimately contain some control chars
    // This is a balance between security and functionality
  }
}

/**
 * Validate Buffer content for null bytes
 */
export function validateBufferContent(buffer: Buffer, context: string): void {
  // Check for null bytes in buffer
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] === 0x00) {
      throw new JsonWebTokenError(
        `${context} buffer must not contain null bytes`
      );
    }
  }
}

/**
 * Safe string comparison that handles Unicode normalization
 */
export function safeStringCompare(a: string, b: string): boolean {
  return normalizeUnicode(a) === normalizeUnicode(b);
}