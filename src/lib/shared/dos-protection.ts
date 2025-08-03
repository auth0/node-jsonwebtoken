/**
 * Denial of Service (DoS) Protection utilities
 * These functions help prevent DoS attacks through size and complexity limits
 */

import { JsonWebTokenError } from '../JsonWebTokenError.js';

// Default limits
export const DEFAULT_MAX_TOKEN_SIZE = 250 * 1024; // 250KB
export const DEFAULT_MAX_PAYLOAD_SIZE = 100 * 1024; // 100KB
export const DEFAULT_MAX_PAYLOAD_DEPTH = 50;
export const DEFAULT_MAX_CLAIM_COUNT = 1000;

export interface DoSProtectionOptions {
  maxTokenSize?: number;
  maxPayloadSize?: number;
  maxPayloadDepth?: number;
  maxClaimCount?: number;
  disableDoSProtection?: boolean;
}

/**
 * Validate the size of a JWT token string
 * @param token The JWT token string
 * @param maxSize Maximum allowed size in bytes
 * @throws {JsonWebTokenError} If token exceeds size limit
 */
export function validateTokenSize(token: string, maxSize: number): void {
  const tokenSize = Buffer.byteLength(token, 'utf8');
  if (tokenSize > maxSize) {
    throw new JsonWebTokenError(
      `JWT exceeds maximum allowed size of ${maxSize} bytes (actual: ${tokenSize} bytes)`
    );
  }
}

/**
 * Validate the size of a decoded payload string
 * @param payload The decoded payload string
 * @param maxSize Maximum allowed size in bytes
 * @throws {JsonWebTokenError} If payload exceeds size limit
 */
export function validatePayloadSize(payload: string, maxSize: number): void {
  const payloadSize = Buffer.byteLength(payload, 'utf8');
  if (payloadSize > maxSize) {
    throw new JsonWebTokenError(
      `JWT payload exceeds maximum allowed size of ${maxSize} bytes (actual: ${payloadSize} bytes)`
    );
  }
}

/**
 * Calculate the depth of an object
 * @param obj The object to measure
 * @param currentDepth Current recursion depth
 * @returns Maximum depth found
 */
function getObjectDepth(obj: any, currentDepth = 0): number {
  if (!obj || typeof obj !== 'object' || currentDepth > 100) {
    return currentDepth;
  }

  let maxDepth = currentDepth;
  
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const depth = getObjectDepth(item, currentDepth + 1);
      maxDepth = Math.max(maxDepth, depth);
    }
  } else {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const depth = getObjectDepth(obj[key], currentDepth + 1);
        maxDepth = Math.max(maxDepth, depth);
      }
    }
  }
  
  return maxDepth;
}

/**
 * Validate the depth of a payload object
 * @param payload The payload object
 * @param maxDepth Maximum allowed nesting depth
 * @throws {JsonWebTokenError} If payload exceeds depth limit
 */
export function validatePayloadDepth(payload: any, maxDepth: number): void {
  const depth = getObjectDepth(payload);
  if (depth > maxDepth) {
    throw new JsonWebTokenError(
      `JWT payload exceeds maximum allowed depth of ${maxDepth} (actual: ${depth})`
    );
  }
}

/**
 * Count total number of claims in an object (including nested)
 * @param obj The object to count claims in
 * @param visited Set to track circular references
 * @returns Total number of claims
 */
function countClaims(obj: any, visited = new WeakSet()): number {
  if (!obj || typeof obj !== 'object' || visited.has(obj)) {
    return 0;
  }
  
  visited.add(obj);
  let count = 0;
  
  if (Array.isArray(obj)) {
    for (const item of obj) {
      count += countClaims(item, visited);
    }
  } else {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        count += 1; // Count the key itself
        count += countClaims(obj[key], visited);
      }
    }
  }
  
  return count;
}

/**
 * Validate the number of claims in a payload
 * @param payload The payload object
 * @param maxClaims Maximum allowed number of claims
 * @throws {JsonWebTokenError} If payload exceeds claim count limit
 */
export function validateClaimCount(payload: any, maxClaims: number): void {
  const claimCount = countClaims(payload);
  if (claimCount > maxClaims) {
    throw new JsonWebTokenError(
      `JWT payload exceeds maximum allowed claim count of ${maxClaims} (actual: ${claimCount})`
    );
  }
}

