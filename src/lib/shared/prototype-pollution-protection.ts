/**
 * Prototype Pollution Protection utilities
 * These functions help prevent prototype pollution attacks through Object.assign and JSON.parse
 */

// Dangerous keys that can lead to prototype pollution
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

/**
 * Filter out dangerous keys from an object that could lead to prototype pollution
 * @param obj The object to filter
 * @returns A new object with dangerous keys removed
 */
export function filterDangerousKeys(obj: any): any {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }
  
  // Handle arrays differently
  if (Array.isArray(obj)) {
    return obj.map(item => filterDangerousKeys(item));
  }
  
  // Create a new object with the same prototype
  const filtered = Object.create(Object.prototype);
  
  for (const key in obj) {
    if (obj.hasOwnProperty(key) && !DANGEROUS_KEYS.includes(key)) {
      // Recursively filter nested objects
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        filtered[key] = filterDangerousKeys(obj[key]);
      } else {
        filtered[key] = obj[key];
      }
    }
  }
  
  return filtered;
}

/**
 * Safe Object.assign that filters out dangerous keys
 * @param target The target object
 * @param source The source object to copy from
 * @returns The target object after assignment
 */
export function safeObjectAssign<T extends object>(target: T, source: any): T {
  if (!source || typeof source !== 'object') {
    return target;
  }
  
  const filtered = filterDangerousKeys(source);
  return Object.assign(target, filtered);
}

/**
 * JSON.parse reviver function that filters out dangerous keys
 * @param key The JSON key
 * @param value The JSON value
 * @returns The value or undefined if the key is dangerous
 */
export function jsonParseReviver(key: string, value: any): any {
  if (DANGEROUS_KEYS.includes(key)) {
    return undefined;
  }
  // If the value is an object, check for and remove dangerous keys
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const dangerousKey of DANGEROUS_KEYS) {
      delete value[dangerousKey];
    }
  }
  return value;
}

/**
 * Safe JSON.parse that prevents prototype pollution
 * @param text The JSON string to parse
 * @returns The parsed object with dangerous keys filtered out
 */
export function safeJsonParse(text: string): any {
  const parsed = JSON.parse(text, jsonParseReviver);
  // Additional safety: run through filter to ensure no dangerous keys remain
  return filterDangerousKeys(parsed);
}