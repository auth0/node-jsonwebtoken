import { parseJwt, decodeHeader, decodePayload } from './lib/jwt-core.js';
import { DecodeOptions, JwtPayload, CompleteResult, JwtHeader } from './types.js';
import { validateTokenSize, DEFAULT_MAX_TOKEN_SIZE } from './lib/shared/dos-protection.js';

export function decode(token: string, options?: DecodeOptions & { complete: true }): CompleteResult | null;
export function decode(token: string, options?: DecodeOptions): JwtPayload | null;
export function decode(token: string, options: DecodeOptions = {}): JwtPayload | CompleteResult | null {
  if (!token || typeof token !== 'string') {
    return null;
  }
  
  // Apply DoS protection - validate token size
  if (!options.disableDoSProtection) {
    const maxTokenSize = options.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE;
    try {
      validateTokenSize(token, maxTokenSize);
    } catch (err) {
      // For decode, we return null on validation errors to maintain backward compatibility
      return null;
    }
  }
  
  // Parse the JWT into its parts
  const parts = parseJwt(token);
  if (!parts) {
    return null;
  }
  
  // Decode header
  const header = decodeHeader(token);
  if (!header) {
    return null;
  }
  
  // Decode payload
  const json = header.typ === 'JWT' || options.json !== false;
  const payload = decodePayload(token, json, options);
  
  if (payload === null) {
    return null;
  }
  
  // Return header if `complete` option is enabled. Header includes claims
  // such as `kid` and `alg` used to select the key within a JWKS needed to
  // verify the signature
  if (options.complete === true) {
    return {
      header: header as JwtHeader,
      payload,
      signature: parts.signature
    };
  }
  
  return payload;
}