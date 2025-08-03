import { prepareVerifyContext, verifySignature, validateClaims } from './lib/shared/verify-core.js';
import { VerifyOptions, Secret, PublicKey, JwtPayload, CompleteResult } from './types.js';
import { JsonWebTokenError } from './lib/JsonWebTokenError.js';

// Overloaded function signatures
export function verifySync(token: string, secretOrPublicKey: Secret | PublicKey, options: VerifyOptions & { complete: true }): CompleteResult;
export function verifySync(token: string, secretOrPublicKey: Secret | PublicKey, options?: VerifyOptions): JwtPayload;

export function verifySync(
  jwtString: string,
  secretOrPublicKey: Secret | PublicKey,
  options: VerifyOptions = {}
): JwtPayload | CompleteResult {
  // Note: verifySync cannot support GetPublicKeyOrSecret since it's async
  if (typeof secretOrPublicKey === 'function') {
    throw new JsonWebTokenError('Synchronous verify cannot use async key resolution. Use verify() instead.');
  }

  const context = prepareVerifyContext(jwtString, secretOrPublicKey, options);
  const clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1000);
  
  // Verify signature
  verifySignature(context, secretOrPublicKey);
  
  // Validate claims
  validateClaims(context.payload, options, clockTimestamp);
  
  if (options.complete === true) {
    return {
      header: context.header,
      payload: context.payload,
      signature: context.decodedToken.signature
    };
  }

  return context.payload;
}