import { prepareVerifyContext, verifySignature, validateClaims } from './lib/shared/verify-core.js';
import { createSanitizedHeader } from './lib/shared/header-validation.js';
import {
  VerifyOptions,
  PublicKey,
  Secret,
  GetPublicKeyOrSecret,
  JwtPayload,
  CompleteResult,
  VerifyErrors
} from './types.js';

// Callback types
type VerifyCallbackComplete = (err: VerifyErrors | null, decoded?: CompleteResult) => void;
type VerifyCallback = (err: VerifyErrors | null, decoded?: JwtPayload) => void;

// Overloaded function signatures for async/Promise
export function verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options: VerifyOptions & { complete: true }): Promise<CompleteResult>;
export function verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options?: VerifyOptions): Promise<JwtPayload>;

// Overloaded function signatures for callback
export function verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, callback: VerifyCallback): void;
export function verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options: VerifyOptions & { complete: true }, callback: VerifyCallbackComplete): void;
export function verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options: VerifyOptions, callback: VerifyCallback): void;

export function verify(
  jwtString: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  optionsOrCallback?: VerifyOptions | VerifyCallback | VerifyCallbackComplete,
  callback?: VerifyCallback | VerifyCallbackComplete
): Promise<JwtPayload | CompleteResult> | void {
  // Handle overloaded arguments
  let options: VerifyOptions = {};
  let done: VerifyCallback | VerifyCallbackComplete | undefined;
  
  if (typeof optionsOrCallback === 'function') {
    done = optionsOrCallback;
  } else if (optionsOrCallback) {
    options = optionsOrCallback;
    done = callback;
  }
  
  // If no callback provided, return a Promise
  if (!done) {
    return verifyAsync(jwtString, secretOrPublicKey, options);
  }
  
  // Callback mode - handle errors
  verifyAsync(jwtString, secretOrPublicKey, options)
    .then(decoded => done!(null, decoded as any))
    .catch(err => done!(err));
}

async function verifyAsync(
  jwtString: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  options: VerifyOptions
): Promise<JwtPayload | CompleteResult> {
  // For function keys, pass a placeholder since we'll resolve it later
  const keyForContext = typeof secretOrPublicKey === 'function' 
    ? '' as Secret  // Placeholder, will be resolved below
    : secretOrPublicKey;
  const context = prepareVerifyContext(jwtString, keyForContext, options);
  const clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1000);
  
  // Handle async key resolution
  let key: Secret | PublicKey;
  if (typeof secretOrPublicKey === 'function') {
    // Pass sanitized header to callback for security
    const sanitizedHeader = createSanitizedHeader(context.header, options);
    key = await secretOrPublicKey(sanitizedHeader);
  } else {
    key = secretOrPublicKey;
  }
  
  // Verify signature
  verifySignature(context, key);
  
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