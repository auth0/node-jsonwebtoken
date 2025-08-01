export { decode } from './decode.js';
export { verify } from './verify.js';
export { sign } from './sign.js';
export { JsonWebTokenError } from './lib/JsonWebTokenError.js';
export { NotBeforeError } from './lib/NotBeforeError.js';
export { TokenExpiredError } from './lib/TokenExpiredError.js';

// Re-export types
export type {
  Algorithm,
  SignOptions,
  VerifyOptions,
  DecodeOptions,
  JwtPayload,
  JwtHeader,
  Secret,
  PublicKey,
  GetPublicKeyOrSecret,
  VerifyErrors
} from './types.js';