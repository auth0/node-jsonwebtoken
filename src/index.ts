export { decode } from './decode.js';
export { verify } from './verify.js';
export { verifySync } from './verifySync.js';
export { sign } from './sign.js';
export { signSync } from './signSync.js';
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
  VerifyErrors,
  SignCallback,
  VerifyCallback,
  VerifyCallbackComplete
} from './types.js';

// Default export for CommonJS compatibility
import { decode } from './decode.js';
import { verify } from './verify.js';
import { verifySync } from './verifySync.js';
import { sign } from './sign.js';
import { signSync } from './signSync.js';
import { JsonWebTokenError } from './lib/JsonWebTokenError.js';
import { NotBeforeError } from './lib/NotBeforeError.js';
import { TokenExpiredError } from './lib/TokenExpiredError.js';

export default {
  decode,
  verify,
  verifySync,
  sign,
  signSync,
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError
};