import { createRequire } from 'module';
const require = createRequire(import.meta.url);
export const verify = require('./verify.js');
export const sign = require('./sign.js');
export const JsonWebTokenError = require('./lib/JsonWebTokenError.js');
export const NotBeforeError = require('./lib/NotBeforeError.js');
export const TokenExpiredError = require('./lib/TokenExpiredError.js');
export const decode = require('./decode');
export default { verify, sign, JsonWebTokenError, NotBeforeError, TokenExpiredError, decode }
