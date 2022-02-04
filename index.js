const { verify, isExpired } = require('./verify');
module.exports = {
  verify: verify,
  isExpired: isExpired,
  sign: require('./sign'),
  JsonWebTokenError: require('./lib/JsonWebTokenError'),
  NotBeforeError: require('./lib/NotBeforeError'),
  TokenExpiredError: require('./lib/TokenExpiredError'),
};

Object.defineProperty(module.exports, 'decode', {
  enumerable: false,
  value: require('./decode'),
});