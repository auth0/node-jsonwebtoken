const signObj = require('./sign');
module.exports = {
  verify: require('./verify'),
  sign: signObj.sign,
  supported_algorithms: signObj.SUPPORTED_ALGS,
  JsonWebTokenError: require('./lib/JsonWebTokenError'),
  NotBeforeError: require('./lib/NotBeforeError'),
  TokenExpiredError: require('./lib/TokenExpiredError'),
};

Object.defineProperty(module.exports, 'decode', {
  enumerable: false,
  value: require('./decode'),
});