module.exports = {
  decode: require('./decode'),
  verify: require('./verify'),
  sign: require('./sign'),
  refresh: require('./refresh'),
  JsonWebTokenError: require('./lib/JsonWebTokenError'),
  NotBeforeError: require('./lib/NotBeforeError'),
  TokenExpiredError: require('./lib/TokenExpiredError'),
};
