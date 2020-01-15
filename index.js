module.exports = {
  decode: require('./decode'),
  verify: require('./verify'),
  sign: require('./sign'),
  timespan: require('./lib/timespan'),
  JsonWebTokenError: require('./lib/JsonWebTokenError'),
  NotBeforeError: require('./lib/NotBeforeError'),
  TokenExpiredError: require('./lib/TokenExpiredError'),
};
