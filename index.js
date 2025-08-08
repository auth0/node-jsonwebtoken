const decode = require('./decode');
const verify = require('./verify');
const sign = require('./sign');
const JsonWebTokenError = require('./lib/JsonWebTokenError');
const NotBeforeError = require('./lib/NotBeforeError');
const TokenExpiredError = require('./lib/TokenExpiredError');

module.exports = {
  decode,
  verify,
  sign,
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError,
};
