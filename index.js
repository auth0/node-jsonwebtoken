var jws = require('jws');

module.exports.decode = function (jwt) {
  var decoded = jws.decode(jwt);
  return decoded && decoded.payload;
};

module.exports.sign = function(payload, secretOrPrivateKey, options) {
  options = options || {};

  var header = {typ: 'JWT', alg: options.algorithm || 'HS256'};

  payload.iat = Math.round(Date.now() / 1000);

  if (options.expiresInMinutes) {
    var ms = options.expiresInMinutes * 60;
    payload.exp = payload.iat + ms;
  }

  if (options.audience)
    payload.aud = options.audience;

  if (options.issuer)
    payload.iss = options.issuer;

  if (options.subject)
    payload.sub = options.subject;

  var signed = jws.sign({header: header, payload: payload, secret: secretOrPrivateKey});

  return signed;
};

module.exports.verify = function(jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) callback = options;
  if (!options) options = {};

  var parts = jwtString.split('.');
  if (parts.length !== 3)
    return callback(new Error('jwt malformed'));

  if (parts[2].trim() === '' && secretOrPublicKey)
    return callback(new Error('jwt signature is required'));

  var valid;
  try {
    valid = jws.verify(jwtString, secretOrPublicKey);
  }
  catch (e) {
    return callback(e);
  }

  if (!valid)
    return callback(new Error('invalid signature'));

  var payload = this.decode(jwtString);

  if (payload.exp) {
    if (Math.round(Date.now()) / 1000 >= payload.exp)
      return callback(new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)));
  }

  if (options.audience) {
    var audiences = Array.isArray(options.audience)? options.audience : [options.audience];
    if (options.audience.indexOf(payload.aud) < 0)
      return callback(new Error('jwt audience invalid. expected: ' + payload.aud));
  }

  if (options.issuer) {
    if (payload.iss !== options.issuer)
      return callback(new Error('jwt issuer invalid. expected: ' + payload.iss));
  }

  callback(null, payload);
};

function JsonWebTokenError(message, error) {
  Error.call(this, message);
  this.name = 'JsonWebTokenError';
  this.message = message;
  if (error) this.inner = error;
}
JsonWebTokenError.prototype = Object.create(Error.prototype);
JsonWebTokenError.prototype.constructor = JsonWebTokenError;

var TokenExpiredError = module.exports.TokenExpiredError = function (message, expiredAt) {
  JsonWebTokenError.call(this, message);
  this.name = 'TokenExpiredError';
  this.expiredAt = expiredAt;
};
TokenExpiredError.prototype = Object.create(JsonWebTokenError.prototype);
TokenExpiredError.prototype.constructor = TokenExpiredError;
