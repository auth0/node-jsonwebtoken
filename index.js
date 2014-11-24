'use strict';

var jws = require('jws');

/**
  Custom exceptions
  */
var JsonWebTokenError = module.exports.JsonWebTokenError = function (message, error) {
  Error.call(this, message);
  this.name = 'JsonWebTokenError';
  this.message = message;
  if (error) this.inner = error;
};

JsonWebTokenError.prototype = Object.create(Error.prototype);
JsonWebTokenError.prototype.constructor = JsonWebTokenError;

var TokenExpiredError = module.exports.TokenExpiredError = function (message, expiredAt) {
  JsonWebTokenError.call(this, message);
  this.name = 'TokenExpiredError';
  this.expiredAt = expiredAt;
};
TokenExpiredError.prototype = Object.create(JsonWebTokenError.prototype);
TokenExpiredError.prototype.constructor = TokenExpiredError;

/**
  Decode JsonWebToken
  */
module.exports.decode = function (jwt) {
  var decoded = jws.decode(jwt, {json: true});
  return decoded && decoded.payload;
};

/**
  Sign payload
  */
module.exports.sign = function (payload, secretOrPrivateKey, options) {
  options = options || {};

  var header = {typ: 'JWT', alg: options.algorithm || 'HS256'};

  payload.iat = Math.floor(Date.now() / 1000);

  if (options.expiresInMinutes) {
    var s = options.expiresInMinutes * 60;
    payload.exp = payload.iat + s;
  }

  if (options.audience) { payload.aud = options.audience; }

  if (options.issuer) { payload.iss = options.issuer; }

  if (options.subject) { payload.sub = options.subject; }

  var signed = jws.sign({header: header, payload: payload, secret: secretOrPrivateKey});

  return signed;
};

/**
  Verify and return decoded JsonWebToken
  @param {function} [callback] - Optional callback, without it, the method will return synchronously
  */
module.exports.verify = function(jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) {
    callback = options;
    options  = null;
  }

  try {
    var payload = this.verifySync(jwtString, secretOrPublicKey, options);

    if (!callback) { return payload; }

    callback(null, payload);
  } catch (err) {
    if (!callback) { throw err; }

    callback(err);
  }
};

module.exports.verifySync = function(jwtString, secretOrPublicKey, options) {
  if (!options) { options = {}; }

  if (!jwtString) {
    throw new JsonWebTokenError('jwt must be provided');
  }

  var parts = jwtString.split('.');
  if (parts.length !== 3)
    throw new JsonWebTokenError('jwt malformed');

  if (parts[2].trim() === '' && secretOrPublicKey)
    throw new JsonWebTokenError('jwt signature is required');

  var valid = jws.verify(jwtString, secretOrPublicKey); // might throw error

  if (!valid)
    throw new JsonWebTokenError('invalid signature');


  var payload = this.decode(jwtString); // might throw error

  // expiry date
  if (payload.exp && Math.floor(Date.now() / 1000) >= payload.exp) {
    throw new TokenExpiredError('jwt expired', new Date(payload.exp * 1000));
  }

  if (options.audience) {
    var audiences = Array.isArray(options.audience)? options.audience : [options.audience];

    if (audiences.indexOf(payload.aud) < 0) {
      throw new JsonWebTokenError('jwt audience invalid. expected: ' + payload.aud);
    }
  }

  if (options.issuer) {
    if (payload.iss !== options.issuer) {
      throw new JsonWebTokenError('jwt issuer invalid. expected: ' + payload.iss);
    }
  }

  return payload;
}