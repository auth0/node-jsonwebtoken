var jws = require('jws');

module.exports.decode = function (jwt) {
  var decoded = jws.decode(jwt, {json: true});
  return decoded && decoded.payload;
};

module.exports.sign = function(payload, secretOrPrivateKey, options) {
  options = options || {};

  var header = {typ: 'JWT', alg: options.algorithm || 'HS256'};

  payload.iat = Math.floor(Date.now() / 1000);

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

  if (!jwtString)
    return callback(new JsonWebTokenError('jwt must be provided'));

  var parts = jwtString.split('.');
  if (parts.length !== 3)
    return callback(new JsonWebTokenError('jwt malformed'));

  if (parts[2].trim() === '' && secretOrPublicKey)
    return callback(new JsonWebTokenError('jwt signature is required'));

  var valid;
  try {
    valid = jws.verify(jwtString, secretOrPublicKey);
  }
  catch (e) {
    return callback(e);
  }

  if (!valid)
    return callback(new JsonWebTokenError('invalid signature'));

  var payload;

  try {
   payload = this.decode(jwtString);
  } catch(err) {
    return callback(err);
  }

  if (payload.exp) {
    if (Math.floor(Date.now() / 1000) >= payload.exp)
      return callback(new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)));
  }

  if (options.audience) {
    var audiences = Array.isArray(options.audience)? options.audience : [options.audience];
    var target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    
    var match = target.some(function(aud) { return audiences.indexOf(aud) != -1; });

    if (!match)
      return callback(new JsonWebTokenError('jwt audience invalid. expected: ' + payload.aud));
  }

  if (options.issuer) {
    if (payload.iss !== options.issuer)
      return callback(new JsonWebTokenError('jwt issuer invalid. expected: ' + payload.iss));
  }

  callback(null, payload);
};

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
