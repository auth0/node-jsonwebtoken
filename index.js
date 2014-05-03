var jws = require('jws');

module.exports.decode = function (jwt) {
  return jws.decode(jwt).payload;
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
      return callback(new Error('jwt expired'));
  }

  if (options.audience) {
    if (payload.aud !== options.audience)
      return callback(new Error('jwt audience invalid. expected: ' + payload.aud));
  }

  if (options.issuer) {
    if (payload.iss !== options.issuer)
      return callback(new Error('jwt issuer invalid. expected: ' + payload.iss));
  }

  callback(null, payload);
};
