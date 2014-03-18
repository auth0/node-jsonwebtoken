var jws = require('jws');
var moment = require('moment');

module.exports.decode = function (jwt) {
  return jws.decode(jwt).payload;
};

module.exports.sign = function(payload, secretOrPrivateKey, options) {
  options = options || {};

  var header = {typ: 'JWT', alg: options.algorithm || 'HS256'};
  if (options.expiresInMinutes)
    payload.exp = moment().add('minutes', options.expiresInMinutes).utc().unix();

  if (options.audience)
    payload.aud = options.audience;

  if (options.issuer)
    payload.iss = options.issuer;

  if (options.subject)
    payload.sub = options.subject;

  payload.iat = moment().utc().unix();

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
    if (moment().utc().unix() >= payload.exp)
      return callback(new Error('jwt expired'));
  }

  if (payload.aud && options.audience) {
    if (payload.aud !== options.audience)
      return callback(new Error('jwt audience invalid. expected: ' + payload.aud));
  }

  if (payload.iss && options.issuer) {
    if (payload.iss !== options.issuer)
      return callback(new Error('jwt issuer invalid. expected: ' + payload.iss));
  }

  callback(null, payload);
};


