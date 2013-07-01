var jws = require('jws');
var moment = require('moment');

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
  
  var jwt = jws.decode(jwtString);

  if (jwt.payload.exp) {
    if (moment().utc().unix() >= jwt.payload.exp)
      return callback(new Error('jwt expired'));
  }

  if (jwt.payload.aud && options.audience) {
    if (jwt.payload.aud !== options.audience)
      return callback(new Error('jwt audience invalid. expected: ' + jwt.payload.aud));
  }

  if (jwt.payload.iss && options.issuer) {
    if (jwt.payload.iss !== options.issuer)
      return callback(new Error('jwt issuer invalid. expected: ' + jwt.payload.iss));
  }
  
  callback(null, jwt.payload);
};


