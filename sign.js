var Joi = require('joi');
var timespan = require('./lib/timespan');
var xtend = require('xtend');
var jws = require('jws');

var sign_options_schema = Joi.object().keys({
  expiresIn: [Joi.number().integer(), Joi.string()],
  notBefore: [Joi.number().integer(), Joi.string()],
  audience:  [Joi.string(), Joi.array()],
  algorithm: Joi.string().valid('RS256','RS384','RS512','ES256','ES384','ES512','HS256','HS384','HS512','none'),
  header:    Joi.object(),
  encoding:  Joi.string(),
  issuer:    Joi.string(),
  subject:   Joi.string(),
  jwtid:     Joi.string(),
  noTimestamp: Joi.boolean()
});

var registered_claims_schema = Joi.object().keys({
  iat: Joi.number(),
  exp: Joi.number(),
  nbf: Joi.number()
}).unknown();


var options_to_payload = {
  'audience': 'aud',
  'issuer':   'iss',
  'subject':  'sub',
  'jwtid':    'jti'
};

var options_for_objects = [
  'expiresIn',
  'notBefore',
  'noTimestamp',
  'audience',
  'issuer',
  'subject',
  'jwtid',
];

module.exports = function(payload, secretOrPrivateKey, options, callback) {
  options = options || {};

  var header = xtend({
    alg: options.algorithm || 'HS256',
    typ: typeof payload === 'object' ? 'JWT' : undefined
  }, options.header);

  function failure (err) {
    if (callback) {
      return callback(err);
    }
    throw err;
  }

  if (typeof payload === 'undefined') {
    return failure(new Error('payload is required'));
  } else if (typeof payload === 'object') {
    var payload_validation_result = registered_claims_schema.validate(payload);

    if (payload_validation_result.error) {
      return failure(payload_validation_result.error);
    }

    payload = xtend(payload);
  } else if (typeof payload !== 'object') {
    var invalid_options = options_for_objects.filter(function (opt) {
      return typeof options[opt] !== 'undefined';
    });

    if (invalid_options.length > 0) {
      return failure(new Error('invalid ' + invalid_options.join(',') + ' option for ' + (typeof payload ) + ' payload' ));
    }
  }

  if (typeof payload.exp !== 'undefined' && typeof options.expiresIn !== 'undefined') {
    return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
  }

  if (typeof payload.nbf !== 'undefined' && typeof options.notBefore !== 'undefined') {
    return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
  }

  var validation_result = sign_options_schema.validate(options);

  if (validation_result.error) {
   return failure(validation_result.error);
  }

  var timestamp = payload.iat || Math.floor(Date.now() / 1000);

  if (!options.noTimestamp) {
    payload.iat = timestamp;
  } else {
    delete payload.iat;
  }

  if (typeof options.notBefore !== 'undefined') {
    payload.nbf = timespan(options.notBefore);
    if (typeof payload.nbf === 'undefined') {
      return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }

  if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object') {
    payload.exp = timespan(options.expiresIn);
    if (typeof payload.exp === 'undefined') {
      return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }

  Object.keys(options_to_payload).forEach(function (key) {
    var claim = options_to_payload[key];
    if (typeof options[key] !== 'undefined') {
      if (typeof payload[claim] !== 'undefined') {
        return failure(new Error('Bad "options.' + key + '" option. The payload already has an "' + claim + '" property.'));
      }
      payload[claim] = options[key];
    }
  });

  var encoding = options.encoding || 'utf8';

  if(typeof callback === 'function') {
    jws.createSign({
      header: header,
      privateKey: secretOrPrivateKey,
      payload: JSON.stringify(payload),
      encoding: encoding
    })
    .once('error', callback)
    .once('done', function(signature) {
      callback(null, signature);
    });
  } else {
    return jws.sign({header: header, payload: payload, secret: secretOrPrivateKey, encoding: encoding});
  }
};
