var JsonWebTokenError = require('./lib/JsonWebTokenError');
var NotBeforeError    = require('./lib/NotBeforeError');
var TokenExpiredError = require('./lib/TokenExpiredError');
var decode            = require('./decode');
var jws               = require('jws');
var ms                = require('ms');
var xtend             = require('xtend');

module.exports = function (jwtString, secretOrPublicKey, options) {
  options = options || {};

  // clone this object since we are going to mutate it.
  options = xtend(options);

  if (!jwtString){
    throw new JsonWebTokenError('jwt must be provided');
  }

  var parts = jwtString.split('.');

  if (parts.length !== 3){
    throw new JsonWebTokenError('jwt malformed');
  }

  var hasSignature = parts[2].trim() !== '';

  if (!hasSignature && secretOrPublicKey){
    throw new JsonWebTokenError('jwt signature is required');
  }

  if (hasSignature && !secretOrPublicKey) {
    throw new JsonWebTokenError('secret or public key must be provided');
  }

  if (!hasSignature && !options.algorithms) {
    options.algorithms = ['none'];
  }

  if (!options.algorithms) {
    options.algorithms = ~secretOrPublicKey.toString().indexOf('BEGIN CERTIFICATE') ||
                         ~secretOrPublicKey.toString().indexOf('BEGIN PUBLIC KEY') ?
                          [ 'RS256','RS384','RS512','ES256','ES384','ES512' ] :
                         ~secretOrPublicKey.toString().indexOf('BEGIN RSA PUBLIC KEY') ?
                          [ 'RS256','RS384','RS512' ] :
                          [ 'HS256','HS384','HS512' ];

  }

  var decodedToken;
  try {
    decodedToken = jws.decode(jwtString);
  } catch (err) {
    throw new JsonWebTokenError('invalid token');
  }

  if (!decodedToken) {
    throw new JsonWebTokenError('invalid token');
  }

  var header = decodedToken.header;

  if (!~options.algorithms.indexOf(header.alg)) {
    throw new JsonWebTokenError('invalid algorithm');
  }

  var valid = jws.verify(jwtString, header.alg, secretOrPublicKey);

  if (!valid) {
    throw new JsonWebTokenError('invalid signature');
  }

  var payload = decode(jwtString);

  if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') {
      throw new JsonWebTokenError('invalid nbf value');
    }
    if (payload.nbf > Math.floor(Date.now() / 1000) + (options.clockTolerance || 0)) {
      throw new NotBeforeError('jwt not active', new Date(payload.nbf * 1000));
    }
  }

  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
      throw new JsonWebTokenError('invalid exp value');
    }
    if (Math.floor(Date.now() / 1000) >= payload.exp + (options.clockTolerance || 0)) {
      throw new TokenExpiredError('jwt expired', new Date(payload.exp * 1000));
    }
  }

  if (options.audience) {
    var audiences = Array.isArray(options.audience)? options.audience : [options.audience];
    var target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

    var match = target.some(function(aud) { return audiences.indexOf(aud) != -1; });

    if (!match) {
      throw new JsonWebTokenError('jwt audience invalid. expected: ' + audiences.join(' or '));
    }
  }

  if (options.issuer) {
    var invalid_issuer =
        (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
        (Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss) === -1);

    if (invalid_issuer) {
      throw new JsonWebTokenError('jwt issuer invalid. expected: ' + options.issuer);
    }
  }

  if (options.subject) {
    if (payload.sub !== options.subject) {
      throw new JsonWebTokenError('jwt subject invalid. expected: ' + options.subject);
    }
  }

  if (options.jwtid) {
    if (payload.jti !== options.jwtid) {
      throw new JsonWebTokenError('jwt jwtid invalid. expected: ' + options.jwtid);
    }
  }

  if (options.maxAge) {
    var maxAge = ms(options.maxAge);
    if (typeof payload.iat !== 'number') {
      throw new JsonWebTokenError('iat required when maxAge is specified');
    }
    if (Date.now() - (payload.iat * 1000) > maxAge + (options.clockTolerance || 0) * 1000) {
      throw new TokenExpiredError('maxAge exceeded', new Date(payload.iat * 1000 + maxAge));
    }
  }

  return payload;
};
