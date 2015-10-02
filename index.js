var jws = require('jws');
var ms = require('ms');

var JWT = module.exports;

var JsonWebTokenError = JWT.JsonWebTokenError = require('./lib/JsonWebTokenError');
var TokenExpiredError = JWT.TokenExpiredError = require('./lib/TokenExpiredError');
var ms = require('ms')

JWT.decode = function (jwt, options) {
  options = options || {};
  var decoded = jws.decode(jwt, options);
  if (!decoded) { return null; }
  var payload = decoded.payload;

  //try parse the payload
  if(typeof payload === 'string') {
    try {
      var obj = JSON.parse(payload);
      if(typeof obj === 'object') {
        payload = obj;
      }
    } catch (e) { }
  }

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  if (options.complete === true) {
    return {
      header: decoded.header,
      payload: payload,
      signature: decoded.signature
    };
  }
  return payload;
};

JWT.sign = function(payload, secretOrPrivateKey, options, callback) {
  options = options || {};

  var header = {};

  if (typeof payload === 'object') {
    header.typ = 'JWT';
  }

  header.alg = options.algorithm || 'HS256';

  if (options.headers) {
    Object.keys(options.headers).forEach(function (k) {
      header[k] = options.headers[k];
    });
  }

  var timestamp = Math.floor(Date.now() / 1000);
  if (!options.noTimestamp) {
    payload.iat = payload.iat || timestamp;
  }

  if (options.expiresInSeconds || options.expiresInMinutes) {
    var deprecated_line;
    try {
      deprecated_line = /.*\((.*)\).*/.exec((new Error()).stack.split('\n')[2])[1];
    } catch(err) {
      deprecated_line = '';
    }

    console.warn('jsonwebtoken: expiresInMinutes and expiresInSeconds is deprecated. (' + deprecated_line + ')\n' +
                 'Use "expiresIn" expressed in seconds.');

    var expiresInSeconds = options.expiresInMinutes ?
        options.expiresInMinutes * 60 :
        options.expiresInSeconds;

    payload.exp = timestamp + expiresInSeconds;
  } else if (options.expiresIn) {
    if (typeof options.expiresIn === 'string') {
      var milliseconds = ms(options.expiresIn);
      if (typeof milliseconds === 'undefined') {
        throw new Error('bad "expiresIn" format: ' + options.expiresIn);
      }
      payload.exp = timestamp + milliseconds / 1000;
    } else if (typeof options.expiresIn === 'number' ) {
      payload.exp = timestamp + options.expiresIn;
    } else {
      throw new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
    }
  }

  if (options.audience)
    payload.aud = options.audience;

  if (options.issuer)
    payload.iss = options.issuer;

  if (options.subject)
    payload.sub = options.subject;

  var encoding = 'utf8';
  if (options.encoding) {
    encoding = options.encoding;
  }

  if(typeof callback === 'function') {
    jws.createSign({
      header: header,
      payload: payload,
      privateKey: secretOrPrivateKey,
      payload: JSON.stringify(payload)
    }).on('done', callback);
  } else {
    return jws.sign({header: header, payload: payload, secret: secretOrPrivateKey, encoding: encoding});
  }
};

JWT.verify = function(jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) {
    callback = options;
    options = {};
  }

  if (!options) options = {};

  var done;

  if (callback) {
    done = function() {
      var args = Array.prototype.slice.call(arguments, 0);
      return process.nextTick(function() {
        callback.apply(null, args);
      });
    };
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }

  if (!jwtString){
    return done(new JsonWebTokenError('jwt must be provided'));
  }

  var parts = jwtString.split('.');

  if (parts.length !== 3){
    return done(new JsonWebTokenError('jwt malformed'));
  }

  if (parts[2].trim() === '' && secretOrPublicKey){
    return done(new JsonWebTokenError('jwt signature is required'));
  }

  if (!secretOrPublicKey) {
    return done(new JsonWebTokenError('secret or public key must be provided'));
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
  } catch(err) {
    return done(new JsonWebTokenError('invalid token'));
  }

  if (!decodedToken) {
    return done(new JsonWebTokenError('invalid token'));
  }

  var header = decodedToken.header;

  if (!~options.algorithms.indexOf(header.alg)) {
    return done(new JsonWebTokenError('invalid algorithm'));
  }

  var valid;

  try {
    valid = jws.verify(jwtString, header.alg, secretOrPublicKey);
  } catch (e) {
    return done(e);
  }

  if (!valid)
    return done(new JsonWebTokenError('invalid signature'));

  var payload;

  try {
    payload = JWT.decode(jwtString);
  } catch(err) {
    return done(err);
  }

  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
      return done(new JsonWebTokenError('invalid exp value'));
    }
    if (Math.floor(Date.now() / 1000) >= payload.exp)
      return done(new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)));
  }

  if (options.audience) {
    var audiences = Array.isArray(options.audience)? options.audience : [options.audience];
    var target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

    var match = target.some(function(aud) { return audiences.indexOf(aud) != -1; });

    if (!match)
      return done(new JsonWebTokenError('jwt audience invalid. expected: ' + audiences.join(' or ')));
  }

  if (options.issuer) {
    if (payload.iss !== options.issuer)
      return done(new JsonWebTokenError('jwt issuer invalid. expected: ' + options.issuer));
  }

  if (options.maxAge) {
    var maxAge = ms(options.maxAge);
    if (typeof payload.iat !== 'number') {
      return done(new JsonWebTokenError('iat required when maxAge is specified'));
    }
    if (Date.now() - (payload.iat * 1000) > maxAge) {
      return done(new TokenExpiredError('maxAge exceeded', new Date(payload.iat * 1000 + maxAge)));
    }
  }

  return done(null, payload);
};
