var JsonWebTokenError = require('./lib/JsonWebTokenError');
var NotBeforeError    = require('./lib/NotBeforeError');
var TokenExpiredError = require('./lib/TokenExpiredError');
var decode            = require('./decode');
var timespan          = require('./lib/timespan');
var jws               = require('jws');
var base64url = require('base64-url');

function jwsVerifyWithCryptoModule(cryptoManager, keyName, jwtString, algorithm) {
  try {

    if(algorithm !== 'ES256k') return false;

    var parts = jwtString.split('.');
    var toVerify = Buffer.from(parts[0] + '.' + parts[1]).toString('ascii');
    var signature = base64url.decode(parts[2]);
    var verified = cryptoManager.verify(toVerify, signature, keyName, 'SHA256');
    return verified;
  } catch (e) {
    return false;
  }
}

module.exports = function (jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) {
    callback = options;
    options = {};
  }

  if (!options) {
    options = {};
  }

  //clone this object since we are going to mutate it.
  options = Object.assign({}, options);

  var done;

  if (callback) {
    done = callback;
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }

  if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
    return done(new JsonWebTokenError('clockTimestamp must be a number'));
  }

  if (options.nonce !== undefined && (typeof options.nonce !== 'string' || options.nonce.trim() === '')) {
    return done(new JsonWebTokenError('nonce must be a non-empty string'));
  }

  var clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1000);

  if (!jwtString){
    return done(new JsonWebTokenError('jwt must be provided'));
  }

  if (typeof jwtString !== 'string') {
    return done(new JsonWebTokenError('jwt must be a string'));
  }

  var parts = jwtString.split('.');

  if (parts.length !== 3){
    return done(new JsonWebTokenError('jwt malformed'));
  }

  var decodedToken;

  try {
    decodedToken = decode(jwtString, { complete: true });
  } catch(err) {
    return done(err);
  }

  if (!decodedToken) {
    return done(new JsonWebTokenError('invalid token'));
  }

  var header = decodedToken.header;
  var getSecret;

  if(typeof secretOrPublicKey === 'function') {
    if(!callback) {
      return done(new JsonWebTokenError('verify must be called asynchronous if secret or public key is provided as a callback'));
    }

    getSecret = secretOrPublicKey;
  }
  else {
    getSecret = function(header, secretCallback) {
      return secretCallback(null, secretOrPublicKey);
    };
  }

  return getSecret(header, function(err, secretOrPublicKey) {
    var cryptoManager = options.cryptoManager;
    var keyName = options.keyName;

    if(keyName && !cryptoManager) {
      return done(new JsonWebTokenError('Keyname is only supported with cryptoManager'));
    }

    if(!keyName && cryptoManager) {
      return done(new JsonWebTokenError('Keyname is required when using a cryptoManager'));
    }

    if(err) {
      return done(new JsonWebTokenError('error in secret or public key callback: ' + err.message));
    }

    var hasSignature = parts[2].trim() !== '';

    if (!hasSignature && (secretOrPublicKey || cryptoManager)){
      return done(new JsonWebTokenError('jwt signature is required'));
    }

    if (hasSignature && !(secretOrPublicKey || cryptoManager)) {
      return done(new JsonWebTokenError('secret or public key must be provided'));
    }

    if (!hasSignature && !options.algorithms) {
      options.algorithms = ['none'];
    }

    if (cryptoManager && !options.algorithms) {
      options.algorithms = ['ES256k'];
    }

    if (!options.algorithms) {
      options.algorithms = ~secretOrPublicKey.toString().indexOf('BEGIN CERTIFICATE') ||
          ~secretOrPublicKey.toString().indexOf('BEGIN PUBLIC KEY') ?
        ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'] :
        ~secretOrPublicKey.toString().indexOf('BEGIN RSA PUBLIC KEY') ?
          ['RS256', 'RS384', 'RS512'] :
          ['HS256', 'HS384', 'HS512'];

    }

    if (!~options.algorithms.indexOf(decodedToken.header.alg)) {
      return done(new JsonWebTokenError('invalid algorithm'));
    }

    var valid;

    try {

      if(cryptoManager) {
        valid = jwsVerifyWithCryptoModule(cryptoManager, keyName, jwtString, decodedToken.header.alg)
      } else {
        valid = jws.verify(jwtString, decodedToken.header.alg, secretOrPublicKey);
      }
    } catch (e) {
      return done(e);
    }

    if (!valid) {
      return done(new JsonWebTokenError('invalid signature'));
    }

    var payload = decodedToken.payload;

    if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
      if (typeof payload.nbf !== 'number') {
        return done(new JsonWebTokenError('invalid nbf value'));
      }
      if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
        return done(new NotBeforeError('jwt not active', new Date(payload.nbf * 1000)));
      }
    }

    if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
      if (typeof payload.exp !== 'number') {
        return done(new JsonWebTokenError('invalid exp value'));
      }
      if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
        return done(new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)));
      }
    }

    if (options.audience) {
      var audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
      var target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

      var match = target.some(function (targetAudience) {
        return audiences.some(function (audience) {
          return audience instanceof RegExp ? audience.test(targetAudience) : audience === targetAudience;
        });
      });

      if (!match) {
        return done(new JsonWebTokenError('jwt audience invalid. expected: ' + audiences.join(' or ')));
      }
    }

    if (options.issuer) {
      var invalid_issuer =
              (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
              (Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss) === -1);

      if (invalid_issuer) {
        return done(new JsonWebTokenError('jwt issuer invalid. expected: ' + options.issuer));
      }
    }

    if (options.subject) {
      if (payload.sub !== options.subject) {
        return done(new JsonWebTokenError('jwt subject invalid. expected: ' + options.subject));
      }
    }

    if (options.jwtid) {
      if (payload.jti !== options.jwtid) {
        return done(new JsonWebTokenError('jwt jwtid invalid. expected: ' + options.jwtid));
      }
    }

    if (options.nonce) {
      if (payload.nonce !== options.nonce) {
        return done(new JsonWebTokenError('jwt nonce invalid. expected: ' + options.nonce));
      }
    }

    if (options.maxAge) {
      if (typeof payload.iat !== 'number') {
        return done(new JsonWebTokenError('iat required when maxAge is specified'));
      }

      var maxAgeTimestamp = timespan(options.maxAge, payload.iat);
      if (typeof maxAgeTimestamp === 'undefined') {
        return done(new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
      }
      if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
        return done(new TokenExpiredError('maxAge exceeded', new Date(maxAgeTimestamp * 1000)));
      }
    }

    return done(null, payload);
  });
};
