var jws = require('jws');
var ms = require('ms');
var timespan = require('./lib/timespan');
var xtend = require('xtend');

var JWT = module.exports;

var JsonWebTokenError = JWT.JsonWebTokenError = require('./lib/JsonWebTokenError');
var NotBeforeError = module.exports.NotBeforeError = require('./lib/NotBeforeError');
var TokenExpiredError = JWT.TokenExpiredError = require('./lib/TokenExpiredError');

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

var payload_options = [
  'expiresIn',
  'notBefore',
  'expiresInMinutes',
  'expiresInSeconds',
  'audience',
  'issuer',
  'subject',
  'jwtid'
];

JWT.sign = function(payload, secretOrPrivateKey, options, callback) {
  options = options || {};
  var header = {};

  if (typeof payload === 'object') {
    header.typ = 'JWT';
    payload = xtend(payload);
  } else {
    var invalid_option = payload_options.filter(function (key) {
      return typeof options[key] !== 'undefined';
    })[0];

    if (invalid_option) {
      console.warn('invalid "' + invalid_option + '" option for ' + (typeof payload) + ' payload');
    }
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

  if (typeof options.notBefore !== 'undefined') {
    payload.nbf = timespan(options.notBefore);
    if (typeof payload.nbf === 'undefined') {
      throw new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
    }
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
  } else if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object') {
    payload.exp = timespan(options.expiresIn);
    if (typeof payload.exp === 'undefined') {
      throw new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
    }
  }

  if (options.audience)
    payload.aud = options.audience;

  if (options.issuer)
    payload.iss = options.issuer;

  if (options.subject)
    payload.sub = options.subject;

  if (options.jwtid)
    payload.jti = options.jwtid;

  var encoding = 'utf8';
  if (options.encoding) {
    encoding = options.encoding;
  }

  if(typeof callback === 'function') {
    jws.createSign({
      header: header,
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

  if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') {
      return done(new JsonWebTokenError('invalid nbf value'));
    }
    if (payload.nbf > Math.floor(Date.now() / 1000)) {
      return done(new NotBeforeError('jwt not active', new Date(payload.nbf * 1000)));
    }
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

/**
* Will refresh the given token.  The token is expected to be decoded and valid. No checks will be
* performed on the token.  The function will copy the values of the token, give it a new
* expiry time based on the given 'expiresIn' time and will return a new signed token.
*
* @param token
* @param expiresIn
* @param secretOrPrivateKey
* @param callback
* @return New signed JWT token
*/
JWT.refresh = function(token, expiresIn, secretOrPrivateKey, callback) {
    //TODO: check if token is not good, if so return error ie: no payload, not required fields, etc.

    var done;
    if (callback) {
        done = function() {
            var args = Array.prototype.slice.call(arguments, 0);
            return process.nextTick(function() {
                callback.apply(null, args);
            });
        };
    }
    else {
        done = function(err, data) {
            if (err) {
                console.log('err : ' + err);
                throw err;
            }
            return data;
        };
    }

    var header;
    var payload;

    if (token.header) {
        header = token['header'];
        payload = token['payload'];
    }
    else {
        payload = token;
    }

    var optionMapping = {
        exp: 'expiresIn',
        aud: 'audience',
        nbf: 'notBefore',
        iss: 'issuer',
        sub: 'subject',
        jti: 'jwtid',
        alg: 'algorithm'
    };
    var newToken;
    var obj = {};
    var options = {};

    for (var key in payload) {
        if (Object.keys(optionMapping).indexOf(key) === -1) {
            obj[key] = payload[key];
        }
        else {
            options[optionMapping[key]] = payload[key];
        }
    }

    if(header) {
        options.headers = { };
        for (var key in header) {
            if (key !== 'typ') {    //don't care about typ -> always JWT
                if (Object.keys(optionMapping).indexOf(key) === -1) {
                    options.headers[key] = header[key];
                }
                else {
                    options[optionMapping[key]] = header[key];
                }
            }
        }
    }
    else {
        console.log('No algorithm was defined for token refresh - using default');
    }

    if (!token.iat) {
        options['noTimestamp'] = true;
    }

    options['expiresIn'] = expiresIn;

    newToken = JWT.sign(obj, secretOrPrivateKey, options);
    return done(null, newToken);
};
