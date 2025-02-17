const timespan = require('./lib/timespan');
const validateAsymmetricKey = require('./lib/validateAsymmetricKey');
const includes = require('lodash.includes');
const isBoolean = require('lodash.isboolean');
const isInteger = require('lodash.isinteger');
const isNumber = require('lodash.isnumber');
const isPlainObject = require('lodash.isplainobject');
const isString = require('lodash.isstring');
const crypto = require('crypto')
const oneShotAlgs = require('./lib/oneShotAlgs');
const encodeBase64url = require('./lib/base64url');

const SUPPORTED_ALGS = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'HS256', 'HS384', 'HS512',
  'EdDSA',
  'Ed25519', 'Ed448',
  'none',
];

const sign_options_schema = {
  expiresIn: { isValid: function(value) { return isInteger(value) || (isString(value) && value); }, message: '"expiresIn" should be a number of seconds or string representing a timespan' },
  notBefore: { isValid: function(value) { return isInteger(value) || (isString(value) && value); }, message: '"notBefore" should be a number of seconds or string representing a timespan' },
  audience: { isValid: function(value) { return isString(value) || Array.isArray(value); }, message: '"audience" must be a string or array' },
  algorithm: { isValid: includes.bind(null, SUPPORTED_ALGS), message: '"algorithm" must be a valid string enum value' },
  header: { isValid: isPlainObject, message: '"header" must be an object' },
  encoding: { isValid: isString, message: '"encoding" must be a string' },
  issuer: { isValid: isString, message: '"issuer" must be a string' },
  subject: { isValid: isString, message: '"subject" must be a string' },
  jwtid: { isValid: isString, message: '"jwtid" must be a string' },
  noTimestamp: { isValid: isBoolean, message: '"noTimestamp" must be a boolean' },
  keyid: { isValid: isString, message: '"keyid" must be a string' },
  mutatePayload: { isValid: isBoolean, message: '"mutatePayload" must be a boolean' },
  allowInsecureKeySizes: { isValid: isBoolean, message: '"allowInsecureKeySizes" must be a boolean'},
  allowInvalidAsymmetricKeyTypes: { isValid: isBoolean, message: '"allowInvalidAsymmetricKeyTypes" must be a boolean'}
};

const registered_claims_schema = {
  iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
  exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
  nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' }
};


function validate(schema, allowUnknown, object, parameterName) {
  if (!isPlainObject(object)) {
    throw new Error('Expected "' + parameterName + '" to be a plain object.');
  }
  Object.keys(object)
    .forEach(function(key) {
      const validator = schema[key];
      if (!validator) {
        if (!allowUnknown) {
          throw new Error('"' + key + '" is not allowed in "' + parameterName + '"');
        }
        return;
      }
      if (!validator.isValid(object[key])) {
        throw new Error(validator.message);
      }
    });
}

function validateOptions(options) {
  return validate(sign_options_schema, false, options, 'options');
}

function validatePayload(payload) {
  return validate(registered_claims_schema, true, payload, 'payload');
}

const options_to_payload = {
  'audience': 'aud',
  'issuer': 'iss',
  'subject': 'sub',
  'jwtid': 'jti'
};

const options_for_objects = [
  'expiresIn',
  'notBefore',
  'noTimestamp',
  'audience',
  'issuer',
  'subject',
  'jwtid',
];

function encodePayload(payload, encoding = 'utf8') {
  let buf;
  if (payload instanceof Uint8Array) {
    buf = Buffer.from(payload)
  } else if (typeof payload === 'string') {
    buf = Buffer.from(payload, encoding);
  } else {
    buf = Buffer.from(JSON.stringify(payload), encoding);
  }

  return encodeBase64url(buf);
}

function encodeHeader(header) {
  return encodeBase64url(Buffer.from(JSON.stringify(header)));
}

module.exports = function(payload, secretOrPrivateKey, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  } else {
    options = options || {};
  }

  let done;
  if (callback) {
    done = callback;
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }

  const isObjectPayload = typeof payload === 'object' &&
                        !Buffer.isBuffer(payload);

  const header = Object.assign({
    alg: options.algorithm || 'HS256',
    typ: isObjectPayload ? 'JWT' : undefined,
    kid: options.keyid
  }, options.header);

  function failure(err) {
    if (done) {
      return done(err);
    }
    throw err;
  }

  if (!secretOrPrivateKey && options.algorithm !== 'none') {
    return failure(new Error('secretOrPrivateKey must have a value'));
  }

  if (secretOrPrivateKey != null && !(secretOrPrivateKey instanceof crypto.KeyObject)) {
    try {
      secretOrPrivateKey = crypto.createPrivateKey(secretOrPrivateKey)
    } catch (_) {
      try {
        secretOrPrivateKey = crypto.createSecretKey(typeof secretOrPrivateKey === 'string' ? Buffer.from(secretOrPrivateKey) : secretOrPrivateKey)
      } catch (_) {
        return failure(new Error('secretOrPrivateKey is not valid key material'));
      }
    }
  }

  if (header.alg.startsWith('HS') && secretOrPrivateKey.type !== 'secret') {
    return failure(new Error((`secretOrPrivateKey must be a symmetric key when using ${header.alg}`)))
  } else if (/^(?:RS|PS|ES)/.test(header.alg)) {
    if (secretOrPrivateKey.type !== 'private') {
      return failure(new Error((`secretOrPrivateKey must be an asymmetric key when using ${header.alg}`)))
    }
  }

  if (typeof payload === 'undefined') {
    return failure(new Error('payload is required'));
  } else if (isObjectPayload) {
    try {
      validatePayload(payload);
    }
    catch (error) {
      return failure(error);
    }
    if (!options.mutatePayload) {
      payload = Object.assign({},payload);
    }
  } else {
    const invalid_options = options_for_objects.filter(function (opt) {
      return typeof options[opt] !== 'undefined';
    });

    if (invalid_options.length > 0) {
      return failure(new Error('invalid ' + invalid_options.join(',') + ' option for ' + (typeof payload ) + ' payload'));
    }
  }

  if (typeof payload.exp !== 'undefined' && typeof options.expiresIn !== 'undefined') {
    return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
  }

  if (typeof payload.nbf !== 'undefined' && typeof options.notBefore !== 'undefined') {
    return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
  }

  try {
    validateOptions(options);
  }
  catch (error) {
    return failure(error);
  }

  if (!options.allowInvalidAsymmetricKeyTypes) {
    try {
      validateAsymmetricKey(header.alg, secretOrPrivateKey);
    } catch (error) {
      return failure(error);
    }
  }

  const timestamp = payload.iat || Math.floor(Date.now() / 1000);

  if (options.noTimestamp) {
    delete payload.iat;
  } else if (isObjectPayload) {
    payload.iat = timestamp;
  }

  if (typeof options.notBefore !== 'undefined') {
    try {
      payload.nbf = timespan(options.notBefore, timestamp);
    }
    catch (err) {
      return failure(err);
    }
    if (typeof payload.nbf === 'undefined') {
      return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }

  if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object') {
    try {
      payload.exp = timespan(options.expiresIn, timestamp);
    }
    catch (err) {
      return failure(err);
    }
    if (typeof payload.exp === 'undefined') {
      return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }

  Object.keys(options_to_payload).forEach(function (key) {
    const claim = options_to_payload[key];
    if (typeof options[key] !== 'undefined') {
      if (typeof payload[claim] !== 'undefined') {
        return failure(new Error('Bad "options.' + key + '" option. The payload already has an "' + claim + '" property.'));
      }
      payload[claim] = options[key];
    }
  });

  const sync = done !== callback || header.alg === 'none' || header.alg.startsWith('HS') || parseInt(process.versions.node, 10) < 16 || options.allowInvalidAsymmetricKeyTypes;
  const data = `${encodeHeader(header)}.${encodePayload(payload, options.encoding)}`

  if (header.alg === 'none') {
    return done(null, `${data}.`)
  }

  if (header.alg.startsWith('HS')) {
    const signature = encodeBase64url(crypto.createHmac(`sha${header.alg.substring(2, 5)}`, secretOrPrivateKey).update(Buffer.from(data)).digest());
    return done(null, `${data}.${signature}`);
  }

  if (sync) {
    const { digest, key } = oneShotAlgs(header.alg, secretOrPrivateKey);

    let signature;
    try {
      signature = crypto.sign(digest, Buffer.from(data), key);
    } catch (err) {
      return done(err);
    }

    if(!options.allowInsecureKeySizes && (header.alg.startsWith('RS') || header.alg.startsWith('PS')) && signature.byteLength < 256) {
      return done(new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`));
    }

    const token = `${data}.${encodeBase64url(signature)}`;

    return done(null, token);
  }

  const { digest, key } = oneShotAlgs(header.alg, secretOrPrivateKey);

  crypto.sign(digest, Buffer.from(data), key, (err, signature) => {
    if (err) {
      return done(err);
    }

    if(!options.allowInsecureKeySizes && (header.alg.startsWith('RS') || header.alg.startsWith('PS')) && signature.byteLength < 256) {
      return done(new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`));
    }

    const token = `${data}.${encodeBase64url(signature)}`;

    return done(null, token);
  });
};
