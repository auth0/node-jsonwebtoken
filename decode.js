var jws = require('jws');

/**
 * (Synchronous) Returns the decoded payload without verifying if the signature is valid.
 *
 * > Warning: This will not verify whether the signature is valid. You should not use this for untrusted messages. You most likely want to use `jwt.verify` instead.
 *
 * > Warning: When the token comes from an untrusted source (e.g. user input or external request), the returned decoded payload should be treated like any other user input; please make sure to sanitize and only work with properties that are expected.
 * @param {string} jwt The JsonWebToken string.
 * @param {object?} options Options
 * @param {object} options.json Force `JSON.parse` on the payload even if the header doesn't contain `"typ":"JWT"`.
 * @param {boolean} options.complete Return an object with the decoded payload and header.
 * @returns {{header: *, payload: string, signature: *}|string|null}
 */
module.exports = function (jwt, options) {
  options = options || {};
  var decoded = jws.decode(jwt, options);
  if (!decoded) { return null; }
  var payload = decoded.payload;

  //try parse the payload
  if(typeof payload === 'string') {
    try {
      var obj = JSON.parse(payload);
      if(obj !== null && typeof obj === 'object') {
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
