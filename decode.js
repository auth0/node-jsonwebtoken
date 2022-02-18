const jws = require('jws');

module.exports = function (jwt, options) {
  options = options || {};
  const decoded = jws.decode(jwt, options);
  if (!decoded) { return null; }
  let payload = decoded.payload;

  //try parse the payload
  if(typeof payload === 'string') {
    try {
      const obj = JSON.parse(payload);
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
