function payloadFromJWS(encodedPayload, encoding = "utf8") {
  try {
    return Buffer.from(encodedPayload, "base64").toString(encoding);
  } catch (_) {
    return;
  }
}

function headerFromJWS(encodedHeader) {
  try {
    return JSON.parse(Buffer.from(encodedHeader, "base64").toString());
  } catch (_) {
    return;
  }
}

const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

function isValidJws(string) {
  return JWS_REGEX.test(string);
}

function jwsDecode(token, opts) {
  opts = opts || {};

  if (!isValidJws(token)) return null;

  let [header, payload, signature] = token.split('.');

  header = headerFromJWS(header);
  if (header === undefined) return null;

  payload = payloadFromJWS(payload);
  if (payload === undefined) return null;

  if (header.typ === "JWT" || opts.json){
    payload = JSON.parse(payload);
  }

  return {
    header,
    payload,
    signature,
  };
}

module.exports = function (jwt, options) {
  options = options || {};
  const decoded = jwsDecode(jwt, options);
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
