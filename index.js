module.exports = {
  decode: require('./decode'),
  verify: require('./verify'),
  sign: require('./sign'),
  JsonWebTokenError: require('./lib/JsonWebTokenError'),
  NotBeforeError: require('./lib/NotBeforeError'),
  TokenExpiredError: require('./lib/TokenExpiredError'),
};

JWT.refresh = function (token, secretOrPrivateKey, options) {

  var decodedToken, limitDate, payload;
  decodedToken = undefined;

  try {
    decodedToken = jws.decode(token);
  } catch (err) {
    return new jwt.JsonWebTokenError("invalid token");
  }

  payload = decodedToken.payload;

  if (!decodedToken)
    return new jwt.JsonWebTokenError("invalid token");

  if (typeof options === "undefined")
    options = {};

  if (typeof payload.exp !== "undefined") {

    if (typeof options.toleranceDays === "undefined")
      options.toleranceDays = 7;

    limitDate = new Date(payload.exp * 1000);
    limitDate.setDate(limitDate.getDate() + options.toleranceDays);

    if (Math.floor(Date.now() / 1000) >= Math.floor(limitDate / 1000))
      return new jwt.TokenExpiredError('jwt expired', new Date(payload.exp * 1000));
    else
      return jwt.sign(payload, process.env.TOKEN_SECRET || "oursecret", options);

  } else
    return token;
};
