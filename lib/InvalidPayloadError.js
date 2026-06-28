const JsonWebTokenError = require("./JsonWebTokenError");

const InvalidPayloadError = function (message) {
  JsonWebTokenError.call(this, message);
  this.name = "InvalidPayloadError";
};

InvalidPayloadError.prototype = Object.create(JsonWebTokenError.prototype);
InvalidPayloadError.prototype.constructor = InvalidPayloadError;

module.exports = InvalidPayloadError;
