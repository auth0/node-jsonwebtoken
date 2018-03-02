var JsonWebTokenError = require('./JsonWebTokenError');

var NotBeforeError = function (message, date, payload) {
  JsonWebTokenError.call(this, message);
  this.name = 'NotBeforeError';
  this.date = date;
  this.payload = payload;
};

NotBeforeError.prototype = Object.create(JsonWebTokenError.prototype);

NotBeforeError.prototype.constructor = NotBeforeError;

module.exports = NotBeforeError;