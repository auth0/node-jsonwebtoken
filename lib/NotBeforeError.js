var JsonWebTokenError = require('./JsonWebTokenError');

/**
 * Thrown if current time is before the nbf claim.
 * @param {string} message Error message
 * @param {Date} date Date
 * @constructor
 */
var NotBeforeError = function (message, date) {
  JsonWebTokenError.call(this, message);
  this.name = 'NotBeforeError';
  this.date = date;
};

NotBeforeError.prototype = Object.create(JsonWebTokenError.prototype);

NotBeforeError.prototype.constructor = NotBeforeError;

module.exports = NotBeforeError;