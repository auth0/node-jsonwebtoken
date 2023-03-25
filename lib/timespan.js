var ms = require('ms');

/**
 * Returns the number of seconds from the given time string or number.
 * If the time or iat params are invalid, undefined is returned.
 *
 * @param {string|number} time
 * @param {number} iat
 * @returns {number}
 */

module.exports = function (time, iat) {

  if (typeof iat != "number") return;

  var timestamp = iat || Math.floor(Date.now() / 1000);

  if (typeof time === 'string') {
    var milliseconds = ms(time);
    if (typeof milliseconds === 'undefined') {
      return;
    }
    return Math.floor(timestamp + milliseconds / 1000);
  } else if (typeof time === 'number') {
    return timestamp + time;
  } else {
    return;
  }

};