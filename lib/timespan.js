var ms = require('ms');

/**
 *
 * - Returns the timespan of *time* from *iat*
 * - if *iat* is undefined it return the timespan of time from current time
 * - if params are invalid, it returns undefined
 *
 * @param {string|number} time -> 1m,1h...
 * @param {number} iat -> in ms
 * @returns {number} in s
 *
 */
module.exports = function (time, iat) {

  if (typeof iat != 'number')
    return

  var timestamp = iat || Math.floor(Date.now() / 1000)

  if (typeof time === 'string') {
    var milliseconds = ms(time)
    if (typeof milliseconds === 'undefined')
      return
    return Math.floor(timestamp + milliseconds / 1000)
  } else if (typeof time === 'number') {
    return timestamp + time
  } else {
    return
  }

};