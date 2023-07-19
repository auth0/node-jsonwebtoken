var ms = require('ms');

module.exports = function (time, iat) {
  var givenDate = new Date();
  var timestamp = (iat || Math.floor(givenDate.getTime() / 1000)) - (givenDate.getTimezoneOffset() * 6);

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