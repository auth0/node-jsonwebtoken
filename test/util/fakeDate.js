var oldDate = global.Date;

/*
 * fix new Date() to a fixed unix timestamp.
 */
global.Date.fix = function (timestamp) {
  var time = timestamp * 1000;

  if (global.Date.unfake) {
    global.Date.unfake();
  }

  global.Date = function (ts) {
    return new oldDate(ts || time);
  };

  global.Date.prototype = Object.create(oldDate.prototype);
  global.Date.prototype.constructor = global.Date;

  global.Date.prototype.now = function () {
    return time;
  };

  global.Date.now = function () {
    return time;
  };

  global.Date.unfix = function () {
    global.Date = oldDate;
  };

};