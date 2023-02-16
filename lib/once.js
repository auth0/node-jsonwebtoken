module.exports = function once(func) {
  function _f() {
    if (!_f.isCalled) {
      _f.isCalled = true;
      _f.res = func.apply(this, arguments);
    }
    return _f.res;
  }

  _f.prototype = func.prototype;
  _f.isCalled = false;

  return _f;
}