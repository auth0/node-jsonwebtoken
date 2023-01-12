module.exports = function isNumber(value) {
  return (
    typeof value == 'number' ||
    (!!value && typeof value == 'object' && Object.prototype.toString.call(value) == '[object Number]')
  );
}
