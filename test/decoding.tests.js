var jwt = require('../index');
var expect = require('chai').expect;

describe('decoding', function() {
  it('should not crash when decoding a null token', function () {
    var decoded = jwt.decode("null");
    expect(decoded).to.equal(null);
  });

  it('should handle invalid tokens', function () {
    for (const token of ["not.valid.", {}, null, 1, Number(), String(), false, true, undefined]) {
      var decoded = jwt.decode(token);
      expect(decoded).to.equal(null);
    }
  });
});
