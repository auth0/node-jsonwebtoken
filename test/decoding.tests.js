var jwt = require('../index');
var expect = require('chai').expect;

describe('decoding', function() {

  it('should not crash when decoding a null token', function () {
    var decoded = jwt.unsafeDecode("null");
    expect(decoded).to.equal(null);
  });

});
