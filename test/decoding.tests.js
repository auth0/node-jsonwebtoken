var jwt = require('../index');
var expect = require('chai').expect;
var atob = require('atob');

describe('decoding', function() {

  it('should not crash when decoding a null token', function () {
    var decoded = jwt.decode("null");
    expect(decoded).to.equal(null);
  });

});
