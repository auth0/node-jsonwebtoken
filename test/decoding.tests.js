const jwt = require('../index');
const expect = require('chai').expect;

describe('decoding', function() {

  it('should not crash when decoding a null token', function () {
    const decoded = jwt.decode("null");
    expect(decoded).to.equal(null);
  });

});
