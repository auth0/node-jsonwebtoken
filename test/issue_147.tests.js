var jwt = require('../index');
var expect = require('chai').expect;

describe('issue 147 - signing with a sealed payload', function() {

  it('should put the expiration claim', function () {
    var token = jwt.sign(Object.seal({foo: 123}), '123', { expiresIn: 10 });
    var result = jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + 10, 0.2);
  });

});