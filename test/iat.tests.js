var jwt = require('../index');
var expect = require('chai').expect;

describe('iat', function() {

  it('should work with a numeric iat not changing the expiration date', function () {
    var token = jwt.sign({foo: 123, iat: Math.floor(Date.now() / 1000) - 30}, '123', { expiresIn: 10 });
    var result = jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + 10, 0.2);
  });


  it('should throw if iat is not a number', function () {
    expect(function () {
      jwt.sign({foo: 123, iat:'hello'}, '123');
    }).to.throw(/"iat" must be a number/);
  });


});
