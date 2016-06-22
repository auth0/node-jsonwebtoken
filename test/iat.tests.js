var jwt = require('../index');
var expect = require('chai').expect;

describe('iat', function () {

  it('should work with a exp calculated based on numeric iat', function () {
    var dateNow = Math.floor(Date.now() / 1000);
    var iat = dateNow - 30;
    var expiresIn = 50;
    var token = jwt.sign({foo: 123, iat: iat}, '123', {expiresIn: expiresIn});
    var result = jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(iat + expiresIn, 0.2);
  });


  it('should throw if iat is not a number', function () {
    expect(function () {
      jwt.sign({foo: 123, iat: 'hello'}, '123');
    }).to.throw(/"iat" must be a number/);
  });

});