var jwt = require('../index');
var expect = require('chai').expect;

describe('clockTolerance', function() {

  it('should produce tokens slightly backdated', function () {
    var token = jwt.sign({foo: 123}, 'xxx', { expiresInMinutes: 5 , clockTolerance: 7 });
    var result = jwt.verify(token, 'xxx');
    expect(result.iat).to.be.closeTo(Math.floor(Date.now() / 1000) - 7, 0.5);
  });
  
   it('should not produce tokens slightly backdated if not requested', function () {
    var token = jwt.sign({foo: 123}, 'yyy', { expiresInMinutes: 5 });
    var result = jwt.verify(token, 'yyy');
    expect(result.iat).to.be.closeTo(Math.floor(Date.now() / 1000), 0.5);
  });
  
  it('should throw if clockTolerance is negative', function () {
    expect(function () {
      jwt.sign({foo: 123}, '123', { clockTolerance: -3 });
    }).to.throw(/"clockTolerance" should be a positive number of seconds/);
  });

});
