var jwt = require('../index');
var expect = require('chai').expect;
var JsonWebTokenError = require('../lib/JsonWebTokenError');

describe('non_object_values values', function() {

  it('should work with string', function () {
    var token = jwt.sign('hello', '123');
    var result = jwt.verify(token, '123');
    expect(result).to.equal('hello');
  });

  //v6 version will throw in this case:
  it('should throw with expiresIn', function () {
    expect(function () {
      jwt.sign('hello', '123', { expiresIn: '12h' });
    }).to.throw(/invalid expiresIn option for string payload/);
  });

  it('should fail to validate audience when the payload is string', function () {
    var token = jwt.sign('hello', '123');
    expect(function () {
      jwt.verify(token, '123', { audience: 'foo' });
    }).to.throw(JsonWebTokenError);
  });

  it('should work with number', function () {
    var token = jwt.sign(123, '123');
    var result = jwt.verify(token, '123');
    expect(result).to.equal('123');
  });

});
