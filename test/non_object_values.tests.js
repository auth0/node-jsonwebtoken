var jwt = require('../index');
var expect = require('chai').expect;

describe('non_object_values values', function() {

  it('should work with string', function () {
    var token = jwt.sign('hello', '123');
    var result = jwt.verify(token, '123');
    expect(result).to.equal('hello');
  });

  it('should work with number', function () {
    var token = jwt.sign(123, '123');
    var result = jwt.verify(token, '123');
    expect(result).to.equal('123');
  });

});
