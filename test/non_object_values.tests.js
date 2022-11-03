const jwt = require('../index');
const expect = require('chai').expect;

describe('non_object_values values', function() {

  it('should work with string', function () {
    const token = jwt.sign('hello', '123');
    const result = jwt.verify(token, '123');
    expect(result).to.equal('hello');
  });

  it('should work with number', function () {
    const token = jwt.sign(123, '123');
    const result = jwt.verify(token, '123');
    expect(result).to.equal('123');
  });

});
