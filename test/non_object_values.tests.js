var jwt = require('../index');
var expect = require('chai').expect;

describe('non_object_values values', function() {

  it('should does not work with string', function () {
    expect(function () {
      jwt.sign('hello', '123');
    }).to.throw('Payload must be valid JSON object');
  });

  it('should does not work with number', function () {
    expect(function () {
      jwt.sign(123, '123');
    }).to.throw('Payload must be valid JSON object');
  });

  it('should does not work with function', function () {
    expect(function () {
      jwt.sign(function () { return 0 }, '123')
    }).to.throw('Payload must be valid JSON object')
  })

  it('should does not work with boolean', function () {
    expect(function () {
      jwt.sign(true, '123')
    }).to.throw('Payload must be valid JSON object')
  })

  it('should does not work with undefined', function () {
    expect(function () {
      jwt.sign(undefined, '123')
    }).to.throw('Payload must be valid JSON object')
  })

});
