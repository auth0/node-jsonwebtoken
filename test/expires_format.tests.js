var jwt = require('../index');
var expect = require('chai').expect;

describe('expires option', function() {

  it('should throw on deprecated expiresInSeconds option', function () {
    expect(function () {
      jwt.sign({foo: 123}, '123', { expiresInSeconds: 5 });
    }).to.throw('"expiresInSeconds" is not allowed');
  });

});
