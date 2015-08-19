var jwt = require('../index');
var expect = require('chai').expect;

describe('set headers', function() {

  it('should add the header', function () {
    var token = jwt.sign({foo: 123}, '123', { headers: { foo: 'bar' } });
    var decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.foo).to.equal('bar');
  });

  it('should allow overriding headers', function () {
    var token = jwt.sign({foo: 123}, '123', { headers: { alg: 'HS512' } });
    var decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.alg).to.equal('HS512');
  });

});