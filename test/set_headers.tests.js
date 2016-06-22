var jwt = require('../index');
var expect = require('chai').expect;

describe('set header', function() {

  it('should add the header', function () {
    var token = jwt.sign({foo: 123}, '123', { header: { foo: 'bar' } });
    var decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.foo).to.equal('bar');
  });

  it('should allow overriding header', function () {
    var token = jwt.sign({foo: 123}, '123', { header: { alg: 'HS512' } });
    var decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.alg).to.equal('HS512');
  });

});
