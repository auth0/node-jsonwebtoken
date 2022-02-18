const jwt = require('../index');
const expect = require('chai').expect;

describe('set header', function() {

  it('should add the header', function () {
    const token = jwt.sign({foo: 123}, '123', { header: { foo: 'bar' } });
    const decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.foo).to.equal('bar');
  });

  it('should allow overriding header', function () {
    const token = jwt.sign({foo: 123}, '123', { header: { alg: 'HS512' } });
    const decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.alg).to.equal('HS512');
  });

});
