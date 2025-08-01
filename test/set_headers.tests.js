const jwt = require('../index');

describe('set header', () => {

  it('should add the header', () => {
    const token = jwt.sign({foo: 123}, '123', { header: { foo: 'bar' } });
    const decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.foo).toBe('bar');
  });

  it('should allow overriding header', () => {
    const token = jwt.sign({foo: 123}, '123', { header: { alg: 'HS512' } });
    const decoded = jwt.decode(token, {complete: true});
    expect(decoded.header.alg).toBe('HS512');
  });

});
