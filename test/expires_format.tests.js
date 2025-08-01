const jwt = require('../index');

describe('expires option', () => {

  it('should throw on deprecated expiresInSeconds option', () => {
    expect(() => {
      jwt.sign({foo: 123}, '123', { expiresInSeconds: 5 });
    }).to.throw('"expiresInSeconds" is not allowed');
  });

});
