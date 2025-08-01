const jwt = require('../index');

describe('issue 147 - signing with a sealed payload', () => {

  it('should put the expiration claim', () => {
    const token = jwt.sign(Object.seal({foo: 123}), '123', { expiresIn: 10 });
    const result = jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + 10, 0.2);
  });

});