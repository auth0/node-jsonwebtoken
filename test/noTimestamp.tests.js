const jwt = require('../index');

describe('noTimestamp', () => {

  it('should work with string', () => {
    const token = jwt.sign({foo: 123}, '123', { expiresIn: '5m' , noTimestamp: true });
    const result = jwt.verify(token, '123', { algorithms: ['HS256'] });
    expect(result.exp).toBeCloseTo(Math.floor(Date.now() / 1000) + (5*60), 0);
  });

});
