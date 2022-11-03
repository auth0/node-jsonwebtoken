const jwt = require('../index');
const expect = require('chai').expect;

describe('noTimestamp', function() {

  it('should work with string', function () {
    const token = jwt.sign({foo: 123}, '123', { expiresIn: '5m' , noTimestamp: true });
    const result = jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + (5*60), 0.5);
  });

});
