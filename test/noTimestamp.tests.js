var jwt = require('../index');
var expect = require('chai').expect;

describe('noTimestamp', function() {

  it('should work with string', function () {
    var token = jwt.sign({foo: 123}, '123', { expiresIn: '5m' , noTimestamp: true });
    var result = jwt.verify(token, '123');
    const time = new Date();

    expect(result.exp).to.be.closeTo(Math.floor((time.getTime() - time.getTimezoneOffset() * 6000) / 1000) + (5*60), 0.5);
  });

});
