var jwt = require('../index');
var expect = require('chai').expect;

describe('expires option', function() {

  it('should work with a number of seconds', function () {
    var token = jwt.sign({foo: 123}, '123', { expiresIn: 10 });
    var result = jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + 10, 0.2);
  });

  it('should work with a string', function () {
    var token = jwt.sign({foo: 123}, '123', { expiresIn: '2d' });
    var result = jwt.verify(token, '123');
    var two_days_in_secs = 2 * 24 * 60 * 60;
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + two_days_in_secs, 0.2);
  });

  it('should work with a string second example', function () {
    var token = jwt.sign({foo: 123}, '123', { expiresIn: '36h' });
    var result = jwt.verify(token, '123');
    var day_and_a_half_in_secs = 1.5 * 24 * 60 * 60;
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + day_and_a_half_in_secs, 0.2);
  });


  it('should throw if expires has a bad string format', function () {
    expect(function () {
      jwt.sign({foo: 123}, '123', { expiresIn: '1 monkey' });
    }).to.throw(/"expiresIn" should be a number of seconds or string representing a timespan/);
  });

  it('should throw if expires is not an string or number', function () {
    expect(function () {
      jwt.sign({foo: 123}, '123', { expiresIn: { crazy : 213 } });
    }).to.throw(/"expiresIn" must be a number/);
  });

  it('should throw an error if expiresIn and exp are provided', function () {
    expect(function () {
      jwt.sign({ foo: 123, exp: 839218392183 }, '123', { expiresIn: '5h' });
    }).to.throw(/Bad "options.expiresIn" option the payload already has an "exp" property./);
  });


  it('should throw on deprecated expiresInSeconds option', function () {
    expect(function () {
      jwt.sign({foo: 123}, '123', { expiresInSeconds: 5 });
    }).to.throw('"expiresInSeconds" is not allowed');
  });


});
