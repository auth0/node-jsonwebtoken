var jwt = require('../index');

var expect = require('chai').expect;
var assert = require('chai').assert;

describe('HS256', function() {

  describe('when signing a token', function() {
    var secret = 'shhhhhh';

    var token = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });

    it('should be syntactically valid', function() {
      expect(token).to.be.a('string');
      expect(token.split('.')).to.have.length(3);
    });

    it('should validate with secret', function() {
      var decoded = jwt.verify(token, secret);
      assert.ok(decoded.foo);
      assert.equal('bar', decoded.foo);
    });

    it('should throw with invalid secret', function() {
      var verify = jwt.verify.bind(null, token, 'invalid secret');
      expect(verify).to.throw('invalid signature');
    });

    it('should throw with secret and token not signed', function() {
      var signed = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'none' });
      var unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
      var verify = jwt.verify.bind(null, unsigned, 'secret');
      expect(verify).to.throw('jwt signature is required');
    });

    it('should throw when verifying null', function() {
      var verify = jwt.verify.bind(null, null, 'secret');
      expect(verify).to.throw('jwt must be provided');
    });

    it('should return an error when the token is expired', function() {
      var token = jwt.sign({ exp: 1 }, secret, { algorithm: 'HS256' });
      var verify = jwt.verify.bind(null, token, secret, { algorithm: 'HS256' });
      expect(verify).to.throw('jwt expired');
    });

    it('should NOT return an error when the token is expired with "ignoreExpiration"', function() {
      var token = jwt.sign({ exp: 1, foo: 'bar' }, secret, { algorithm: 'HS256' });
      var decoded = jwt.verify(token, secret, { algorithm: 'HS256', ignoreExpiration: true });
      assert.ok(decoded.foo);
      assert.equal('bar', decoded.foo);
    });

  });

});
