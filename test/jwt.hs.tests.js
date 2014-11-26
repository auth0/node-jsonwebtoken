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

    it('should validate with secret', function(done) {
      jwt.verify(token, secret, function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal('bar', decoded.foo);
        done();
      });
    });

    it('should throw with invalid secret', function(done) {
      jwt.verify(token, 'invalid secret', function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

    it('should throw with secret and token not signed', function(done) {
      var signed = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'none' });
      var unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
      jwt.verify(unsigned, 'secret', function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

    it('should throw when verifying null', function(done) {
      jwt.verify(null, 'secret', function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

    it('should throw when the payload is not json', function(done) {
      var token = jwt.sign('bar', 'secret', { algorithm: 'HS256' });
      jwt.verify(token, 'secret', function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

  });
});
