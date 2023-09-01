const jwt = require('../index');

const jws = require('jws');
const expect = require('chai').expect;
const assert = require('chai').assert;
const { generateKeyPairSync } = require('crypto')

describe('HS256', function() {

  describe("when signing using HS256", function () {
    it('should throw if the secret is an asymmetric key', function () {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

      expect(function () {
        jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'HS256' })
      }).to.throw(Error, 'must be a symmetric key')
    })

    it('should throw if the payload is undefined', function () {
      expect(function () {
        jwt.sign(undefined, "secret", { algorithm: 'HS256' })
      }).to.throw(Error, 'payload is required')
    })

    it('should throw if options is not a plain object', function () {
      expect(function () {
        jwt.sign({ foo: 'bar' }, "secret", ['HS256'])
      }).to.throw(Error, 'Expected "options" to be a plain object')
    })
  })

  describe('with a token signed using HS256', function() {
    var secret = 'shhhhhh';

    var token = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });

    it('should be syntactically valid', function() {
      expect(token).to.be.a('string');
      expect(token.split('.')).to.have.length(3);
    });

    it('should be able to validate without options', function(done) {
      var callback = function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal('bar', decoded.foo);
        done();
      };
      callback.issuer = "shouldn't affect";
      jwt.verify(token, secret, callback );
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
      const header = { alg: 'none' };
      const payload = { foo: 'bar' };
      const token = jws.sign({ header, payload, secret: 'secret', encoding: 'utf8' });
      jwt.verify(token, 'secret', function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

    it('should throw with falsy secret and token not signed', function(done) {
      const header = { alg: 'none' };
      const payload = { foo: 'bar' };
      const token = jws.sign({ header, payload, secret: null, encoding: 'utf8' });
      jwt.verify(token, 'secret', function(err, decoded) {
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

    it('should return an error when the token is expired', function(done) {
      var token = jwt.sign({ exp: 1 }, secret, { algorithm: 'HS256' });
      jwt.verify(token, secret, { algorithm: 'HS256' }, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

    it('should NOT return an error when the token is expired with "ignoreExpiration"', function(done) {
      var token = jwt.sign({ exp: 1, foo: 'bar' }, secret, { algorithm: 'HS256' });
      jwt.verify(token, secret, { algorithm: 'HS256', ignoreExpiration: true }, function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal('bar', decoded.foo);
        assert.isNull(err);
        done();
      });
    });

    it('should default to HS256 algorithm when no options are passed', function() {
      var token = jwt.sign({ foo: 'bar' }, secret);
      var verifiedToken = jwt.verify(token, secret);
      assert.ok(verifiedToken.foo);
      assert.equal('bar', verifiedToken.foo);
    });
  });

  describe('should fail verification gracefully on malformed token', function() {
    var secret = 'shhhhhh';
    var token  = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });

    it('should return the "jwt malformed" error with a trailing space', function(done) {
      var malformedToken = token + ' '; // corrupt the token by adding a space
      jwt.verify(malformedToken, secret, { algorithm: 'HS256', ignoreExpiration: true }, function(err) {
        assert.isNotNull(err);
        assert.equal('JsonWebTokenError', err.name);
        assert.equal('jwt malformed', err.message);
        done();
      });
    });

    it('should return the "jwt malformed" error with missing pieces', function(done) {
      var malformedToken = token.split('.').slice(0, 2).join('.'); // corrupt the token by removing a section
      jwt.verify(malformedToken, secret, { algorithm: 'HS256', ignoreExpiration: true }, function(err) {
        assert.isNotNull(err);
        assert.equal('JsonWebTokenError', err.name);
        assert.equal('jwt malformed', err.message);
        done();
      });
    });
  });

});
