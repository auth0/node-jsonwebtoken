const jwt = require('../index');
const crypto = require("crypto");

const {assert, expect} = require('chai');

describe('HS256', function() {

  describe('when signing a token', function() {
    const secret = 'shhhhhh';
    const {
      publicKey: pubRsaKey,
      privateKey: privRsaKey
    } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

    const token = jwt.sign({foo: 'bar'}, secret, {algorithm: 'HS256'});

    it('should be syntactically valid', function() {
      expect(token).to.be.a('string');
      expect(token.split('.')).to.have.length(3);
    });

    it('should be able to validate without options', function(done) {
      const callback = function (err, decoded) {
        assert.ok(decoded.foo);
        assert.equal(decoded.foo, 'bar');
        done();
      };
      callback.issuer = "shouldn't affect";
      jwt.verify(token, secret, callback );
    });

    it('should validate with secret', function(done) {
      jwt.verify(token, secret, function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal(decoded.foo, 'bar');
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
      const signed = jwt.sign({foo: 'bar'}, secret, {algorithm: 'none'});
      const unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
      jwt.verify(unsigned, 'secret', function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

    it('should work with falsy secret and token not signed', function(done) {
      const signed = jwt.sign({foo: 'bar'}, null, {algorithm: 'none'});
      const unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
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

    it('should return an error when the token is expired', function(done) {
      const token = jwt.sign({exp: 1}, secret, {algorithm: 'HS256'});
      jwt.verify(token, secret, { algorithm: 'HS256' }, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

    it('should NOT return an error when the token is expired with "ignoreExpiration"', function(done) {
      const token = jwt.sign({exp: 1, foo: 'bar'}, secret, {algorithm: 'HS256'});
      jwt.verify(token, secret, { algorithm: 'HS256', ignoreExpiration: true }, function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal(decoded.foo, 'bar');
        assert.isNull(err);
        done();
      });
    });

    it('should default to HS256 algorithm when no options are passed', function() {
      const token = jwt.sign({foo: 'bar'}, secret);
      const verifiedToken = jwt.verify(token, secret);
      assert.ok(verifiedToken.foo);
      assert.equal(verifiedToken.foo, 'bar');
    });

    describe('when the algorithm is HS256', function () {
      it('should throw when a PublicKeyObject is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, pubRsaKey, {algorithm: 'HS256'})).to.throw(Error, 'must be of type secret');
      })

      it('should throw when a PrivateKeyObject is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, privRsaKey, {algorithm: 'HS256'})).to.throw(Error, 'must be of type secret');
      })

      it('should throw when a secret is not valid input for crypto.createSecretKey is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, 5, {algorithm: 'HS256'})).to.throw(Error, 'valid input for secret for crypto.createSecretKey');
      })
    })

    describe('when the algorithm is HS384', function () {
      it('should throw when a PublicKeyObject is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, pubRsaKey, {algorithm: 'HS384'})).to.throw(Error, 'must be of type secret');
      })

      it('should throw when a PrivateKeyObject is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, privRsaKey, {algorithm: 'HS384'})).to.throw(Error, 'must be of type secret');
      })

      it('should throw when a secret is not valid input for crypto.createSecretKey is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, 5, {algorithm: 'HS384'})).to.throw(Error, 'valid input for secret for crypto.createSecretKey');
      })
    })

    describe('when the algorithm is HS512', function () {
      it('should throw when a PublicKeyObject is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, pubRsaKey, {algorithm: 'HS512'})).to.throw(Error, 'must be of type secret');
      })

      it('should throw when a PrivateKeyObject is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, privRsaKey, {algorithm: 'HS512'})).to.throw(Error, 'must be of type secret');
      })

      it('should throw when a secret is not valid input for crypto.createSecretKey is used as secret', function () {
        expect(() => jwt.sign({ foo: 'bar' }, 5, {algorithm: 'HS512'})).to.throw(Error, 'valid input for secret for crypto.createSecretKey');
      })
    })
  });

  describe('should fail verification gracefully with trailing space in the jwt', function() {
    const secret = 'shhhhhh';
    const token = jwt.sign({foo: 'bar'}, secret, {algorithm: 'HS256'});

    it('should return the "invalid token" error', function(done) {
      const malformedToken = token + ' '; // corrupt the token by adding a space
      jwt.verify(malformedToken, secret, { algorithm: 'HS256', ignoreExpiration: true }, function(err) {
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.equal(err.message, 'invalid token');
        done();
      });
    });
  });

  describe('when verifying a token', function () {
    it('should throw when a secret is not valid input for crypto.createSecretKey is used as secret', function () {
      const secret = 'shhhhhh';
      const token = jwt.sign({foo: 'bar'}, secret, {algorithm: 'HS256'});
      expect(() => jwt.verify(token, 5, {algorithms: 'HS256'})).to.throw(Error, 'valid input for secret for crypto.createSecretKey');
    })
  })

});
