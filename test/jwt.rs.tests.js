var jwt = require('../index');
var fs = require('fs');
var path = require('path');

var expect = require('chai').expect;
var assert = require('chai').assert;
var ms = require('ms');

describe('RS256', function() {
  var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'));
  var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));
  var invalid_pub = fs.readFileSync(path.join(__dirname, 'invalid_pub.pem'));

  describe('when signing a token', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should be syntactically valid', function() {
      expect(token).to.be.a('string');
      expect(token.split('.')).to.have.length(3);
    });

    context('synchronous', function() {
      it('should validate with public key', function() {
        var decoded = jwt.verify(token, pub);
        assert.ok(decoded.foo);
        assert.equal('bar', decoded.foo);
      });

      it('should throw with invalid public key', function() {
        var jwtVerify = jwt.verify.bind(null, token, invalid_pub)
        assert.throw(jwtVerify, 'invalid signature');
      });
    });

  });

  describe('when signing a token with expiration', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', expiresIn: '10m' });

    it('should be valid expiration', function() {
      var decoded = jwt.verify(token, pub);
      assert.isNotNull(decoded);
    });

    it('should be invalid', function() {
      // expired token
      token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', expiresIn: -1 * ms('10m') });
      try {
        var decoded = jwt.verify(token, pub);
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'TokenExpiredError');
        assert.instanceOf(err.expiredAt, Date);
        assert.instanceOf(err, jwt.TokenExpiredError);
      }
    });

    it('should NOT be invalid', function() {
      // expired token
      token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', expiresIn: -1 * ms('10m') });

      var decoded = jwt.verify(token, pub, { ignoreExpiration: true });
      assert.ok(decoded.foo);
      assert.equal('bar', decoded.foo);
    });
  });

  describe('when signing a token with not before', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', notBefore: -10 * 3600 });

    it('should be valid expiration', function() {
      var decoded = jwt.verify(token, pub);
      assert.isNotNull(decoded);
    });

    it('should be invalid', function() {
      // not active token
      token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', notBefore: '10m' });

      try {
        var decoded = jwt.verify(token, pub);
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'NotBeforeError');
        assert.instanceOf(err.date, Date);
        assert.instanceOf(err, jwt.NotBeforeError);
      }
    });


    it('should valid when date are equals', function() {
      Date.fix(1451908031);

      token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', notBefore: 0 });

      var decoded = jwt.verify(token, pub);
      assert.isNotNull(decoded);
      Date.unfix();
    });

    it('should NOT be invalid', function() {
      // not active token
      token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', notBefore: '10m' });

      var decoded = jwt.verify(token, pub, { ignoreNotBefore: true });
      assert.ok(decoded.foo);
      assert.equal('bar', decoded.foo);
    });
  });

  describe('when signing a token with audience', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', audience: 'urn:foo' });

    it('should check audience', function() {
      var decoded = jwt.verify(token, pub, { audience: 'urn:foo' });
      assert.isNotNull(decoded);
    });

    it('should check audience in array', function() {
      var decoded = jwt.verify(token, pub, { audience: ['urn:foo', 'urn:other'] });
      assert.isNotNull(decoded);
    });

    it('should throw when invalid audience', function() {
      try {
        var decoded = jwt.verify(token, pub, { audience: 'urn:wrong' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });

    it('should throw when invalid audience in array', function() {
      try {
        var decoded = jwt.verify(token, pub, { audience: ['urn:wrong', 'urn:morewrong'] });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });
  });

  describe('when signing a token with array audience', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', audience: [ 'urn:foo', 'urn:bar' ] });

    it('should check audience', function() {
      var decoded = jwt.verify(token, pub, { audience: 'urn:foo' });
      assert.isNotNull(decoded);
    });

    it('should check other audience', function() {
      var decoded = jwt.verify(token, pub, { audience: 'urn:bar' });
      assert.isNotNull(decoded);
    });

    it('should check audience in array', function() {
      var decoded = jwt.verify(token, pub, { audience: ['urn:foo', 'urn:other'] });
      assert.isNotNull(decoded);
    });

    it('should throw when invalid audience', function() {
      try {
        var decoded = jwt.verify(token, pub, { audience: 'urn:wrong' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });

    it('should throw when invalid audience in array', function() {
      try {
        var decoded = jwt.verify(token, pub, { audience: ['urn:wrong', 'urn:morewrong'] });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });

  });

  describe('when signing a token without audience', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should check audience', function() {
      try {
        var decoded = jwt.verify(token, pub, { audience: 'urn:wrong' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });

    it('should check audience in array', function() {
      try {
        var decoded = jwt.verify(token, pub, { audience: ['urn:wrong', 'urn:morewrong'] });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });

  });

  describe('when signing a token with issuer', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', issuer: 'urn:foo' });

    it('should check issuer', function() {
      var decoded = jwt.verify(token, pub, { issuer: 'urn:foo' });
      assert.isNotNull(decoded);
    });

    it('should check the issuer when providing a list of valid issuers', function() {
      var decoded = jwt.verify(token, pub, { issuer: [ 'urn:foo', 'urn:bar' ] });
      assert.isNotNull(decoded);
    });

    it('should throw when invalid issuer', function() {
      try {
        var decoded = jwt.verify(token, pub, { issuer: 'urn:wrong' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });
  });

  describe('when signing a token without issuer', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should check issuer', function() {
      try {
        var decoded = jwt.verify(token, pub, { issuer: 'urn:foo' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });
  });

  describe('when signing a token with subject', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', subject: 'subject' });

    it('should check subject', function() {
      var decoded = jwt.verify(token, pub, { subject: 'subject' });
      assert.isNotNull(decoded);
    });

    it('should throw when invalid subject', function() {
      try {
        var decoded = jwt.verify(token, pub, { subject: 'wrongSubject' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });
  });

  describe('when signing a token without subject', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should check subject', function() {
      try {
        var decoded = jwt.verify(token, pub, { subject: 'subject' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });
  });

  describe('when signing a token with jwt id', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', jwtid: 'jwtid' });

    it('should check jwt id', function() {
      var decoded = jwt.verify(token, pub, { jwtid: 'jwtid' });
      assert.isNotNull(decoded);
    });

    it('should throw when invalid jwt id', function() {
      try {
        var decoded = jwt.verify(token, pub, { jwtid: 'wrongJwtid' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });
  });

  describe('when signing a token without jwt id', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should check jwt id', function() {
      try {
        var decoded = jwt.verify(token, pub, { jwtid: 'jwtid' });
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.instanceOf(err, jwt.JsonWebTokenError);
      }
    });
  });

  describe('when verifying a malformed token', function() {
    it('should throw', function() {
      try {
        var decoded = jwt.verify('fruit.fruit.fruit', pub);
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
      }
    });
  });

  describe('when decoding a jwt token with additional parts', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should throw', function() {
      try {
        var decoded = jwt.verify(token + '.foo', pub);
      } catch (err) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
      }
    });
  });

  describe('when decoding a invalid jwt token', function() {
    it('should return null', function() {
      var payload = jwt.decode('whatever.token');
      assert.isNull(payload);
    });
  });

  describe('when decoding a valid jwt token', function() {
    it('should return the payload', function() {
      var obj     = { foo: 'bar' };
      var token   = jwt.sign(obj, priv, { algorithm: 'RS256' });
      var payload = jwt.decode(token);
      assert.equal(payload.foo, obj.foo);
    });
    it('should return the header and payload and signature if complete option is set', function() {
      var obj     = { foo: 'bar' };
      var token   = jwt.sign(obj, priv, { algorithm: 'RS256' });
      var decoded = jwt.decode(token, { complete: true });
      assert.equal(decoded.payload.foo, obj.foo);
      assert.deepEqual(decoded.header, { typ: 'JWT', alg: 'RS256' });
      assert.ok(typeof decoded.signature == 'string');
    });
  });
});
