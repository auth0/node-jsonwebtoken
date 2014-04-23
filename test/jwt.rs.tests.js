var jwt = require('../index');
var fs = require('fs');
var path = require('path');

var expect = require('chai').expect;
var assert = require('chai').assert;

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

    it('should validate with public key', function(done) {
      jwt.verify(token, pub, function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal('bar', decoded.foo);
        done();
      });
    });

    it('should throw with invalid public key', function(done) {
      jwt.verify(token, invalid_pub, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });

    });

  });


  describe('when signing a token with expiration', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', expiresInMinutes: 10 });

    it('should be valid expiration', function(done) {
      jwt.verify(token, pub, function(err, decoded) {
        assert.isNotNull(decoded);
        assert.isNull(err);
        done();
      });
    });

    it('should be invalid', function(done) {
      // expired token
      token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', expiresInMinutes: -10 });

      jwt.verify(token, pub, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

  });

  describe('when signing a token with audience', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', audience: 'urn:foo' });

    it('should check audience', function(done) {
      jwt.verify(token, pub, { audience: 'urn:foo' }, function(err, decoded) {
        assert.isNotNull(decoded);
        assert.isNull(err);
        done();
      });
    });

    it('should throw when invalid audience', function(done) {
      jwt.verify(token, pub, { audience: 'urn:wrong' }, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

  });

  describe('when signing a token without audience', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should check audience', function(done) {
      jwt.verify(token, pub, { audience: 'urn:wrong' }, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });

  });

  describe('when signing a token with issuer', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256', issuer: 'urn:foo' });

    it('should check issuer', function() {
      jwt.verify(token, pub, { issuer: 'urn:foo' }, function(err, decoded) {
        assert.isNotNull(decoded);
        assert.isNull(err);
      });
    });

    it('should throw when invalid issuer', function() {
      jwt.verify(token, pub, { issuer: 'urn:wrong' }, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
      });
    });
  });

  describe('when signing a token without issuer', function() {
    var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    it('should check issuer', function() {
      jwt.verify(token, pub, { issuer: 'urn:foo' }, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
      });
    });
  });

  describe('when verifying a malformed token', function() {
    it('should throw', function(done) {
      jwt.verify('fruit.fruit.fruit', pub, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });
    });
  });


});
