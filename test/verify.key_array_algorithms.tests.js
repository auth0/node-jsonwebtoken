var jwt = require('../index');
var jws = require('jws');
var fs = require('fs');
var path = require('path');

var assert = require('chai').assert;

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

describe('verify with secretOrPublicKey array', function() {
  var payload = { foo: 'bar', iat: 1437018582, exp: 1437018592 };

  var ecdsa_priv_key = loadKey('ecdsa-private.pem');
  var ecdsa_pub_key = loadKey('ecdsa-public.pem');
  var rsa_priv_key = loadKey('rsa-private.pem');
  var rsa_pub_key = loadKey('rsa-public-key.pem');
  var hmac_secret = 'key';

  var ecdsa_pub_key_invalid = loadKey('ecdsa-public-invalid.pem');
  var rsa_pub_key_invalid = loadKey('rsa-public-invalid.pem');

  var ecdsa_signed = jws.sign({
    header: { alg: 'ES256' },
    payload: payload,
    secret: ecdsa_priv_key,
    encoding: 'utf8'
  });
  var rsa_signed = jws.sign({
    header: { alg: 'RS256' },
    payload: payload,
    secret: rsa_priv_key,
    encoding: 'utf8'
  });
  var hmac_signed = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';

  var keys;
  var options;

  beforeEach(function () {
    keys = ['badhskey', rsa_pub_key, ecdsa_pub_key, hmac_secret];
    options = {ignoreExpiration: true};
  });

  describe('algorithms', function() {
    it('should work with ecdsa', function(done) {
      jwt.verify(ecdsa_signed, keys, options, function (err, p) {
        assert.isNull(err);
        assert.deepEqual(p, payload);
        done();
      });
    });

    it('should work with rsa', function(done) {
      jwt.verify(rsa_signed, keys, options, function (err, p) {
        assert.isNull(err);
        assert.deepEqual(p, payload);
        done();
      });
    });

    it('should work with hmac', function(done) {
      jwt.verify(hmac_signed, keys, options, function (err, p) {
        assert.isNull(err);
        assert.deepEqual(p, payload);
        done();
      });
    });

    describe('with invalid keys', function() {
      beforeEach(function () {
        keys = [ecdsa_pub_key_invalid, rsa_pub_key_invalid, 'badhskey'];
      });

      it('should fail with ecdsa', function(done) {
        jwt.verify(ecdsa_signed, keys, options, function (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'invalid signature');
          done();
        });
      });

      it('should fail with rsa', function(done) {
        jwt.verify(rsa_signed, keys, options, function (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'invalid signature');
          done();
        });
      });

      it('should fail with hmac', function(done) {
        jwt.verify(hmac_signed, keys, options, function (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'invalid signature');
          done();
        });
      });
    });

    it('should error if token algorithm not included in options.algorithms', function(done) {
      options = {algorithms: ['ES256'], ignoreExpiration: true}

      jwt.verify(hmac_signed, keys, options, function (err) {
        assert.equal(err.name, 'JsonWebTokenError');
        assert.equal(err.message, 'invalid algorithm for every given key or algorithm option');
        done();
      });
    });

    describe('should error if token algorithm not supported by any key defaults', function() {
      it('hmac token with rsa and ecdsa keys', function(done) {
        var keys = [rsa_pub_key, ecdsa_pub_key]

        jwt.verify(hmac_signed, keys, options, function (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'invalid algorithm for every given key or algorithm option');
          done();
        });
      });

      it('ecdsa token with rsa and hmac keys', function(done) {
        var keys = [rsa_pub_key, hmac_secret]

        jwt.verify(ecdsa_signed, keys, options, function (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'invalid algorithm for every given key or algorithm option');
          done();
        });
      });

      it('rsa token with hmac key', function(done) {
        var keys = [hmac_secret]

        jwt.verify(rsa_signed, keys, options, function (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'invalid algorithm for every given key or algorithm option');
          done();
        });
      });
    });
  });
});
