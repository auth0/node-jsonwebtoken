var jwt = require('../index');
var jws = require('jws');
var fs = require('fs');
var path = require('path');
var sinon = require('sinon');
var JsonWebTokenError = require('../lib/JsonWebTokenError');

var assert = require('chai').assert;
var expect = require('chai').expect;

describe('verify', function() {
  var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'));
  var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

  it('should first assume JSON claim set', function (done) {
    var header = { alg: 'RS256' };
    var payload = { iat: Math.floor(Date.now() / 1000 ) };

    var signed = jws.sign({
      header: header,
      payload: payload,
      secret: priv,
      encoding: 'utf8'
    });

    jwt.verify(signed, pub, {typ: 'JWT'}, function(err, p) {
      assert.isNull(err);
      assert.deepEqual(p, payload);
      done();
    });
  });

  it('should be able to validate unsigned token', function (done) {
    var header = { alg: 'none' };
    var payload = { iat: Math.floor(Date.now() / 1000 ) };

    var signed = jws.sign({
      header: header,
      payload: payload,
      secret: priv,
      encoding: 'utf8'
    });

    jwt.verify(signed, null, {typ: 'JWT'}, function(err, p) {
      assert.isNull(err);
      assert.deepEqual(p, payload);
      done();
    });
  });

  it('should not mutate options', function (done) {
    var header = { alg: 'none' };

    var payload = { iat: Math.floor(Date.now() / 1000 ) };

    var options = {typ: 'JWT'};

    var signed = jws.sign({
      header: header,
      payload: payload,
      secret: priv,
      encoding: 'utf8'
    });

    jwt.verify(signed, null, options, function(err) {
      assert.isNull(err);
      assert.deepEqual(Object.keys(options).length, 1);
      done();
    });
  });

  describe('secret or token as callback', function () {
    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
    var key = 'key';

    var payload = { foo: 'bar', iat: 1437018582, exp: 1437018592 };
    var options = {algorithms: ['HS256'], ignoreExpiration: true};

    it('without callback', function (done) {
      jwt.verify(token, key, options, function (err, p) {
        assert.isNull(err);
        assert.deepEqual(p, payload);
        done();
      });
    });

    it('simple callback', function (done) {
      var keyFunc = function(header, callback) {
        assert.deepEqual(header, { alg: 'HS256', typ: 'JWT' });

        callback(undefined, key);
      };

      jwt.verify(token, keyFunc, options, function (err, p) {
        assert.isNull(err);
        assert.deepEqual(p, payload);
        done();
      });
    });

    it('should error if called synchronously', function (done) {
      var keyFunc = function(header, callback) {
        callback(undefined, key);
      };

      expect(function () {
        jwt.verify(token, keyFunc, options);
      }).to.throw(JsonWebTokenError, /verify must be called asynchronous if secret or public key is provided as a callback/);

      done();
    });

    it('simple error', function (done) {
      var keyFunc = function(header, callback) {
        callback(new Error('key not found'));
      };

      jwt.verify(token, keyFunc, options, function (err, p) {
        assert.equal(err.name, 'JsonWebTokenError');
        assert.match(err.message, /error in secret or public key callback/);
        assert.isUndefined(p);
        done();
      });
    });

    it('delayed callback', function (done) {
      var keyFunc = function(header, callback) {
        setTimeout(function() {
          callback(undefined, key);
        }, 25);
      };

      jwt.verify(token, keyFunc, options, function (err, p) {
        assert.isNull(err);
        assert.deepEqual(p, payload);
        done();
      });
    });

    it('delayed error', function (done) {
      var keyFunc = function(header, callback) {
        setTimeout(function() {
          callback(new Error('key not found'));
        }, 25);
      };

      jwt.verify(token, keyFunc, options, function (err, p) {
        assert.equal(err.name, 'JsonWebTokenError');
        assert.match(err.message, /error in secret or public key callback/);
        assert.isUndefined(p);
        done();
      });
    });
  });

  describe('expiration', function () {
    // { foo: 'bar', iat: 1437018582, exp: 1437018592 }
    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
    var key = 'key';

    var clock;
    afterEach(function () {
      try { clock.restore(); } catch (e) {}
    });

    it('should error on expired token', function (done) {
      clock = sinon.useFakeTimers(1437018650000); // iat + 58s, exp + 48s
      var options = {algorithms: ['HS256']};

      jwt.verify(token, key, options, function (err, p) {
        assert.equal(err.name, 'TokenExpiredError');
        assert.equal(err.message, 'jwt expired');
        assert.equal(err.expiredAt.constructor.name, 'Date');
        assert.equal(Number(err.expiredAt), 1437018592000);
        assert.isUndefined(p);
        done();
      });
    });

    it('should not error on expired token within clockTolerance interval', function (done) {
      clock = sinon.useFakeTimers(1437018594000); // iat + 12s, exp + 2s
      var options = {algorithms: ['HS256'], clockTolerance: 5 }

      jwt.verify(token, key, options, function (err, p) {
        assert.isNull(err);
        assert.equal(p.foo, 'bar');
        done();
      });
    });

    describe('option: clockTimestamp', function () {
      var clockTimestamp = 1000000000;
      it('should verify unexpired token relative to user-provided clockTimestamp', function (done) {
        var token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp: clockTimestamp}, function (err) {
          assert.isNull(err);
          done();
        });
      });
      it('should error on expired token relative to user-provided clockTimestamp', function (done) {
        var token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp: clockTimestamp + 1}, function (err, p) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'jwt expired');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), (clockTimestamp + 1) * 1000);
          assert.isUndefined(p);
          done();
        });
      });
      it('should verify clockTimestamp is a number', function (done) {
        var token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp: 'notANumber'}, function (err, p) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message,'clockTimestamp must be a number');
          assert.isUndefined(p);
          done();
        });
      });
    });

    describe('option: maxAge and clockTimestamp', function () {
      // { foo: 'bar', iat: 1437018582, exp: 1437018800 } exp = iat + 218s
      var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODgwMH0.AVOsNC7TiT-XVSpCpkwB1240izzCIJ33Lp07gjnXVpA';
      it('cannot be more permissive than expiration', function (done) {
        var clockTimestamp = 1437018900;  // iat + 318s (exp: iat + 218s)
        var options = {algorithms: ['HS256'], clockTimestamp: clockTimestamp, maxAge: '1000y'};

        jwt.verify(token, key, options, function (err, p) {
          // maxAge not exceded, but still expired
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'jwt expired');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018800000);
          assert.isUndefined(p);
          done();
        });
      });
    });
  });
});
