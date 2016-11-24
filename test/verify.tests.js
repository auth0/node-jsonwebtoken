var jwt = require('../index');
var jws = require('jws');
var fs = require('fs');
var path = require('path');
var sinon = require('sinon');

var assert = require('chai').assert;

describe('verify', function() {
  var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'));
  var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

  it('should first assume JSON claim set', function () {
    var header = { alg: 'RS256' };
    var payload = { iat: Math.floor(Date.now() / 1000 ) };
    var signed = jws.sign({
      header: header,
        payload: payload,
        secret: priv,
        encoding: 'utf8'
    });
    var p = jwt.verify(signed, pub, {typ: 'JWT'});

    assert.deepEqual(p, payload);
  });

  it('should be able to validate unsigned token', function () {
    var header = { alg: 'none' };
    var payload = { iat: Math.floor(Date.now() / 1000 ) };
    var signed = jws.sign({
      header: header,
      payload: payload,
      secret: priv,
      encoding: 'utf8'
    });
    var p = jwt.verify(signed, null, {typ: 'JWT'});

    assert.deepEqual(p, payload);
  });

  it('should not mutate options', function () {
    var header = { alg: 'none' };
    var payload = { iat: Math.floor(Date.now() / 1000 ) };
    var options = {typ: 'JWT'};
    var signed = jws.sign({
      header: header,
      payload: payload,
      secret: priv,
      encoding: 'utf8'
    });

    jwt.verify(signed, null, options);
    assert.deepEqual(Object.keys(options).length, 1);
  });

  describe('expiration', function () {
    // { foo: 'bar', iat: 1437018582, exp: 1437018583 }
    var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU4M30.NmMv7sXjM1dW0eALNXud8LoXknZ0mH14GtnFclwJv0s';
    var key = 'key';
    var clock;

    afterEach(function () {
      try { clock.restore(); } catch (e) {}
    });

    it('should error on expired token', function () {
      clock = sinon.useFakeTimers(1437018650000);
      var options = {algorithms: ['HS256']};
      var p;

      try {
        p = jwt.verify(token, key, options);
      }
      catch (err) {
        assert.equal(err.name, 'TokenExpiredError');
        assert.equal(err.message, 'jwt expired');
        assert.equal(err.expiredAt.constructor.name, 'Date');
        assert.equal(Number(err.expiredAt), 1437018583000);
        assert.isUndefined(p);
      }
    });

    it('should not error on expired token within clockTolerance interval', function () {
      clock = sinon.useFakeTimers(1437018584000);
      var options = {algorithms: ['HS256'], clockTolerance: 100}
      var p = jwt.verify(token, key, options);

      assert.equal(p.foo, 'bar');
    });

    it('should not error if within maxAge timespan', function () {
      clock = sinon.useFakeTimers(1437018582500);
      var options = {algorithms: ['HS256'], maxAge: '600ms'};
      var p = jwt.verify(token, key, options);

      assert.equal(p.foo, 'bar');
    });

    describe('option: maxAge', function () {
      it('should error for claims issued before a certain timespan', function () {
        clock = sinon.useFakeTimers(1437018582500);
        var options = {algorithms: ['HS256'], maxAge: '321ms'};
        var p;

        try {
          p = jwt.verify(token, key, options);
        }
        catch (err) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'maxAge exceeded');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018582321);
          assert.isUndefined(p);
        }
      });

      it('should not error for claims issued before a certain timespan but still inside clockTolerance timespan', function () {
        clock = sinon.useFakeTimers(1437018582500);
        var options = {algorithms: ['HS256'], maxAge: '321ms', clockTolerance: 100};
        var p = jwt.verify(token, key, options);

        assert.equal(p.foo, 'bar');
      });

      it('should not error if within maxAge timespan', function () {
        clock = sinon.useFakeTimers(1437018582500);
        var options = {algorithms: ['HS256'], maxAge: '600ms'};
        var p = jwt.verify(token, key, options);

        assert.equal(p.foo, 'bar');
      });

      it('can be more restrictive than expiration', function () {
        clock = sinon.useFakeTimers(1437018582900);
        var options = {algorithms: ['HS256'], maxAge: '800ms'};
        var p;

        try {
          p = jwt.verify(token, key, options);
        }
        catch (err) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'maxAge exceeded');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018582800);
          assert.isUndefined(p);
        }
      });

      it('cannot be more permissive than expiration', function () {
        clock = sinon.useFakeTimers(1437018583100);
        var options = {algorithms: ['HS256'], maxAge: '1200ms'};
        var p;

        try {
          p = jwt.verify(token, key, options);
        }
        catch (err) {
          // maxAge not exceded, but still expired
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'jwt expired');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018583000);
          assert.isUndefined(p);
        }
      });

      it('should error if maxAge is specified but there is no iat claim', function () {
        clock = sinon.useFakeTimers(1437018582900);
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.0MBPd4Bru9-fK_HY3xmuDAc6N_embknmNuhdb9bKL_U';
        var options = {algorithms: ['HS256'], maxAge: '1s'};
        var p;

        try {
          p = jwt.verify(token, key, options);
        }
        catch (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'iat required when maxAge is specified');
          assert.isUndefined(p);
        }
      });
    });
  });
});
