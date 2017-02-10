var jwt = require('../index');
var jws = require('jws');
var fs = require('fs');
var path = require('path');
var sinon = require('sinon');

var assert = require('chai').assert;

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

  describe('expiration', function () {
    // { foo: 'bar', iat: 1437018582, exp: 1437018583 }
    var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU4M30.NmMv7sXjM1dW0eALNXud8LoXknZ0mH14GtnFclwJv0s';
    var key = 'key';

    var clock;
    afterEach(function () {
      try { clock.restore(); } catch (e) {}
    });

    it('should error on expired token', function (done) {
      clock = sinon.useFakeTimers(1437018650000);
      var options = {algorithms: ['HS256']};

      jwt.verify(token, key, options, function (err, p) {
        assert.equal(err.name, 'TokenExpiredError');
        assert.equal(err.message, 'jwt expired');
        assert.equal(err.expiredAt.constructor.name, 'Date');
        assert.equal(Number(err.expiredAt), 1437018583000);
        assert.isUndefined(p);
        done();
      });
    });

    it('should not error on expired token within clockTolerance interval', function (done) {
      clock = sinon.useFakeTimers(1437018584000);
      var options = {algorithms: ['HS256'], clockTolerance: 100}

      jwt.verify(token, key, options, function (err, p) {
        assert.isNull(err);
        assert.equal(p.foo, 'bar');
        done();
      });
    });

    it('should not error if within maxAge timespan', function (done) {
      clock = sinon.useFakeTimers(1437018582500);
      var options = {algorithms: ['HS256'], maxAge: '600ms'};

      jwt.verify(token, key, options, function (err, p) {
        assert.isNull(err);
        assert.equal(p.foo, 'bar');
        done();
      });
    });

    describe('option: maxAge', function () {
      it('should error for claims issued before a certain timespan', function (done) {
        clock = sinon.useFakeTimers(1437018582500);
        var options = {algorithms: ['HS256'], maxAge: '321ms'};

        jwt.verify(token, key, options, function (err, p) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'maxAge exceeded');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018582321);
          assert.isUndefined(p);
          done();
        });
      });

      it('should not error for claims issued before a certain timespan but still inside clockTolerance timespan', function (done) {
        clock = sinon.useFakeTimers(1437018582500);
        var options = {algorithms: ['HS256'], maxAge: '321ms', clockTolerance: 100};

        jwt.verify(token, key, options, function (err, p) {
          assert.isNull(err);
          assert.equal(p.foo, 'bar');
          done();
        });
      });

      it('should not error if within maxAge timespan', function (done) {
        clock = sinon.useFakeTimers(1437018582500);
        var options = {algorithms: ['HS256'], maxAge: '600ms'};

        jwt.verify(token, key, options, function (err, p) {
          assert.isNull(err);
          assert.equal(p.foo, 'bar');
          done();
        });
      });
      it('can be more restrictive than expiration', function (done) {
        clock = sinon.useFakeTimers(1437018582900);
        var options = {algorithms: ['HS256'], maxAge: '800ms'};

        jwt.verify(token, key, options, function (err, p) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'maxAge exceeded');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018582800);
          assert.isUndefined(p);
          done();
        });
      });
      it('cannot be more permissive than expiration', function (done) {
        clock = sinon.useFakeTimers(1437018583100);
        var options = {algorithms: ['HS256'], maxAge: '1200ms'};

        jwt.verify(token, key, options, function (err, p) {
          // maxAge not exceded, but still expired
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'jwt expired');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018583000);
          assert.isUndefined(p);
          done();
        });
      });
      it('should error if maxAge is specified but there is no iat claim', function (done) {
        clock = sinon.useFakeTimers(1437018582900);
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.0MBPd4Bru9-fK_HY3xmuDAc6N_embknmNuhdb9bKL_U';
        var options = {algorithms: ['HS256'], maxAge: '1s'};

        jwt.verify(token, key, options, function (err, p) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'iat required when maxAge is specified');
          assert.isUndefined(p);
          done();
        });
      });
    });

    describe('option: clockTimestamp', function () {
      var clockTimestamp = 1000000000;
      it('should verify unexpired token relative to user-provided clockTimestamp', function (done) {
        var token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp: clockTimestamp}, function (err, p) {
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
      it('should verify valid token with nbf', function (done) {
        var token = jwt.sign({
          foo: 'bar',
          iat: clockTimestamp,
          nbf: clockTimestamp + 1,
          exp: clockTimestamp + 2
        }, key);
        jwt.verify(token, key, {clockTimestamp: clockTimestamp + 1}, function (err, p) {
          assert.isNull(err);
          done();
        });
      });
      it('should error on token used before nbf', function (done) {
        var token = jwt.sign({
          foo: 'bar',
          iat: clockTimestamp,
          nbf: clockTimestamp + 1,
          exp: clockTimestamp + 2
        }, key);
        jwt.verify(token, key, {clockTimestamp: clockTimestamp}, function (err, p) {
          assert.equal(err.name, 'NotBeforeError');
          assert.equal(err.date.constructor.name, 'Date');
          assert.equal(Number(err.date), (clockTimestamp + 1) * 1000);
          assert.isUndefined(p);
          done();
        });
      });
    });

    describe('option: maxAge and clockTimestamp', function () {
      // { foo: 'bar', iat: 1437018582, exp: 1437018800 }
      var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODgwMH0.AVOsNC7TiT-XVSpCpkwB1240izzCIJ33Lp07gjnXVpA';
      it('should error for claims issued before a certain timespan', function (done) {
        var clockTimestamp = 1437018682;
        var options = {algorithms: ['HS256'], clockTimestamp: clockTimestamp, maxAge: '1m'};

        jwt.verify(token, key, options, function (err, p) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'maxAge exceeded');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018642000);
          assert.isUndefined(p);
          done();
        });
      });
      it('should not error for claims issued before a certain timespan but still inside clockTolerance timespan', function (done) {
        var clockTimestamp = 1437018582;
        var options = {
          algorithms: ['HS256'],
          clockTimestamp: clockTimestamp,
          maxAge: '321ms',
          clockTolerance: 100
        };

        jwt.verify(token, key, options, function (err, p) {
          assert.isNull(err);
          assert.equal(p.foo, 'bar');
          done();
        });
      });
      it('should not error if within maxAge timespan', function (done) {
        var clockTimestamp = 1437018582;
        var options = {algorithms: ['HS256'], clockTimestamp: clockTimestamp, maxAge: '600ms'};

        jwt.verify(token, key, options, function (err, p) {
          assert.isNull(err);
          assert.equal(p.foo, 'bar');
          done();
        });
      });
      it('can be more restrictive than expiration', function (done) {
        var clockTimestamp = 1437018588;
        var options = {algorithms: ['HS256'], clockTimestamp: clockTimestamp, maxAge: '5s'};

        jwt.verify(token, key, options, function (err, p) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'maxAge exceeded');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018587000);
          assert.isUndefined(p);
          done();
        });
      });
      it('cannot be more permissive than expiration', function (done) {
        var clockTimestamp = 1437018900;
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
      it('should error if maxAge is specified but there is no iat claim', function (done) {
        var clockTimestamp = 1437018582;
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.0MBPd4Bru9-fK_HY3xmuDAc6N_embknmNuhdb9bKL_U';
        var options = {algorithms: ['HS256'], clockTimestamp: clockTimestamp, maxAge: '1s'};

        jwt.verify(token, key, options, function (err, p) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'iat required when maxAge is specified');
          assert.isUndefined(p);
          done();
        });
      });
    });
  });
});
