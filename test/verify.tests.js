const jwt = require('../index');
const jws = require('jws');
const fs = require('fs');
const path = require('path');
const sinon = require('sinon');
const JsonWebTokenError = require('../lib/JsonWebTokenError');

const assert = require('chai').assert;
const expect = require('chai').expect;

describe('verify', function() {
  const pub = fs.readFileSync(path.join(__dirname, 'pub.pem'));
  const priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

  it('should first assume JSON claim set', function (done) {
    const header = { alg: 'RS256' };
    const payload = { iat: Math.floor(Date.now() / 1000 ) };

    const signed = jws.sign({
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

  it('should not be able to verify unsigned token', function () {
    const header = { alg: 'none' };
    const payload = { iat: Math.floor(Date.now() / 1000 ) };

    const signed = jws.sign({
      header: header,
      payload: payload,
      secret: 'secret',
      encoding: 'utf8'
    });

    expect(function () {
      jwt.verify(signed, 'secret', {typ: 'JWT'});
    }).to.throw(JsonWebTokenError, /jwt signature is required/);
  });

  it('should not be able to verify unsigned token', function () {
    const header = { alg: 'none' };
    const payload = { iat: Math.floor(Date.now() / 1000 ) };

    const signed = jws.sign({
      header: header,
      payload: payload,
      secret: 'secret',
      encoding: 'utf8'
    });

    expect(function () {
      jwt.verify(signed, undefined, {typ: 'JWT'});
    }).to.throw(JsonWebTokenError, /please specify "none" in "algorithms" to verify unsigned tokens/);
  });

  it('should be able to verify unsigned token when none is specified', function (done) {
    const header = { alg: 'none' };
    const payload = { iat: Math.floor(Date.now() / 1000 ) };

    const signed = jws.sign({
      header: header,
      payload: payload,
      secret: 'secret',
      encoding: 'utf8'
    });

    jwt.verify(signed, null, {typ: 'JWT', algorithms: ['none']}, function(err, p) {
      assert.isNull(err);
      assert.deepEqual(p, payload);
      done();
    });
  });

  it('should not mutate options', function (done) {
    const header = { alg: 'HS256' };
    const payload = { iat: Math.floor(Date.now() / 1000 ) };
    const  options = { typ: 'JWT' };
    const signed = jws.sign({
      header: header,
      payload: payload,
      secret: 'secret',
      encoding: 'utf8'
    });

    jwt.verify(signed, 'secret', options, function(err) {
      assert.isNull(err);
      assert.deepEqual(Object.keys(options).length, 1);
      done();
    });
  });

  describe('secret or token as callback', function () {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
    const key = 'key';

    const payload = { foo: 'bar', iat: 1437018582, exp: 1437018592 };
    const options = {algorithms: ['HS256'], ignoreExpiration: true};

    it('without callback', function (done) {
      jwt.verify(token, key, options, function (err, p) {
        assert.isNull(err);
        assert.deepEqual(p, payload);
        done();
      });
    });

    it('simple callback', function (done) {
      const keyFunc = function(header, callback) {
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
      const keyFunc = function(header, callback) {
        callback(undefined, key);
      };

      expect(function () {
        jwt.verify(token, keyFunc, options);
      }).to.throw(JsonWebTokenError, /verify must be called asynchronous if secret or public key is provided as a callback/);

      done();
    });

    it('simple error', function (done) {
      const keyFunc = function(header, callback) {
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
      const keyFunc = function(header, callback) {
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
      const keyFunc = function(header, callback) {
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
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
    const key = 'key';

    let clock;
    afterEach(function () {
      try { clock.restore(); } catch (e) {}
    });

    it('should error on expired token', function (done) {
      clock = sinon.useFakeTimers(1437018650000); // iat + 58s, exp + 48s
      const options = {algorithms: ['HS256']};

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
      const options = {algorithms: ['HS256'], clockTolerance: 5 }

      jwt.verify(token, key, options, function (err, p) {
        assert.isNull(err);
        assert.equal(p.foo, 'bar');
        done();
      });
    });

    describe('option: clockTimestamp', function () {
      const clockTimestamp = 1000000000;
      it('should verify unexpired token relative to user-provided clockTimestamp', function (done) {
        const token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp: clockTimestamp}, function (err) {
          assert.isNull(err);
          done();
        });
      });
      it('should error on expired token relative to user-provided clockTimestamp', function (done) {
        const token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
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
        const token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
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
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODgwMH0.AVOsNC7TiT-XVSpCpkwB1240izzCIJ33Lp07gjnXVpA';
      it('cannot be more permissive than expiration', function (done) {
        const clockTimestamp = 1437018900;  // iat + 318s (exp: iat + 218s)
        const options = {algorithms: ['HS256'], clockTimestamp: clockTimestamp, maxAge: '1000y'};

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

  describe('when verifying a token with an unsupported public key type', function () {
    it('should throw an error', function() {
      const token = 'eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE2Njk5OTAwMDN9.YdjFWJtPg_9nccMnTfQyesWQ0UX-GsWrfCGit_HqjeIkNjoV6dkAJ8AtbnVEhA4oxwqSXx6ilMOfHEjmMlPtyyyVKkWKQHcIWYnqPbNSEv8a7Men8KhJTIWb4sf5YbhgSCpNvU_VIZjLO1Z0PzzgmEikp0vYbxZFAbCAlZCvUlcIc-kdjIRCnDJe0BBrYRxNLEJtYsf7D1yFIFIqw8-VP87yZdExA4eHsTaE84SgnL24ZK5h5UooDx-IRNd_rrMyio8kNy63grVxCWOtkXZ26iZk6v-HMsnBqxvUwR6-8wfaWrcpADkyUO1q3SNsoTdwtflbvfwgjo3uve0IvIzHMw';
      const key = fs.readFileSync(path.join(__dirname, 'dsa-public.pem'));

      expect(function() {
        jwt.verify(token, key);
      }).to.throw('Unknown key type "dsa".');
    });
  });

  describe('when verifying a token with an incorrect public key type', function () {
    it('should throw a validation error if key validation is enabled', function() {
      const token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXkiOiJsb2FkIiwiaWF0IjoxNjcwMjMwNDE2fQ.7TYP8SB_9Tw1fNIfuG60b4tvoLPpDAVBQpV1oepnuKwjUz8GOw4fRLzclo0Q2YAXisJ3zIYMEFsHpYrflfoZJQ';
      const key = fs.readFileSync(path.join(__dirname, 'rsa-public.pem'));

      expect(function() {
        jwt.verify(token, key, { algorithms: ['ES256'] });
      }).to.throw('"alg" parameter for "rsa" key type must be one of: RS256, PS256, RS384, PS384, RS512, PS512.');
    });

    it('should throw an unknown error if key validation is disabled', function() {
      const token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXkiOiJsb2FkIiwiaWF0IjoxNjcwMjMwNDE2fQ.7TYP8SB_9Tw1fNIfuG60b4tvoLPpDAVBQpV1oepnuKwjUz8GOw4fRLzclo0Q2YAXisJ3zIYMEFsHpYrflfoZJQ';
      const key = fs.readFileSync(path.join(__dirname, 'rsa-public.pem'));

      expect(function() {
        jwt.verify(token, key, { algorithms: ['ES256'], allowInvalidAsymmetricKeyTypes: true });
      }).to.not.throw('"alg" parameter for "rsa" key type must be one of: RS256, PS256, RS384, PS384, RS512, PS512.');
    });
  });
});
