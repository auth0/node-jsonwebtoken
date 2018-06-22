'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');

function base64UrlEncode(str) {
  return Buffer.from(str).toString('base64')
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
  ;
}

function signWithNoBefore(payload, notBefore) {
  const options = {algorithm: 'none'};
  if (notBefore !== undefined) {
    options.notBefore = notBefore;
  }
  return jwt.sign(payload, undefined, options);
}

const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

describe('not before', function() {
  describe('`jwt.sign` notBefore option validation', function () {
    [
      true,
      false,
      null,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      // TODO empty string currently fails
      // '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((notBefore) => {
      it(`should error with with value ${util.inspect(notBefore)}`, function () {
        expect(() => signWithNoBefore({}, notBefore)).to.throw(
          '"notBefore" should be a number of seconds or string representing a timespan'
        );
      });
    });

    // undefined needs special treatment because {} is not the same as {notBefore: undefined}
    it('should error with with value undefined', function () {
      expect(() =>jwt.sign({}, undefined, {notBefore: undefined, algorithm: 'none'})).to.throw(
        '"notBefore" should be a number of seconds or string representing a timespan'
      );
    });

    it ('should error when "nbf" is in payload', function() {
      expect(() => signWithNoBefore({nbf: 100}, 100)).to.throw(
        'Bad "options.notBefore" option the payload already has an "nbf" property.'
      );
    });

    it('should error with a string payload', function() {
      expect(() => signWithNoBefore('a string payload', 100)).to.throw(
        'invalid notBefore option for string payload'
      );
    });

    it('should error with a Buffer payload', function() {
      expect(() => signWithNoBefore(new Buffer('a Buffer payload'), 100)).to.throw(
        'invalid notBefore option for object payload'
      );
    });
  });

  describe('`jwt.sign` nbf claim validation', function () {
    [
      true,
      false,
      null,
      undefined,
      // TODO should these fail in validation?
      // -Infinity,
      // Infinity,
      // NaN,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((nbf) => {
      it(`should error with with value ${util.inspect(nbf)}`, function () {
        expect(() => signWithNoBefore({nbf})).to.throw(
          '"nbf" should be a number of seconds'
        );
      });
    });
  });

  describe('nbf in payload validation', function () {
    [
      true,
      false,
      null,
      -Infinity,
      Infinity,
      NaN,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((nbf) => {
      it(`should error with with value ${util.inspect(nbf)}`, function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({nbf}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        expect(() => jwt.verify(token, undefined)).to.throw(
          jwt.JsonWebTokenError,
          'invalid nbf value'
        );
      });
    })
  });

  describe('when signing and verifying a token with notBefore option', function () {
    let fakeClock;
    beforeEach(function() {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function() {
      fakeClock.uninstall();
    });


    it('should set correct "nbf" with negative number of seconds', function() {
      const token = signWithNoBefore({}, -10);
      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.nbf).to.equal(50);
    });

    it('should set correct "nbf" with positive number of seconds', function() {
      const token = signWithNoBefore({}, 10);

      fakeClock.tick(10000);
      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.nbf).to.equal(70);
    });

    it('should set correct "nbf" with zero seconds', function() {
      const token = signWithNoBefore({}, 0);

      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.nbf).to.equal(60);
    });

    it('should set correct "nbf" with negative string timespan', function() {
      const token = signWithNoBefore({}, '-10 s');

      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.nbf).to.equal(50);
    });


    it('should set correct "nbf" with positive string timespan', function() {
      const token = signWithNoBefore({}, '10 s');

      fakeClock.tick(10000);
      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.nbf).to.equal(70);
    });

    it('should set correct "nbf" with zero string timespan', function() {
      const token = signWithNoBefore({}, '0 s');

      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.nbf).to.equal(60);
    });

    it('should set correct "nbf" when "iat" is passed', function () {
      const token = signWithNoBefore({iat: 40}, -10);

      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.nbf).to.equal(30);
    });

    it('should verify "nbf" using "clockTimestamp"', function () {
      const token = signWithNoBefore({}, 10);

      const verified = jwt.verify(token, undefined, {clockTimestamp: 70});
      expect(verified.iat).to.equal(60);
      expect(verified.nbf).to.equal(70);
    });

    it('should verify "nbf" using "clockTolerance"', function () {
      const token = signWithNoBefore({}, 5);

      const verified = jwt.verify(token, undefined, {clockTolerance: 6});
      expect(verified.iat).to.equal(60);
      expect(verified.nbf).to.equal(65);
    });

    it('should ignore a not active token when "ignoreNotBefore" is true', function () {
      const token = signWithNoBefore({}, '10 s');

      const verified = jwt.verify(token, undefined, {ignoreNotBefore: true});
      expect(verified.iat).to.equal(60);
      expect(verified.nbf).to.equal(70);
    });

    it('should error on verify if "nbf" is after current time', function() {
      const token = signWithNoBefore({nbf: 61});

      expect(() => jwt.verify(token, undefined)).to.throw(
        jwt.NotBeforeError,
        'jwt not active'
      );
    });

    it('should error on verify if "nbf" is after current time using clockTolerance', function () {
      const token = signWithNoBefore({}, 5);

      expect(() => jwt.verify(token, undefined, {clockTolerance: 4})).to.throw(
        jwt.NotBeforeError,
        'jwt not active'
      );
    });
  });
});