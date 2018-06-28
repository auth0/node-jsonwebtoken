'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

function signWithExpiresIn(payload, expiresIn) {
  const options = {algorithm: 'none'};
  if (expiresIn !== undefined) {
    options.expiresIn = expiresIn;
  }
  return jwt.sign(payload, undefined, options);
}

describe('expires', function() {
  describe('`jwt.sign` "expiresIn" option validation', function () {
    [
      true,
      false,
      null,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((expiresIn) => {
      it(`should error with with value ${util.inspect(expiresIn)}`, function () {
        expect(() => signWithExpiresIn({}, expiresIn)).to.throw(
          '"expiresIn" should be a number of seconds or string representing a timespan'
        );
      });
    });

    // TODO this should throw the same error as other invalid inputs
    it(`should error with with value ''`, function () {
      expect(() => signWithExpiresIn({}, '')).to.throw(
        'val is not a non-empty string or a valid number. val=""'
      );
    });

    // undefined needs special treatment because {} is not the same as {expiresIn: undefined}
    it('should error with with value undefined', function () {
      expect(() =>jwt.sign({}, undefined, {expiresIn: undefined, algorithm: 'none'})).to.throw(
        '"expiresIn" should be a number of seconds or string representing a timespan'
      );
    });

    it ('should error when "exp" is in payload', function() {
      expect(() => signWithExpiresIn({exp: 100}, 100)).to.throw(
        'Bad "options.expiresIn" option the payload already has an "exp" property.'
      );
    });

    it('should error with a string payload', function() {
      expect(() => signWithExpiresIn('a string payload', 100)).to.throw(
        'invalid expiresIn option for string payload'
      );
    });

    it('should error with a Buffer payload', function() {
      expect(() => signWithExpiresIn(Buffer.from('a Buffer payload'), 100)).to.throw(
        'invalid expiresIn option for object payload'
      );
    });
  });

  describe('`jwt.sign` "exp" claim validation', function () {
    [
      true,
      false,
      null,
      undefined,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((exp) => {
      it(`should error with with value ${util.inspect(exp)}`, function () {
        expect(() => signWithExpiresIn({exp})).to.throw(
          '"exp" should be a number of seconds'
        );
      });
    });
  });

  describe('"exp" in payload validation', function () {
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
    ].forEach((exp) => {
      it(`should error with with value ${util.inspect(exp)}`, function () {
        const encodedPayload = base64UrlEncode(JSON.stringify({exp}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        expect(() => jwt.verify(token, undefined)).to.throw(
          jwt.JsonWebTokenError,
          'invalid exp value'
        );
      });
    })
  });

  describe('when signing and verifying a token with expires option', function () {
    let fakeClock;
    beforeEach(function() {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function() {
      fakeClock.uninstall();
    });

    it('should set correct "exp" with negative number of seconds', function() {
      const token = signWithExpiresIn({}, -10);
      fakeClock.tick(-10001);

      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.exp).to.equal(50);
    });

    it('should set correct "exp" with positive number of seconds', function() {
      const token = signWithExpiresIn({}, 10);

      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.exp).to.equal(70);
    });

    it('should set correct "exp" with zero seconds', function() {
      const token = signWithExpiresIn({}, 0);

      fakeClock.tick(-1);

      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.exp).to.equal(60);
    });

    it('should set correct "exp" with negative string timespan', function() {
      const token = signWithExpiresIn({}, '-10 s');

      fakeClock.tick(-10001);

      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.exp).to.equal(50);
    });

    it('should set correct "exp" with positive string timespan', function() {
      const token = signWithExpiresIn({}, '10 s');

      fakeClock.tick(-10001);
      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.exp).to.equal(70);
    });

    it('should set correct "exp" with zero string timespan', function() {
      const token = signWithExpiresIn({}, '0 s');

      fakeClock.tick(-1);
      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.exp).to.equal(60);
    });

    // TODO an exp of -Infinity should fail validation
    it('should set null "exp" when given -Infinity', function () {
      const token = signWithExpiresIn({exp: -Infinity});

      const decoded = jwt.decode(token);
      expect(decoded.exp).to.be.null;
    });

    // TODO an exp of Infinity should fail validation
    it('should set null "exp" when given value Infinity', function () {
      const token = signWithExpiresIn({exp: Infinity});

      const decoded = jwt.decode(token);
      expect(decoded.exp).to.be.null;
    });

    // TODO an exp of NaN should fail validation
    it('should set null "exp" when given value NaN', function () {
      const token = signWithExpiresIn({exp: NaN});

      const decoded = jwt.decode(token);
      expect(decoded.exp).to.be.null;
    });

    it('should set correct "exp" when "iat" is passed', function () {
      const token = signWithExpiresIn({iat: 80}, -10);

      const decoded = jwt.decode(token);

      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.exp).to.equal(70);
    });

    it('should verify "exp" using "clockTimestamp"', function () {
      const token = signWithExpiresIn({}, 10);

      const verified = jwt.verify(token, undefined, {clockTimestamp: 69});
      expect(verified.iat).to.equal(60);
      expect(verified.exp).to.equal(70);
    });

    it('should verify "exp" using "clockTolerance"', function () {
      const token = signWithExpiresIn({}, 5);

      fakeClock.tick(10000);

      const verified = jwt.verify(token, undefined, {clockTolerance: 6});
      expect(verified.iat).to.equal(60);
      expect(verified.exp).to.equal(65);
    });

    it('should ignore a expired token when "ignoreExpiration" is true', function () {
      const token = signWithExpiresIn({}, '-10 s');

      const verified = jwt.verify(token, undefined, {ignoreExpiration: true});
      expect(verified.iat).to.equal(60);
      expect(verified.exp).to.equal(50);
    });

    it('should error on verify if "exp" is at current time', function() {
      const token = signWithExpiresIn({exp: 60});

      expect(() => jwt.verify(token, undefined)).to.throw(
        jwt.TokenExpiredError,
        'jwt expired'
      );
    });

    it('should error on verify if "exp" is before current time using clockTolerance', function () {
      const token = signWithExpiresIn({}, -5);

      expect(() => jwt.verify(token, undefined, {clockTolerance: 5})).to.throw(
        jwt.TokenExpiredError,
        'jwt expired'
      );
    });
  });
});
