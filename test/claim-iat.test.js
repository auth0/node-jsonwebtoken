'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

function signWithIssueAtSync(issueAt, options) {
  const payload = {};
  if (issueAt !== undefined) {
    payload.iat = issueAt;
  }
  const opts = Object.assign({algorithm: 'none'}, options);
  return jwt.sign(payload, undefined, opts);
}

function signWithIssueAtAsync(issueAt, options, cb) {
  const payload = {};
  if (issueAt !== undefined) {
    payload.iat = issueAt;
  }
  const opts = Object.assign({algorithm: 'none'}, options);
  // async calls require a truthy secret
  // see: https://github.com/brianloveswords/node-jws/issues/62
  return jwt.sign(payload, 'secret', opts, cb);
}

function verifyWithIssueAtSync(token, maxAge, options) {
  const opts = Object.assign({maxAge}, options);
  return jwt.verify(token, undefined, opts)
}

function verifyWithIssueAtAsync(token, maxAge, options, cb) {
  const opts = Object.assign({maxAge}, options);
  return jwt.verify(token, undefined, opts, cb)
}

describe('issue at', function() {
  describe('`jwt.sign` "iat" claim validation', function () {
    [
      true,
      false,
      null,
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((iat) => {
      it(`should error with iat of ${util.inspect(iat)}`, function (done) {
        expect(() => signWithIssueAtSync(iat, {})).to.throw('"iat" should be a number of seconds');
        signWithIssueAtAsync(iat, {}, (err) => {
          expect(err.message).to.equal('"iat" should be a number of seconds');
          done();
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {iat: undefined}
    it('should error with iat of undefined', function (done) {
      expect(() => jwt.sign({iat: undefined}, undefined, {algorithm: 'none'})).to.throw(
        '"iat" should be a number of seconds'
      );
      jwt.sign({iat: undefined}, undefined, {algorithm: 'none'}, (err) => {
        expect(err.message).to.equal('"iat" should be a number of seconds');
        done();
      });
    });
  });

  describe('"iat" in payload with "maxAge" option validation', function () {
    [
      true,
      false,
      null,
      undefined,
      -Infinity,
      Infinity,
      NaN,
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((iat) => {
      it(`should error with iat of ${util.inspect(iat)}`, function (done) {
        const encodedPayload = base64UrlEncode(JSON.stringify({iat}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        expect(() => verifyWithIssueAtSync(token, '1 min', {})).to.throw(
          jwt.JsonWebTokenError, 'iat required when maxAge is specified'
        );

        verifyWithIssueAtAsync(token, '1 min', {}, (err) => {
          expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
          expect(err.message).to.equal('iat required when maxAge is specified');
          done();
        });
      });
    })
  });

  describe('when signing a token', function () {
    let fakeClock;
    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function () {
      fakeClock.uninstall();
    });

    [
      {
        description: 'should default to current time for "iat"',
        iat: undefined,
        expectedIssueAt: 60,
        options: {}
      },
      {
        description: 'should sign with provided time for "iat"',
        iat: 100,
        expectedIssueAt: 100,
        options: {}
      },
      // TODO an iat of -Infinity should fail validation
      {
        description: 'should set null "iat" when given -Infinity',
        iat: -Infinity,
        expectedIssueAt: null,
        options: {}
      },
      // TODO an iat of Infinity should fail validation
      {
        description: 'should set null "iat" when given Infinity',
        iat: Infinity,
        expectedIssueAt: null,
        options: {}
      },
      // TODO an iat of NaN should fail validation
      {
        description: 'should set to current time for "iat" when given value NaN',
        iat: NaN,
        expectedIssueAt: 60,
        options: {}
      },
      {
        description: 'should remove default "iat" with "noTimestamp" option',
        iat: undefined,
        expectedIssueAt: undefined,
        options: {noTimestamp: true}
      },
      {
        description: 'should remove provided "iat" with "noTimestamp" option',
        iat: 10,
        expectedIssueAt: undefined,
        options: {noTimestamp: true}
      },
    ].forEach((testCase) => {
      it(testCase.description, function (done) {
        const token = signWithIssueAtSync(testCase.iat, testCase.options);
        expect(jwt.decode(token).iat).to.equal(testCase.expectedIssueAt);
        signWithIssueAtAsync(testCase.iat, testCase.options, (err, token) => {
          // node-jsw catches the error from expect, so we have to wrap it in try/catch and use done(error)
          try {
            expect(err).to.be.null;
            expect(jwt.decode(token).iat).to.equal(testCase.expectedIssueAt);
            done();
          }
          catch (e) {
            done(e);
          }
        });
      });
    });
  });

  describe('when verifying a token', function() {
    let token;
    let fakeClock;

    beforeEach(function() {
      fakeClock = sinon.useFakeTimers({now: 60000});
    });

    afterEach(function () {
      fakeClock.uninstall();
    });

    [
      {
        description: 'should verify using "iat" before the "maxAge"',
        clockAdvance: 10000,
        maxAge: 11,
        options: {},
      },
      {
        description: 'should verify using "iat" before the "maxAge" with a provided "clockTimestamp',
        clockAdvance: 60000,
        maxAge: 11,
        options: {clockTimestamp: 70},
      },
      {
        description: 'should verify using "iat" after the "maxAge" but within "clockTolerance"',
        clockAdvance: 10000,
        maxAge: 9,
        options: {clockTimestamp: 2},
      },
    ].forEach((testCase) => {
      it(testCase.description, function (done) {
        const token = signWithIssueAtSync(undefined, {});
        fakeClock.tick(testCase.clockAdvance);
        expect(verifyWithIssueAtSync(token, testCase.maxAge, testCase.options)).to.not.throw;
        verifyWithIssueAtAsync(token, testCase.maxAge, testCase.options, done)
      });
    });

    [
      {
        description: 'should throw using "iat" equal to the "maxAge"',
        clockAdvance: 10000,
        maxAge: 10,
        options: {},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 70000,
      },
      {
        description: 'should throw using "iat" after the "maxAge"',
        clockAdvance: 10000,
        maxAge: 9,
        options: {},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 69000,
      },
      {
        description: 'should throw using "iat" after the "maxAge" with a provided "clockTimestamp',
        clockAdvance: 60000,
        maxAge: 10,
        options: {clockTimestamp: 70},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 70000,
      },
      {
        description: 'should throw using "iat" after the "maxAge" and "clockTolerance',
        clockAdvance: 10000,
        maxAge: 8,
        options: {clockTolerance: 2},
        expectedError: 'maxAge exceeded',
        expectedExpiresAt: 68000,
      },
    ].forEach((testCase) => {
      it(testCase.description, function(done) {
        const expectedExpiresAtDate = new Date(testCase.expectedExpiresAt);
        token = signWithIssueAtSync(undefined, {});
        fakeClock.tick(testCase.clockAdvance);
        expect(() => verifyWithIssueAtSync(token, testCase.maxAge, {}))
          .to.throw(jwt.TokenExpiredError, testCase.expectedError)
          .to.have.property('expiredAt').that.deep.equals(expectedExpiresAtDate);
        verifyWithIssueAtAsync(token, testCase.maxAge, {}, (err) => {
          expect(err).to.be.instanceOf(jwt.TokenExpiredError);
          expect(err.message).to.equal(testCase.expectedError);
          expect(err.expiredAt).to.deep.equal(expectedExpiresAtDate);
          done();
        });
      });
    });
  });
});
