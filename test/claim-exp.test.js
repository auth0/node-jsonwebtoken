'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');
const testUtils = require('./test-utils');

const base64UrlEncode = testUtils.base64UrlEncode;
const noneAlgorithmHeader = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0';

function signWithExpiresIn(expiresIn, payload, callback) {
  const options = {algorithm: 'none'};
  if (expiresIn !== undefined) {
    options.expiresIn = expiresIn;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
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
      '',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((expiresIn) => {
      it(`should error with with value ${util.inspect(expiresIn)}`, function (done) {
        signWithExpiresIn(expiresIn, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message')
              .match(/"expiresIn" should be a number of seconds or string representing a timespan/);
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {expiresIn: undefined}
    it('should error with with value undefined', function (done) {
      testUtils.signJWTHelper({}, undefined, {expiresIn: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            '"expiresIn" should be a number of seconds or string representing a timespan'
          );
        });
      });
    });

    it ('should error when "exp" is in payload', function(done) {
      signWithExpiresIn(100, {exp: 100}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.expiresIn" option the payload already has an "exp" property.'
          );
        });
      });
    });

    it('should error with a string payload', function(done) {
      signWithExpiresIn(100, 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid expiresIn option for string payload');
        });
      });
    });

    it('should error with a Buffer payload', function(done) {
      signWithExpiresIn(100, Buffer.from('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid expiresIn option for object payload');
        });
      });
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
      it(`should error with with value ${util.inspect(exp)}`, function (done) {
        signWithExpiresIn(undefined, {exp}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"exp" should be a number of seconds');
          });
        });
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
      it(`should error with with value ${util.inspect(exp)}`, function (done) {
        const encodedPayload = base64UrlEncode(JSON.stringify({exp}));
        const token = `${noneAlgorithmHeader}.${encodedPayload}.`;
        testUtils.verifyJWTHelper(token, undefined, {exp}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'invalid exp value');
          });
        });
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

    it('should set correct "exp" with negative number of seconds', function(done) {
      signWithExpiresIn(-10, {}, (e1, token) => {
        fakeClock.tick(-10001);
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 50);
          });
        })
      });
    });

    it('should set correct "exp" with positive number of seconds', function(done) {
      signWithExpiresIn(10, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should set correct "exp" with zero seconds', function(done) {
      signWithExpiresIn(0, {}, (e1, token) => {
        fakeClock.tick(-1);
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 60);
          });
        })
      });
    });

    it('should set correct "exp" with negative string timespan', function(done) {
      signWithExpiresIn('-10 s', {}, (e1, token) => {
        fakeClock.tick(-10001);
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 50);
          });
        })
      });
    });

    it('should set correct "exp" with positive string timespan', function(done) {
      signWithExpiresIn('10 s', {}, (e1, token) => {
        fakeClock.tick(-10001);
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should set correct "exp" with zero string timespan', function(done) {
      signWithExpiresIn('0 s', {}, (e1, token) => {
        fakeClock.tick(-1);
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 60);
          });
        })
      });
    });

    // TODO an exp of -Infinity should fail validation
    it('should set null "exp" when given -Infinity', function (done) {
      signWithExpiresIn(undefined, {exp: -Infinity}, (err, token) => {
        const decoded = jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('exp', null);
        });
      });
    });

    // TODO an exp of Infinity should fail validation
    it('should set null "exp" when given value Infinity', function (done) {
      signWithExpiresIn(undefined, {exp: Infinity}, (err, token) => {
        const decoded = jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('exp', null);
        });
      });
    });

    // TODO an exp of NaN should fail validation
    it('should set null "exp" when given value NaN', function (done) {
      signWithExpiresIn(undefined, {exp: NaN}, (err, token) => {
        const decoded = jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('exp', null);
        });
      });
    });

    it('should set correct "exp" when "iat" is passed', function (done) {
      signWithExpiresIn(-10, {iat: 80}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should verify "exp" using "clockTimestamp"', function (done) {
      signWithExpiresIn(10, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {clockTimestamp: 69}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('exp', 70);
          });
        })
      });
    });

    it('should verify "exp" using "clockTolerance"', function (done) {
      signWithExpiresIn(5, {}, (e1, token) => {
        fakeClock.tick(10000);
        testUtils.verifyJWTHelper(token, undefined, {clockTimestamp: 6}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('exp', 65);
          });
        })
      });
    });

    it('should ignore a expired token when "ignoreExpiration" is true', function (done) {
      signWithExpiresIn('-10 s', {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {ignoreExpiration: true}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('iat', 60);
            expect(decoded).to.have.property('exp', 50);
          });
        })
      });
    });

    it('should error on verify if "exp" is at current time', function(done) {
      signWithExpiresIn(undefined, {exp: 60}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.TokenExpiredError);
            expect(e2).to.have.property('message', 'jwt expired');
          });
        });
      });
    });

    it('should error on verify if "exp" is before current time using clockTolerance', function (done) {
      signWithExpiresIn(-5, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {clockTolerance: 5}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.TokenExpiredError);
            expect(e2).to.have.property('message', 'jwt expired');
          });
        });
      });
    });
  });
});
