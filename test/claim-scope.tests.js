'use strict';

const jwt = require('..');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

function signWithScope(scope, payload, callback) {
  const options = {algorithm: 'none'};
  if (scope !== undefined) {
    options.scope = scope;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('scope', function() {
  describe('`jwt.sign` "scope" option validation', function () {
    [
      true,
      false,
      null,
      -1,
      0,
      1,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((scope) => {
      it(`should error with with value ${util.inspect(scope)}`, function (done) {
        signWithScope(scope, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"scope" must be a string');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {scope: undefined}
    it('should error with with value undefined', function (done) {
      testUtils.signJWTHelper({}, undefined, {scope: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', '"scope" must be a string');
        });
      });
    });

    it('should error when "scope" is in payload', function (done) {
      signWithScope('foo', {scope: 'bar'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.scope" option. The payload already has an "scope" property.'
          );
        });
      });
    });

    it('should error with a string payload', function (done) {
      signWithScope('foo', 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid scope option for string payload'
          );
        });
      });
    });

    it('should error with a Buffer payload', function (done) {
      signWithScope('foo', new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid scope option for object payload'
          );
        });
      });
    });
  });

  describe('when signing and verifying a token', function () {
    it('should not verify "scope" if verify "scope" option not provided', function(done) {
      signWithScope(undefined, {scope: 'foo'}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('scope', 'foo');
          });
        })
      });
    });

    describe('with string "scope" option', function () {
      it('should verify with a string "scope"', function (done) {
        signWithScope('foo', {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('scope', 'foo');
            });
          })
        });
      });

      it('should verify with a string "scope"', function (done) {
        signWithScope(undefined, {scope: 'foo'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('scope', 'foo');
            });
          })
        });
      });

      it('should error if "scope" does not match verify "scope" option', function(done) {
        signWithScope(undefined, {scope: 'foobar'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'invalid scope');
            });
          })
        });
      });

      it('should error without "scope" and with verify "scope" option', function(done) {
        signWithScope(undefined, {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'invalid scope');
            });
          })
        });
      });
    });

    describe('with array "scope" option', function () {
      it('should verify with a string "scope"', function (done) {
        signWithScope('bar', {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: ['foo', 'bar']}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('scope', 'bar');
            });
          })
        });
      });

      it('should verify with a string "scope"', function (done) {
        signWithScope(undefined, {scope: 'foo'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: ['foo', 'bar']}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('scope', 'foo');
            });
          })
        });
      });

      it('should error if "scope" does not match verify "scope" option', function(done) {
        signWithScope(undefined, {scope: 'foobar'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: ['foo', 'bar']}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'invalid scope');
            });
          })
        });
      });

      it('should error without "scope" and with verify "scope" option', function(done) {
        signWithScope(undefined, {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {scope: ['foo', 'bar']}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'invalid scope');
            });
          })
        });
      });
    });
  });
});
