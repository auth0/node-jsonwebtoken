'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

function signWithJWTId(jwtid, payload, callback) {
  const options = {algorithm: 'none'};
  if (jwtid !== undefined) {
    options.jwtid = jwtid;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('jwtid', function() {
  describe('`jwt.sign` "jwtid" option validation', function () {
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
    ].forEach((jwtid) => {
      it(`should error with with value ${util.inspect(jwtid)}`, function (done) {
        signWithJWTId(jwtid, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"jwtid" must be a string');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {jwtid: undefined}
    it('should error with with value undefined', function (done) {
      testUtils.signJWTHelper({}, undefined, {jwtid: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', '"jwtid" must be a string');
        });
      });
    });

    it('should error when "jti" is in payload', function (done) {
      signWithJWTId('foo', {jti: 'bar'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.jwtid" option. The payload already has an "jti" property.'
          );
        });
      });
    });

    it('should error with a string payload', function (done) {
      signWithJWTId('foo', 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid jwtid option for string payload'
          );
        });
      });
    });

    it('should error with a Buffer payload', function (done) {
      signWithJWTId('foo', new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid jwtid option for object payload'
          );
        });
      });
    });
  });

  describe('when signing and verifying a token', function () {
    it('should not verify "jti" if verify "jwtid" option not provided', function(done) {
      signWithJWTId(undefined, {jti: 'foo'}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('jti', 'foo');
          });
        })
      });
    });

    describe('with "jwtid" option', function () {
      it('should verify with "jwtid" option', function (done) {
        signWithJWTId('foo', {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {jwtid: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('jti', 'foo');
            });
          })
        });
      });

      it('should verify with "jti" in payload', function (done) {
        signWithJWTId(undefined, {jti: 'foo'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {jetid: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.null;
              expect(decoded).to.have.property('jti', 'foo');
            });
          })
        });
      });

      it('should error if "jti" does not match verify "jwtid" option', function(done) {
        signWithJWTId(undefined, {jti: 'bar'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {jwtid: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'jwt jwtid invalid. expected: foo');
            });
          })
        });
      });

      it('should error without "jti" and with verify "jwtid" option', function(done) {
        signWithJWTId(undefined, {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, undefined, {jwtid: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).to.be.null;
              expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
              expect(e2).to.have.property('message', 'jwt jwtid invalid. expected: foo');
            });
          })
        });
      });
    });
  });
});
