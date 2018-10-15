'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

function signWithSubject(subject, payload, callback) {
  const options = {algorithm: 'none'};
  if (subject !== undefined) {
    options.subject = subject;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('subject', function() {
  describe('`jwt.sign` "subject" option validation', function () {
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
    ].forEach((subject) => {
      it(`should error with with value ${util.inspect(subject)}`, function (done) {
        signWithSubject(subject, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"subject" must be a string');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {subject: undefined}
    it('should error with with value undefined', function (done) {
      testUtils.signJWTHelper({}, undefined, {subject: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', '"subject" must be a string');
        });
      });
    });

    it('should error when "sub" is in payload', function (done) {
      signWithSubject('foo', {sub: 'bar'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'Bad "options.subject" option. The payload already has an "sub" property.'
          );
        });
      });
    });

    it('should error with a string payload', function (done) {
      signWithSubject('foo', 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid subject option for string payload'
          );
        });
      });
    });

    it('should error with a Buffer payload', function (done) {
      signWithSubject('foo', new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property(
            'message',
            'invalid subject option for object payload'
          );
        });
      });
    });
  });

  describe('when signing and verifying a token with "subject" option', function () {
    it('should verify with a string "subject"', function (done) {
      signWithSubject('foo', {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {subject: 'foo'}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('sub', 'foo');
          });
        })
      });
    });

    it('should verify with a string "sub"', function (done) {
      signWithSubject(undefined, {sub: 'foo'}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {subject: 'foo'}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('sub', 'foo');
          });
        })
      });
    });

    it('should not verify "sub" if verify "subject" option not provided', function(done) {
      signWithSubject(undefined, {sub: 'foo'}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('sub', 'foo');
          });
        })
      });
    });

    it('should error if "sub" does not match verify "subject" option', function(done) {
      signWithSubject(undefined, {sub: 'foo'}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {subject: 'bar'}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(e2).to.have.property('message', 'jwt subject invalid. expected: bar');
          });
        })
      });
    });

    it('should error without "sub" and with verify "subject" option', function(done) {
      signWithSubject(undefined, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {subject: 'foo'}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(e2).to.have.property('message', 'jwt subject invalid. expected: foo');
          });
        })
      });
    });
  });
});
